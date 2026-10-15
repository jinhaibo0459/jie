# -*- coding: utf-8 -*-
# 跨平台/android/androidpkg64.py —— AN-2 装配器：stub + jiqiA64.jie → jiqiA64an.elf
#   对偶：跨平台/linux/linuxpkg64.py（x86-64 版）——同一契约在 aarch64 上的重写。
#   ★v2（S3-C-166·W^X 适配改造·承 规格/50）：双 PT_LOAD 布局（elfpkg64a.build_ds）
#     ＋ park→trap 重定向**前移为构建期补丁**（离线写入 J64′·运行时零写码）。
#   布局（blob 内·与 androidstub.py 头部契约双端同步 v2）：
#     桩区@0x000（保留零填）· 壳@blob 0x1C8（文件 0x278·入口 0x400278）· jiqiA64@blob 0x1DC8
#     （文件 0x1E78·VA 0x401E78）· 数据区外移 RW 段@文件 0x6000／VA 0x406000
#   回填与填写（J64′ 判据＝「除 1 word 登记补丁外逐字节原样」·承 规格/50 §2.2）：
#     ① J64 基址占位：movz4(24, 0xE1E1F010) ×1 → movz4(24, 0x401E78)
#     ② park 槽：{park_off, b_word} 2 dword = 0xE2E2E2E2 ×2（构建记录·运行时不读）
#          park_off = jiqiA64 内「B_SELF 且前一条 BL→svc_int13」唯一位点（构建收尾自旋环）
#          b_word   = B（从 park 到 trap 的相对指令数）——**构建期**写入 ELF 文件内 J64′，
#                     将「裸机自旋停机」重定向为「trap → exit(0)」（进程停机）
#     ③ 与 xfA64_manifest.txt 的 BUILD_PARK / MACHINE 行双核对（防脱节）
#     ④ 登记三件套 {slot_off, old=0x14000000〔B_SELF〕, new=b_word}——断言 old 相符⇒写 new
#   --e4（S3-C-146）：E4 变体装配——壳取 androidstub.build('e4')，槽位点改
#     seq_exit 自旋（exit_off+16·断言 B_SELF·承 A 线 F6「停住==halt_pc」实证），
#     b_word 同机制（自旋→trap→exit(0)）。输出默认 jiqiA64an_e4.elf。
#   --beta（S3-C-147 · β 段）：路径相对化（配合 adb shell「cd /data/local/tmp」）＋
#     产物写回文件（写后回读 8B 校验）——与 --e4 正交组合（4 形态）。
#   用法：python androidpkg64.py [stub.bin] [out.elf] [--e4] [--beta]
#          stub.bin 若给出则校验「文件 == 重生成」（确定性）；默认重生成。
#   产出：static ELF64（elfpkg64a.build_ds·双 PT_LOAD：seg1 R|X／seg2 R|W——
#         W^X 合规：任何页不得同时含可写数据与可执行码）
import hashlib
import os
import re
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.abspath(os.path.join(HERE, '..', 'arm')))

import androidstub            # noqa: E402
import elfpkg64a              # noqa: E402

# ---- 溯源锁（S3-C-138 基线·随上游跨家族线更新）----
J64_LEN = 15912
J64_MD5 = '4124175f75455a96a1d46925e6febd3f'

BASE = 0x400000
HDR2 = elfpkg64a.HDR2                  # 0xB0（ehdr＋phdr×2·双段布局 v2）
J64_OFF = 0x1DC8                       # blob 内（文件 0x1E78 = HDR2+J64_OFF——不变）
J64_VA = BASE + HDR2 + J64_OFF         # 0x401E78（不变）
ENTRY = HDR2 + androidstub.SHELL_OFF   # 壳（= 0x278——文件偏移/VA 不变·双端联动）
assert ENTRY == 0x278, '壳入口偏移契约破坏'
assert J64_VA == 0x401E78, 'J64 VA 契约破坏'

B_SELF = 0x14000000


def main():
    e4 = '--e4' in sys.argv
    beta = '--beta' in sys.argv
    variant = 'e4' if e4 else 'build'
    args = [a for a in sys.argv[1:] if not a.startswith('--')]
    stub_path = args[0] if len(args) > 0 else None
    default_out = 'jiqiA64an%s%s.elf' % ('_e4' if e4 else '',
                                         '_beta' if beta else '')
    out_path = args[1] if len(args) > 1 else os.path.join(HERE, default_out)

    # ===== 1) jiqiA64 + manifest（双核对·先读以算 data_va）=====
    j64 = open(os.path.join(HERE, '..', 'arm', 'jiqiA64.jie'), 'rb').read()
    assert len(j64) == J64_LEN, len(j64)
    assert hashlib.md5(j64).hexdigest() == J64_MD5, hashlib.md5(j64).hexdigest()
    mf = open(os.path.join(HERE, '..', 'arm', 'xfA64_manifest.txt'),
              encoding='utf-8').read()
    m_bp = re.search(r'BUILD_PARK: old=([0-9A-F]+) new=(\d+)', mf)
    m_mc = re.search(r'MACHINE: exit_off=(\d+) svc_off=(\d+) total=(\d+) '
                     r'total_all=(\d+) md5=(\w+)', mf)
    assert m_bp and m_mc, 'xfA64_manifest 关键行缺失'
    assert m_mc.group(5) == J64_MD5, 'manifest md5 与实体不符'
    park_manifest = int(m_bp.group(2))          # 新偏移（字节）
    svc_off = int(m_mc.group(2))                # svc_int13 桩字节偏移

    # ===== 2) 壳（v2：data_va 显式传入·数据区外移 RW 段·承 规格/50 §2.3）=====
    data_va = androidstub.calc_data_va(len(j64))
    stub, data, meta = androidstub.build(variant=variant, beta=beta, data_va=data_va)
    print('stub（variant=%s%s）%d B · trap_off=0x%X · data_va=0x%X（文件 0x%X）' %
          (variant, '·beta' if beta else '', len(stub),
           meta['trap_off'], meta['data_va'], meta['data_off']))
    if stub_path:
        f = open(stub_path, 'rb').read()
        assert f == stub, 'stub 文件与重生成不符（确定性校验失败）'
        print('stub 文件校验：== 重生成 ✓')

    # ===== 3) 槽位点定位（build：park 扫描；e4：seq_exit 自旋）=====
    words = struct.unpack('<%dI' % (len(j64) // 4), j64)
    n_bself = sum(1 for w in words if w == B_SELF)
    if e4:
        # E4：seq_exit 自旋（exit_off+16·承 A 线 F6 halt_pc 实证）
        exit_off = int(m_mc.group(1))
        slot_off = exit_off + 16
        assert struct.unpack_from('<I', j64, slot_off)[0] == B_SELF, \
            'seq_exit 自旋位点异常 @0x%X' % slot_off
        print('E4 槽位点：seq_exit 自旋 @0x%X（exit_off+16·B_SELF ✓）' % slot_off)
    else:
        # 构建版：park 位点扫描（B_SELF 且前一条 BL→svc_int13·唯一）
        cands = []
        for i in range(1, len(words)):
            if words[i] != B_SELF:
                continue
            bl = words[i - 1]
            if (bl & 0xFC000000) != 0x94000000:
                continue
            off = bl & 0x3FFFFFF
            if off >= (1 << 25):
                off -= (1 << 26)
            if (i - 1 + off) * 4 == svc_off:        # BL 目标 == svc_int13
                cands.append(i)
        assert len(cands) == 1, '「INT13h 后自旋」候选不唯一：%s' % [(i * 4) for i in cands]
        slot_off = cands[0] * 4
        assert slot_off == park_manifest, '扫描(%d) 与 manifest(%d) 不符' % (slot_off, park_manifest)
        print('park 位点：B_SELF 全量 %d 处 · 候选 1 处 @0x%X（manifest 双核对 ✓）'
              % (n_bself, slot_off))

    # ===== 4) b_word（自旋 → trap 的相对 B）=====
    delta = meta['trap_off'] - (J64_OFF + slot_off)
    assert delta % 4 == 0, delta
    imm = delta // 4
    assert -(1 << 25) <= imm < (1 << 25), imm
    b_word = B_SELF | (imm & 0x3FFFFFF)
    print('trap_off=0x%X - slot_blob=0x%X → B imm=%d → b_word=0x%08X' %
          (meta['trap_off'], J64_OFF + slot_off, imm, b_word))

    # ===== 5) 回填（占位替换·计数断言）：stub 内 J64_VA · data 内槽 =====
    place = elfpkg64a.movz4(24, androidstub.PLACE_HOLD)
    newv = elfpkg64a.movz4(24, J64_VA)
    assert stub.count(place) == 1, 'J64 占位不唯一'
    stub2 = stub.replace(place, newv)
    slot_pat = struct.pack('<II', androidstub.SLOT_MAGIC, androidstub.SLOT_MAGIC)
    assert data.count(slot_pat) == 1, 'park 槽占位不唯一'
    data2 = data.replace(slot_pat, struct.pack('<II', slot_off, b_word))
    assert place not in stub2, 'J64 占位残留！'
    assert slot_pat not in data2, 'park 槽占位残留！'
    print('回填：J64_VA=0x%X（占位×1）· 槽={slot_off=%d, b_word=0x%08X}' %
          (J64_VA, slot_off, b_word))

    # ===== 6) J64′ 构建期补丁（park→trap 离线写入·承 规格/50 §2.2）=====
    j64p = bytearray(j64)
    old = struct.unpack_from('<I', j64p, slot_off)[0]
    assert old == B_SELF, 'slot old 非 B_SELF：0x%08X' % old
    struct.pack_into('<I', j64p, slot_off, b_word)
    jdiff = [i for i in range(len(j64)) if j64p[i] != j64[i]]
    assert jdiff and min(jdiff) >= slot_off and max(jdiff) < slot_off + 4, \
        'J64′ 差异超界：%s' % jdiff[:8]
    print('J64′ 构建期补丁：{slot_off=%d, old=0x%08X, new=0x%08X}（差异 %d B @%d）'
          % (slot_off, old, b_word, len(jdiff), slot_off))
    j64p = bytes(j64p)

    # ===== 7) 组装 main_blob（J64′：除 1 word 登记补丁外逐字节原样）=====
    blob = bytearray(stub2)
    blob += b'\x00' * (J64_OFF - len(blob))
    blob += j64p
    assert len(blob) == J64_OFF + len(j64), len(blob)
    bdiff = [i for i in range(len(j64)) if blob[J64_OFF + i] != j64[i]]
    assert len(bdiff) == 4 and bdiff[0] == slot_off, 'J64′ 差异集异常：%s' % bdiff[:8]
    print('组装：main_blob %d B（桩+壳+垫+J64′）· 差异集 == {slot_off…slot_off+4}' % len(blob))

    # ===== 8) ELF 包装（elfpkg64a.build_ds·双段 RX/RW·W^X 合规）=====
    elf, dmeta = elfpkg64a.build_ds(bytes(blob), data2, entry=ENTRY)
    assert dmeta['data_off'] == meta['data_off'] and dmeta['data_va'] == data_va, \
        'build_ds meta 与 androidstub meta 不符：%s' % dmeta
    open(out_path, 'wb').write(elf)
    print()
    print('%s 写出：%d B（0x%X）· md5 %s' %
          (os.path.basename(out_path), len(elf), len(elf), hashlib.md5(elf).hexdigest()))
    print('  e_entry 0x%X · J64_VA 0x%X · seg1[0,0x%X) R|X · seg2[0x%X,0x%X) R|W（data_va 0x%X）' %
          (BASE + ENTRY, J64_VA, dmeta['data_off'], dmeta['data_off'],
           dmeta['data_off'] + len(data2), dmeta['data_va']))
    return 0


if __name__ == '__main__':
    sys.exit(main())
