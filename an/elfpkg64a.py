# -*- coding: utf-8 -*-
# 跨平台/android/elfpkg64a.py —— AArch64 ELF 构造器（AN-1 · 安卓线 · S3-C-144）
#   依据：规格/48（安卓线设计稿）§三 —— 「目标格式层：ELF（AArch64·static·ET_EXEC·e_machine=0xB7）」
#   对偶：跨平台/linux/elfpkg64.py（x86-64 版）——头布局同构：ehdr(64)+phdr(56)=120 B(0x78)
#         ＋平铺 blob（code+data）·单 PT_LOAD R|W|X·fileoff 0 覆盖全文件·base 0x400000
#   差异点：①e_machine=0xB7（AArch64/183）②fixups 为「movz/movk 16 位四段」回填
#          （aarch64 无「64 位立即数 mov」——规格/48 §3.3 存疑点①定型为四段方案）
#   接口：build(code, data=b'', base=0x400000, entry=None, fixups=())
#         fixups=[(blob_off, target_blob_off), ...]
#           —— blob_off 处须为 movz4() 生成的「movz+movk×3」四指令序列（16 B）
#              回填值 = base + 0x78 + target_blob_off（绝对虚拟地址）
#   编码原文：承 a64enc.py（A-1 标定）——MOVZ Xd,#imm16,lsl#hw : D2800000|hw<<21|imm16<<5|Rd
#                                        MOVK Xd,#imm16,lsl#hw : F2800000|hw<<21|imm16<<5|Rd
import struct

BASE = 0x400000          # 默认装载基址（非 PIE）
HDR = 64 + 56            # ehdr + 1 phdr = 0x78
ENTRY_OFF = HDR          # 默认入口＝文件内代码起点

_MOVZ_X = 0xD2800000
_MOVK_X = 0xF2800000


def movz4(rd, value=0):
    """生成「movz+movk×3」四段 64 位立即数装载序列（16 B·小端指令流）。
    用途：①样本占位（value=0，随后由 build(fixups=…) 回填）②常数直填。"""
    insns = [_MOVZ_X | ((value & 0xFFFF) << 5) | rd]
    for hw in (1, 2, 3):
        insns.append(_MOVK_X | (hw << 21) | (((value >> (16 * hw)) & 0xFFFF) << 5) | rd)
    return b''.join(struct.pack('<I', i) for i in insns)


def _patch_movz4(blob, off, addr):
    """在 blob 的 off 处回填 4 条 movz/movk 的 imm16 位域（bits 5-20·保留 opcode/hw/Rd）。"""
    for hw in range(4):
        io = off + 4 * hw
        insn = struct.unpack_from('<I', blob, io)[0]
        insn = (insn & ~(0xFFFF << 5)) | (((addr >> (16 * hw)) & 0xFFFF) << 5)
        struct.pack_into('<I', blob, io, insn)


def build(code, data=b'', *, base=BASE, entry=None, fixups=()):
    """构造 static ELF64（AArch64）。返回完整文件字节串。"""
    code = bytes(code)
    data = bytes(data)
    blob = bytearray(code + data)

    # 绝对地址回填（fixups·movz/movk 四段）
    for off, target in fixups:
        _patch_movz4(blob, off, base + HDR + target)

    if entry is None:
        entry = ENTRY_OFF
    total = HDR + len(blob)

    # —— ELF 头（64 B）——
    eh = bytearray()
    eh += b'\x7fELF' + bytes([2, 1, 1, 0]) + bytes(8)   # ELF64 · LSB · v1 · SysV
    eh += struct.pack('<H', 2)          # e_type  = ET_EXEC
    eh += struct.pack('<H', 0xB7)       # e_machine = AArch64
    eh += struct.pack('<I', 1)          # e_version
    eh += struct.pack('<Q', base + entry)
    eh += struct.pack('<Q', 64)         # e_phoff
    eh += struct.pack('<Q', 0)          # e_shoff（无节表）
    eh += struct.pack('<I', 0)          # e_flags
    eh += struct.pack('<H', 64)         # e_ehsize
    eh += struct.pack('<H', 56)         # e_phentsize
    eh += struct.pack('<H', 1)          # e_phnum
    eh += struct.pack('<H', 0) + struct.pack('<H', 0) + struct.pack('<H', 0)
    assert len(eh) == 64

    # —— 程序头（56 B）：PT_LOAD · R|W|X · 文件全程覆盖 ——
    ph = struct.pack('<IIQQQQQQ',
                     1,        # p_type   = PT_LOAD
                     7,        # p_flags  = R|W|X（桩/壳/补丁需可写）
                     0,        # p_offset = 0（覆盖全文件）
                     base,     # p_vaddr
                     base,     # p_paddr
                     total,    # p_filesz
                     total,    # p_memsz
                     0x1000)   # p_align（页）
    assert len(ph) == 56

    return bytes(eh) + ph + bytes(blob)


def _decode_movz4(buf, off):
    """回读 movz4 序列的 64 位值（自检用·非构造路径）。"""
    v = 0
    for hw in range(4):
        insn = struct.unpack_from('<I', buf, off + 4 * hw)[0]
        v |= ((insn >> 5) & 0xFFFF) << (16 * hw)
    return v


if __name__ == '__main__':
    # 自检：①movz4 直填回读 ②占位+回填 == 直填 ③最小样本头核验
    import hashlib
    v = 0x123456789ABC
    seq = movz4(1, v)
    assert len(seq) == 16
    assert _decode_movz4(seq, 0) == v, 'movz4 直填回读不符'
    # 占位（0）→ 回填 → 应等于直填
    blob = bytearray(movz4(1, 0))
    _patch_movz4(blob, 0, v)
    assert bytes(blob) == movz4(1, v), '占位+回填 ≠ 直填'
    # 最小样本
    msg = b'A64-PKG-OK\n'
    code = movz4(1, 0)  # 仅占位（结构自检用·非可执行语义）
    out = build(code, msg, fixups=[(0, len(code))])
    assert len(out) == 120 + len(code) + len(msg)
    assert _decode_movz4(out, 120) == 0x400000 + 120 + len(code)
    print('elfpkg64a 自检：movz4 直填/回填 ✓ · 样本 %d B · md5 %s'
          % (len(out), hashlib.md5(out).hexdigest()[:12]))
