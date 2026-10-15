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
HDR2 = 64 + 56 * 2       # ehdr + 2 phdr = 0xB0（双段布局 v2·W^X 合规·承 规格/50 §2.1）
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


def build_ds(blob, data, *, base=BASE, entry=None, fixups=(), align=0x1000):
    """构造双段 static ELF64（AArch64·W^X 合规布局 v2·承 规格/50 §2.1）。

    seg1（R|X·offset 0·vaddr base）：ehdr＋phdr×2（HDR2=0xB0）＋blob，
        p_filesz = p_memsz = HDR2 + len(blob)
    seg2（R|W·offset align_up(HDR2+len(blob))·vaddr base+同）：data，
        p_filesz = p_memsz = len(data)
    页规则：seg2 起点页对齐 ⇒ seg1 页域 [0, seg2_off) 与 seg2 页域不重叠
    （无共享页——任何页不得同时含可写数据与可执行码）。
    fixups 语义同 build（blob 内偏移 → 回填值 = base + HDR2 + target）。
    返回 (file_bytes, meta{'data_off','data_va'})。"""
    blob = bytes(blob)
    data = bytes(data)
    assert len(data) > 0, '数据段为空（双段构造需非空数据）'
    buf = bytearray(blob)

    # 绝对地址回填（fixups·movz/movk 四段·blob 内空间）
    for off, target in fixups:
        _patch_movz4(buf, off, base + HDR2 + target)

    if entry is None:
        entry = HDR2
    seg1_filesz = HDR2 + len(buf)
    seg2_off = (seg1_filesz + align - 1) // align * align   # 页对齐（= seg1 页域上界）
    seg2_va = base + seg2_off
    assert (seg2_va - seg2_off) % align == 0, 'seg2 (vaddr-offset) 非页对齐'
    assert seg1_filesz <= seg2_off, 'seg1 与 seg2 共享页'
    total = seg2_off + len(data)

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
    eh += struct.pack('<H', 2)          # e_phnum（双段）
    eh += struct.pack('<H', 0) + struct.pack('<H', 0) + struct.pack('<H', 0)
    assert len(eh) == 64

    # —— 程序头 ×2 ——
    ph1 = struct.pack('<IIQQQQQQ',
                      1,          # p_type  = PT_LOAD
                      5,          # p_flags = R|X（代码段）
                      0,          # p_offset = 0
                      base,       # p_vaddr
                      base,       # p_paddr
                      seg1_filesz, seg1_filesz,
                      align)
    ph2 = struct.pack('<IIQQQQQQ',
                      1,          # p_type  = PT_LOAD
                      6,          # p_flags = R|W（数据段）
                      seg2_off,   # p_offset
                      seg2_va,    # p_vaddr
                      seg2_va,    # p_paddr
                      len(data), len(data),
                      align)
    assert len(ph1) == 56 and len(ph2) == 56

    out = bytes(eh) + ph1 + ph2 + bytes(buf)
    assert len(out) == seg1_filesz
    out += b'\x00' * (seg2_off - len(out)) + data
    assert len(out) == total
    return out, {'data_off': seg2_off, 'data_va': seg2_va}


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
    # 双段（build_ds·W^X 布局 v2·承 规格/50 §2.1）
    ddata = b'DS-OK\n'
    out2, meta2 = build_ds(code, ddata, fixups=[(0, 8)])
    assert meta2['data_off'] == 0x1000 and meta2['data_va'] == 0x401000, meta2
    assert len(out2) == 0x1000 + len(ddata)
    (e_phnum,) = struct.unpack_from('<H', out2, 56)
    assert e_phnum == 2, e_phnum
    (f1, f2) = struct.unpack_from('<I', out2, 64 + 4)[0], \
        struct.unpack_from('<I', out2, 64 + 56 + 4)[0]
    assert f1 == 5 and f2 == 6, (f1, f2)
    assert _decode_movz4(out2, HDR2) == 0x400000 + HDR2 + 8
    out3, _ = build_ds(code, ddata)                      # 无 fixup：seg1 字节保真
    assert out3[HDR2:HDR2 + len(code)] == code, 'seg1 代码区不符'
    assert out2[HDR2 + 16:HDR2 + len(code)] == code[16:], 'seg1 代码区不符（回填后尾部）'
    assert out2[0x1000:] == ddata, 'seg2 数据区不符'
    print('elfpkg64a 自检：movz4 直填/回填 ✓ · 样本 %d B · 双段 %d B（meta %s）· md5 %s'
          % (len(out), len(out2), meta2, hashlib.md5(out).hexdigest()[:12]))
