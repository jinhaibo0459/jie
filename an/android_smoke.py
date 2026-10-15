# -*- coding: utf-8 -*-
# 跨平台/android/android_smoke.py —— AN-1 冒烟样本构造（aarch64 · 手写级产物 · S3-C-144）
#   承 A 线「纯手写编码」范式（a64enc 公式·无外部工具链）——本件以 elfpkg64a 构造器产出。
#   样本（aarch64 · 直接 syscall · 判据文本写入 stdout=串口）：
#     s1 —— write("S144-A64-OK\n")  → reboot(poweroff)〔快速退出〕·exit 兜底
#     s2 —— write("S144-A64-OK2\n") → 同上（消息长度参数变化）
#     s3 —— write("S144 ") + write("A64-OK3\n") → 同上（代码长度・双段 write）
#   syscall 面（aarch64 通用 ABI·规格/48 §3.3 候选清单实证）：
#     write=64（x8=64·x0=fd·x1=buf·x2=len）· reboot=142（x0=magic1 0xfee1dead·
#     x1=magic2 0x28121969·x2=cmd 0x4321fedc）· exit=93 —— svc #0 触发。
#   reboot 说明：init（PID1·root）触发 PSCI SYSTEM_OFF ⇒ QEMU 快速退出；失败则 exit 兜底。
#   编码公式承 a64enc.py（A-1 标定）：movz_x=0xD2800000·movk_x=0xF2800000（hw<<21|imm16<<5|Rd）。
import struct
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import elfpkg64a

SVC0 = 0xD4000001            # SVC #0（AArch64 系统调用指令·承 a64enc 系统类同族 HVC=0xD4000002）


def _i(x):
    return struct.pack('<I', x)


def _movz(rd, imm16, hw=0):
    return _i(0xD2800000 | (hw << 21) | ((imm16 & 0xFFFF) << 5) | rd)


def _movk(rd, imm16, hw=0):
    return _i(0xF2800000 | (hw << 21) | ((imm16 & 0xFFFF) << 5) | rd)


def _movzx2(rd, v32):
    """32 位常数两段装载（movz + movk·hw 0/1）——magic 类值用。"""
    return _movz(rd, v32 & 0xFFFF, 0) + _movk(rd, (v32 >> 16) & 0xFFFF, 1)


def _write_seq(msg):
    """返回 write(1, msg, len) 序列字节 + x1 占位（movz4）在序列内的偏移。"""
    seq = bytearray()
    seq += _movz(8, 64, 0)                # x8 = 64（write）
    seq += _movz(0, 1, 0)                 # x0 = 1（stdout）
    off = len(seq)                        # movz4 占位（x1 = msg_addr）在序列内偏移
    seq += elfpkg64a.movz4(1, 0)          # x1 占位（16 B·fixup 回填）
    seq += _movz(2, len(msg), 0)          # x2 = len
    seq += _i(SVC0)                       # svc #0
    return bytes(seq), off


_TAIL = (_movz(8, 142, 0)                 # x8 = 142（reboot）
         + _movzx2(0, 0xfee1dead)         # x0 = magic1
         + _movzx2(1, 0x28121969)         # x1 = magic2
         + _movzx2(2, 0x4321fedc)         # x2 = cmd（POWER_OFF）
         + _movz(3, 0, 0)                 # x3 = arg（NULL）
         + _i(SVC0)
         + _movz(8, 93, 0)                # exit 兜底：x8 = 93（exit）
         + _movz(0, 0, 0)                 # x0 = 0
         + _i(SVC0))


def sample1():
    """write("S144-A64-OK\n") + 退出链。"""
    msg = b'S144-A64-OK\n'
    seq, off = _write_seq(msg)
    code = bytearray(seq)
    code += _TAIL
    d = len(code)
    return code, msg, [(off, d)]


def sample2():
    """write("S144-A64-OK2\n") + 退出链（长度参数变化）。"""
    msg = b'S144-A64-OK2\n'
    seq, off = _write_seq(msg)
    code = bytearray(seq)
    code += _TAIL
    d = len(code)
    return code, msg, [(off, d)]


def sample3():
    """双段 write（代码长度变化）。"""
    m1, m2 = b'S144 ', b'A64-OK3\n'
    code = bytearray()
    seq1, off1 = _write_seq(m1)
    p1 = len(code) + off1
    code += seq1
    seq2, off2 = _write_seq(m2)
    p2 = len(code) + off2
    code += seq2
    code += _TAIL
    d1 = len(code)
    d2 = d1 + len(m1)
    return code, m1 + m2, [(p1, d1), (p2, d2)]


SAMPLES = {'s1': sample1, 's2': sample2, 's3': sample3}


def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 else '_tmp_an1'
    os.makedirs(outdir, exist_ok=True)
    for name, fn in SAMPLES.items():
        code, data, fixups = fn()
        elf = elfpkg64a.build(code, data, fixups=fixups)
        path = os.path.join(outdir, name + '.elf')
        open(path, 'wb').write(elf)
        print('%s.elf: %d B（code %d + data %d·fixup %d）' %
              (name, len(elf), len(code), len(data), len(fixups)))


if __name__ == '__main__':
    main()
