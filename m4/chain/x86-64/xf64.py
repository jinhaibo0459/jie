# -*- coding: utf-8 -*-
# xf64.py —— jiqi 16→64 接续变换器（正式版 · S3-C-98 定版）
#   规则：R1–R10（规格/09 §三·补）+ 接续四类：
#     ① INT 13h（×5·写盘）→ 写盘接续（44 B·call thunk64 0x6000）
#     ② INT 10h（×3·失败显示）→ 显示接续（11 B·写显存 0xB8000）
#     ③ seg（8E C0·×4）→ R14 ← 段值×16（41 BE imm32）
#     ④ EA（×1·执行出口）→ 完成签名+停住 桩（12 B·测试模式出口）
#   校验：xj64_check.py v2（as 实测模板独立对拍）
#   沿革：xf64（陷阱桩版·S3-C-94/95）→ xf64b（接续版·S3-C-96）→ S3-C-98（正式化）→ S3-C-126（对 4741·MJ-2 跳板化基线）→ S3-C-138（对 5382·处理外批）
#   输入：jiqi16.jie（5382 B · jie.jie[512:512+5382] 提取 · md5 001c34443c01a8e1254605a21d1cb6c4）
#   在 xf64.py（R1–R10 机械翻译·陷阱桩版）基础上，把「系统指令位点」升级为「真实接续」：
#     ① INT 13h（×5·写盘）→ 写盘接续序列（44 B）：
#         push rax/rdi → 装参数块 0x9020（BL/BH/CL/CH/DH/AL/AH）→ ES 字段 = R14>>4（[0x902C]）
#         → call thunk64（0x6000·rel32）→ pop rdi/rax
#     ② INT 10h（×3·失败显示）→ 显示接续序列（11 B）：写显存 0xB8000（AL 字符 + 属性 07）→ 流入原 EB FE
#     ③ 执行出口 EA（×1）→ 保持「完成签名 + 停住」桩（12 B·测试模式出口不变）
#     ④ seg（8E C0·×4）→ R14 ← 段值×16（41 BE imm32·同 xf64）
#   断言：8 陷阱 = 5×13h + 3×10h；4 seg；1 exit；8E C0 紧邻前驱必为 B8 imm16 且 imm ∈ {0,0x1000}
#   输出：jiqi64.jie + xf64_manifest.txt（分类统计/位点清单/长度账/扇区裁决）
import os, hashlib
from collections import Counter

D = os.path.dirname(os.path.abspath(__file__))
data = open(os.path.join(D, 'jiqi16.jie'), 'rb').read()
assert len(data) == 5382, len(data)
assert hashlib.md5(data).hexdigest() == '001c34443c01a8e1254605a21d1cb6c4', hashlib.md5(data).hexdigest()

# ---- SIB 工具（同 xf64 勘误版：index=换码后 32 位号·base=R15/R14·scale=0）----
RECODE = {4: 6, 5: 7, 7: 3}
def sib_ds(rm):
    assert rm in RECODE, 'SIB(DS) 目标未登记 rm=%d' % rm
    return (RECODE[rm] << 3) | 7        # base=R15(111)：BX→1F·SI→37·DI→3F

def sib_es(rm):
    assert rm in RECODE, 'SIB(ES) 目标未登记 rm=%d' % rm
    return (RECODE[rm] << 3) | 6        # base=R14(110)：BX→1E·SI→36·DI→3E

def modrm_sib(reg):
    return 0x04 | (reg << 3)    # mod=00, rm=100（SIB 跟随）

# ================= 接续序列模板 =================
# ① 写盘接续（44 B；call 位于序列内偏移 37，rel32 = 0x6000-(0x7E00+na+42)）
CALL13_SEQ = bytes.fromhex(
    '50'                # pushq %rax
    '57'                # pushq %rdi
    'bf20900000'        # movl $0x9020, %edi
    '881f'              # movb %bl, (%rdi)
    '887f01'            # movb %bh, 1(%rdi)
    '884f02'            # movb %cl, 2(%rdi)
    '886f03'            # movb %ch, 3(%rdi)
    '887704'            # movb %dh, 4(%rdi)
    '884705'            # movb %al, 5(%rdi)
    '886706'            # movb %ah, 6(%rdi)
    '4489f0'            # movl %r14d, %eax
    'c1e804'            # shrl $4, %eax
    '6689470c'          # movw %ax, 0xC(%rdi)（★ES 段值字段）
    'e800000000'        # call 0x6000（rel32 待填）
    '5f'                # popq %rdi
    '58'                # popq %rax
)
assert len(CALL13_SEQ) == 44, len(CALL13_SEQ)
CALL_POS = CALL13_SEQ.index(bytes.fromhex('e800000000'))
assert CALL_POS == 37, CALL_POS

# ② 显示接续（11 B）：写显存 0xB8000（左上角·字符 AL + 属性 07；失败路径随后流入原 EB FE 停住）
DISP_SEQ = bytes.fromhex(
    'bf00800b00'        # movl $0xB8000, %edi
    '8807'              # movb %al, (%rdi)
    'c6470107'          # movb $7, 1(%rdi)
)
assert len(DISP_SEQ) == 11, len(DISP_SEQ)

# ================= 解析（同 xf64）=================
insns = []   # (old_off, orig_len, new_bytes_or_spec, kind)
p = 0
prev = None
while p < len(data):
    b = data[p]
    if b == 0x26:
        op2, m = data[p+1], data[p+2]
        assert op2 in (0x88, 0x89), '26 %02X 未登记 @%04X' % (op2, p)
        assert m >> 6 == 0, '26 前缀 mod≠0 @%04X' % p
        reg, rm = (m >> 3) & 7, m & 7
        s = sib_es(rm)
        if op2 == 0x88:
            raw = bytes([0x26, 0x41, 0x88, modrm_sib(reg), s])
        else:
            raw = bytes([0x26, 0x66, 0x41, 0x89, modrm_sib(reg), s])
        insns.append((p, 3, raw, 'i')); p += 3
    elif b in (0x01, 0x2B, 0x3B):
        m = data[p+1]
        assert m >> 6 == 3, 'arith16 mod≠3 @%04X' % p
        insns.append((p, 2, bytes([0x66, b, m]), 'i')); p += 2
    elif b in (0x05, 0x2D):
        insns.append((p, 3, bytes([0x66, b]) + data[p+1:p+3], 'i')); p += 3
    elif b in (0x2C, 0x3C):
        insns.append((p, 2, data[p:p+2], 'i')); p += 2
    elif b in (0x38, 0x3A):
        m = data[p+1]
        assert m >> 6 == 3, 'byte8(38/3A) mod≠3 @%04X' % p
        insns.append((p, 2, data[p:p+2], 'i')); p += 2
    elif 0x40 <= b <= 0x47:
        insns.append((p, 1, bytes([0x66, 0xFF, 0xC0 + (b - 0x40)]), 'i')); p += 1
    elif 0x50 <= b <= 0x5F:
        insns.append((p, 1, bytes([0x66, b]), 'i')); p += 1
    elif b in (0x88, 0x8A):
        m = data[p+1]
        if m >> 6 == 3:
            insns.append((p, 2, data[p:p+2], 'i'))
        else:
            reg, rm = (m >> 3) & 7, m & 7
            insns.append((p, 2, bytes([0x41, b, modrm_sib(reg), sib_ds(rm)]), 'i'))
        p += 2
    elif b in (0x89, 0x8B):
        m = data[p+1]
        if m >> 6 == 3:
            insns.append((p, 2, bytes([0x66, b, m]), 'i'))
        else:
            reg, rm = (m >> 3) & 7, m & 7
            insns.append((p, 2, bytes([0x66, 0x41, b, modrm_sib(reg), sib_ds(rm)]), 'i'))
        p += 2
    elif b == 0x8E:
        assert data[p+1] == 0xC0, '8E %02X @%04X' % (data[p+1], p)
        assert prev is not None and prev[0] + prev[1] == p, '8E C0 无紧邻前驱 @%04X' % p
        pi = prev[0]
        assert data[pi] == 0xB8 and prev[1] == 3, '8E C0 前驱非 B8 imm16 @%04X' % p
        imm = data[pi+1] | (data[pi+2] << 8)
        assert imm in (0x0000, 0x1000), '段值集合外 %04X @%04X' % (imm, p)
        segv = (imm << 4) & 0xFFFFFFFF
        insns.append((p, 2, bytes([0x41, 0xBE]) + segv.to_bytes(4, 'little'), 'i')); p += 2
    elif 0xB0 <= b <= 0xB7:
        insns.append((p, 2, data[p:p+2], 'i')); p += 2
    elif 0xB8 <= b <= 0xBF:
        insns.append((p, 3, bytes([0x66, b]) + data[p+1:p+3], 'i')); p += 3
    elif b == 0xC3:
        insns.append((p, 1, data[p:p+1], 'i')); p += 1
    elif b == 0xFE:
        m = data[p+1]
        assert m >> 6 == 3, 'FE mod≠3 @%04X' % p
        insns.append((p, 2, data[p:p+2], 'i')); p += 2
    elif b == 0xD1:
        m = data[p+1]
        assert m >> 6 == 3, 'D1 mod≠3 @%04X' % p
        insns.append((p, 2, bytes([0x66, 0xD1, m]), 'i')); p += 2
    elif b == 0xCD:
        insns.append((p, 2, None, ('int', data[p+1]))); p += 2
    elif b == 0x0F:
        op2 = data[p+1]; assert op2 in (0x84, 0x85), '0F %02X @%04X' % (op2, p)
        rel = int.from_bytes(data[p+2:p+4], 'little', signed=True)
        insns.append((p, 4, (0x0F, op2, p + 4 + rel), 'i')); p += 4
    elif b in (0xE8, 0xE9):
        rel = int.from_bytes(data[p+1:p+3], 'little', signed=True)
        insns.append((p, 3, (b, None, p + 3 + rel), 'i')); p += 3
    elif b == 0xEB:
        rel = int.from_bytes(data[p+1:p+2], 'little', signed=True)
        insns.append((p, 2, (0xEB, None, p + 2 + rel), 'i')); p += 2
    elif b == 0xEA:
        insns.append((p, 5, None, ('exit',))); p += 5
    else:
        raise AssertionError('未登记 opcode %02X @ %04X' % (b, p))
    prev = (insns[-1][0], insns[-1][1])
assert p == len(data), '解析未覆盖全文件'

for i in range(1, len(insns)):
    assert insns[i][0] == insns[i-1][0] + insns[i-1][1], '不连续 @%04X' % insns[i][0]

# ================= 布局 =================
NEWMAP = {}
off = 0
for (o, ol, raw, kind) in insns:
    NEWMAP[o] = off
    if isinstance(kind, tuple) and kind[0] == 'int':
        ln = len(CALL13_SEQ) if kind[1] == 0x13 else len(DISP_SEQ)
    elif kind == ('exit',):
        ln = 12
    elif isinstance(raw, tuple):
        ln = 6 if raw[0] == 0x0F else 5
    else:
        ln = len(raw)
    off += ln
NEWMAP[len(data)] = off
J64LEN = off

# ================= 生成 =================
JI64_LOAD = 0x7E00       # jiqi64v 装载物理基址（0x7E00+7680=0x9C00 < 0xA000 ✓）
THUNK64 = 0x6000         # thunk64 固定入口
out = bytearray()
traps = []
for (o, ol, raw, kind) in insns:
    if isinstance(kind, tuple) and kind[0] == 'int':
        na = NEWMAP[o]
        if kind[1] == 0x13:
            seq = bytearray(CALL13_SEQ)
            rel = THUNK64 - (JI64_LOAD + na + CALL_POS + 5)
            seq[CALL_POS+1:CALL_POS+5] = rel.to_bytes(4, 'little', signed=True)
            traps.append((o, kind[1], na, rel))
            out += bytes(seq)
        else:
            traps.append((o, kind[1], na, None))
            out += DISP_SEQ
    elif kind == ('exit',):
        out += bytes([0x66, 0x41, 0xC7, 0x87, 0xF6, 0xF0, 0x00, 0x00, 0x77, 0x00])
        out += bytes([0xEB, 0xFE])
    elif isinstance(raw, tuple):
        b0 = raw[0]
        if b0 == 0x0F:
            tgt = raw[2]; na = NEWMAP[o]; rel = NEWMAP[tgt] - (na + 6)
            out += bytes([0x0F, raw[1]]) + rel.to_bytes(4, 'little', signed=True)
        else:
            tgt = raw[2]; na = NEWMAP[o]; rel = NEWMAP[tgt] - (na + 5)
            opc = 0xE8 if b0 == 0xE8 else 0xE9
            out += bytes([opc]) + rel.to_bytes(4, 'little', signed=True)
    else:
        out += raw
assert len(out) == J64LEN, (len(out), J64LEN)

# ================= 复核 =================
bound = set(NEWMAP.keys())
for (o, ol, raw, kind) in insns:
    if isinstance(raw, tuple):
        t = raw[2]
        assert t in bound, '跳转目标非边界 @%04X -> %04X' % (o, t)

traps_ = [it for it in insns if isinstance(it[3], tuple) and it[3][0] == 'int']
segs = [it for it in insns if it[2] is not None and isinstance(it[2], bytes) and len(it[2]) == 6 and it[2][:2] == bytes([0x41, 0xBE])]
exits = [it for it in insns if it[3] == ('exit',)]
n13 = sum(1 for it in traps if it[1] == 0x13)
n10 = sum(1 for it in traps if it[1] == 0x10)
assert len(traps_) == 8 and n13 == 5 and n10 == 3, (len(traps_), n13, n10)
assert len(segs) == 4 and len(exits) == 1, (len(segs), len(exits))
ex_old = exits[0][0]; ex_new = NEWMAP[ex_old]
HALT_EIP = JI64_LOAD + ex_new + 10

# call 目标自检（rel 解析回 0x6000）
for o, no, na, rel in traps:
    if no == 0x13:
        assert JI64_LOAD + na + CALL_POS + 5 + rel == THUNK64, '@%04X rel 解析异常' % o

c = Counter()
for (o, ol, raw, kind) in insns:
    if isinstance(kind, tuple) and kind[0] == 'int':
        c['int→接续(%s)' % ('写盘44B' if kind[1] == 0x13 else '显示11B')] += 1
    elif kind == ('exit',): c['exit→出口桩(12B)'] += 1
    elif isinstance(raw, tuple): c['branch→rel32'] += 1
    elif isinstance(raw, bytes) and len(raw) == 6 and raw[:2] == bytes([0x41, 0xBE]): c['seg(R14 imm)'] += 1
    elif isinstance(raw, bytes) and (raw[0] == 0x41 or (len(raw) >= 2 and raw[1] == 0x41)): c['REX(41)'] += 1
    elif isinstance(raw, bytes) and (raw[0] == 0x66 or (len(raw) >= 2 and raw[1] == 0x66)): c['66 前缀'] += 1
    else: c['其他'] += 1

open(os.path.join(D, 'jiqi64.jie'), 'wb').write(bytes(out))
lines = []
lines.append('jiqi16=5382 → jiqi64=%d（Δ=%+d）md5=%s' % (len(out), len(out) - 5382, hashlib.md5(bytes(out)).hexdigest()))
lines.append('指令 %d 条' % len(insns))
lines.append('分类: %s' % dict(c))
lines.append('接续位点（thunk64@0x6000·装载 0x7E00）：')
for o, no, na, rel in traps:
    kindname = '写盘接续(call thunk64 44B)' if no == 0x13 else '显示接续(显存 0xB8000·11B)'
    lines.append('  @%04X  INT %02X → 新偏移 %04X  %s%s' % (o, no, na, kindname, ('  rel=%d' % rel) if rel is not None else ''))
for it in segs:
    o = it[0]; imm = data[it[0]-2] | (data[it[0]-1] << 8)
    lines.append('  @%04X  mov es,ax（段值 %04X → R14=%05X）→ 新偏移 %04X（41 BE imm32）' % (o, imm, (imm << 4) & 0xFFFFFFFF, NEWMAP[o]))
lines.append('执行出口 @%04X → 新偏移 %04X；完成签名 [R15+0xF0F6]←0x0077；停住 EIP(载 0x7E00)=0x%X' % (ex_old, ex_new, HALT_EIP))
lines.append('长度账：14 扇区 7168 → %s；15 扇区 7680 → %s（余 %d）；16 扇区 8192 → %s（余 %d）'
             % ('OK' if J64LEN <= 7168 else '超限',
                'OK' if J64LEN <= 7680 else '超限', 7680 - J64LEN,
                'OK' if J64LEN <= 8192 else '超限', 8192 - J64LEN))
txt = '\n'.join(lines)
open(os.path.join(D, 'xf64_manifest.txt'), 'w', encoding='utf-8').write(txt + '\n')
print(txt)
