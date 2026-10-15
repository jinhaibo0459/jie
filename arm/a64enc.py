# -*- coding: utf-8 -*-
# a64enc.py —— ARM 编码字典（AArch64）·机器可读形式【纯手写编码 · 零外部工具链】
#   S3-C-111（A-1）产出 —— 每条公式经 QEMU 行为标定（calib_a64.py·全绿）
#   编码来源：AArch64 架构规范位域公式（手推）；验证：QEMU virt 虚拟真机行为判据
#   约定：寄存器号 Rd/Rn/Rm/Rt ∈ 0..30；31 在 Rd=ZR（UZR）、Rn=SP 视上下文
#   命名：下划线位号 acc 由公式直译；_w/_x = 32 位/64 位变体
#   （本文件为「编码字典」的机器可读形态；文档形态见 规格/35）

# ================= 条件码全集（B.cond / 条件选择） =================
COND = {
    'EQ': 0x0, 'NE': 0x1, 'HS': 0x2, 'LO': 0x3,   # HS=CS（无符号 ≥）／LO=CC（无符号 <）
    'MI': 0x4, 'PL': 0x5, 'VS': 0x6, 'VC': 0x7,
    'HI': 0x8, 'LS': 0x9, 'GE': 0xA, 'LT': 0xB,
    'GT': 0xC, 'LE': 0xD, 'AL': 0xE,
    # 别名
    'CS': 0x2, 'CC': 0x3,
}

def _chk(v, lo, hi, what):
    assert lo <= v <= hi, '%s 越界: %d（应 %d..%d）' % (what, v, lo, hi)
    return v

# ================= 数据搬移（立即数） =================
def movz_w(rd, imm16):
    """MOVZ Wd, #imm16        : 52800000 | imm16<<5 | Rd"""
    _chk(rd, 0, 31, 'Rd'); _chk(imm16, 0, 0xFFFF, 'imm16')
    return 0x52800000 | (imm16 << 5) | rd

def movz_x(rd, imm16, hw=0):
    """MOVZ Xd, #imm16, lsl#hw : D2800000 | hw<<21 | imm16<<5 | Rd"""
    _chk(rd, 0, 31, 'Rd'); _chk(imm16, 0, 0xFFFF, 'imm16'); _chk(hw, 0, 3, 'hw')
    return 0xD2800000 | (hw << 21) | (imm16 << 5) | rd

def movk_w(rd, imm16, hw=0):
    """MOVK Wd, #imm16, lsl#hw : 72800000 | hw<<21 | imm16<<5 | Rd"""
    _chk(rd, 0, 31, 'Rd'); _chk(imm16, 0, 0xFFFF, 'imm16'); _chk(hw, 0, 3, 'hw')
    return 0x72800000 | (hw << 21) | (imm16 << 5) | rd

def movk_x(rd, imm16, hw=0):
    """MOVK Xd, #imm16, lsl#hw : F2800000 | hw<<21 | imm16<<5 | Rd"""
    _chk(rd, 0, 31, 'Rd'); _chk(imm16, 0, 0xFFFF, 'imm16'); _chk(hw, 0, 3, 'hw')
    return 0xF2800000 | (hw << 21) | (imm16 << 5) | rd

def movn_w(rd, imm16, hw=0):
    """MOVN Wd, #imm16, lsl#hw : 12800000 | hw<<21 | imm16<<5 | Rd（储备）"""
    _chk(rd, 0, 31, 'Rd'); _chk(imm16, 0, 0xFFFF, 'imm16'); _chk(hw, 0, 3, 'hw')
    return 0x12800000 | (hw << 21) | (imm16 << 5) | rd

def movn_x(rd, imm16, hw=0):
    """MOVN Xd, #imm16, lsl#hw : 92800000 | hw<<21 | imm16<<5 | Rd（储备）"""
    _chk(rd, 0, 31, 'Rd'); _chk(imm16, 0, 0xFFFF, 'imm16'); _chk(hw, 0, 3, 'hw')
    return 0x92800000 | (hw << 21) | (imm16 << 5) | rd

# ================= 寄存器搬移（ORR 别名 MOV） =================
def mov_w(rd, rm):
    """MOV Wd, Wm  = ORR Wd, WZR, Wm : 2A0003E0 | Rm<<16 | Rd"""
    _chk(rd, 0, 30, 'Rd'); _chk(rm, 0, 30, 'Rm')
    return 0x2A0003E0 | (rm << 16) | rd

def mov_x(rd, rm):
    """MOV Xd, Xm  = ORR Xd, XZR, Xm : AA0003E0 | Rm<<16 | Rd"""
    _chk(rd, 0, 30, 'Rd'); _chk(rm, 0, 30, 'Rm')
    return 0xAA0003E0 | (rm << 16) | rd

# ================= 算术（加减） =================
def add_w(rd, rn, rm):
    """ADD Wd, Wn, Wm  : 0B000000 | Rm<<16 | Rn<<5 | Rd"""
    return 0x0B000000 | (rm << 16) | (rn << 5) | rd

def add_x_reg(rd, rn, rm):
    """ADD Xd, Xn, Xm  : 8B000000 | Rm<<16 | Rn<<5 | Rd（64 位·A-2 扩展·ret 链用）"""
    _chk(rd, 0, 31, 'Rd'); _chk(rn, 0, 31, 'Rn'); _chk(rm, 0, 31, 'Rm')
    return 0x8B000000 | (rm << 16) | (rn << 5) | rd

def adds_w(rd, rn, rm):
    """ADDS Wd, Wn, Wm : 2B000000 | Rm<<16 | Rn<<5 | Rd"""
    return 0x2B000000 | (rm << 16) | (rn << 5) | rd

def add_w_imm(rd, rn, imm12):
    """ADD Wd, Wn, #imm12 : 11000000 | imm12<<10 | Rn<<5 | Rd"""
    _chk(imm12, 0, 0xFFF, 'imm12')
    return 0x11000000 | (imm12 << 10) | (rn << 5) | rd

def adds_w_imm(rd, rn, imm12):
    """ADDS Wd, Wn, #imm12 : 31000000 | imm12<<10 | Rn<<5 | Rd"""
    _chk(imm12, 0, 0xFFF, 'imm12')
    return 0x31000000 | (imm12 << 10) | (rn << 5) | rd

def add_x_imm(rd, rn, imm12):
    """ADD Xd, Xn, #imm12 : 91000000 | imm12<<10 | Rn<<5 | Rd"""
    _chk(imm12, 0, 0xFFF, 'imm12')
    return 0x91000000 | (imm12 << 10) | (rn << 5) | rd

def sub_w(rd, rn, rm):
    """SUB Wd, Wn, Wm  : 4B000000 | Rm<<16 | Rn<<5 | Rd"""
    return 0x4B000000 | (rm << 16) | (rn << 5) | rd

def subs_w(rd, rn, rm):
    """SUBS Wd, Wn, Wm : 6B000000 | Rm<<16 | Rn<<5 | Rd"""
    return 0x6B000000 | (rm << 16) | (rn << 5) | rd

def sub_w_imm(rd, rn, imm12):
    """SUB Wd, Wn, #imm12 : 51000000 | imm12<<10 | Rn<<5 | Rd"""
    _chk(imm12, 0, 0xFFF, 'imm12')
    return 0x51000000 | (imm12 << 10) | (rn << 5) | rd

def subs_w_imm(rd, rn, imm12):
    """SUBS Wd, Wn, #imm12 : 71000000 | imm12<<10 | Rn<<5 | Rd"""
    _chk(imm12, 0, 0xFFF, 'imm12')
    return 0x71000000 | (imm12 << 10) | (rn << 5) | rd

def sub_x_imm(rd, rn, imm12):
    """SUB Xd, Xn, #imm12 : D1000000 | imm12<<10 | Rn<<5 | Rd"""
    _chk(imm12, 0, 0xFFF, 'imm12')
    return 0xD1000000 | (imm12 << 10) | (rn << 5) | rd

def subs_x_imm(rd, rn, imm12):
    """SUBS Xd, Xn, #imm12 : F1000000 | imm12<<10 | Rn<<5 | Rd"""
    _chk(imm12, 0, 0xFFF, 'imm12')
    return 0xF1000000 | (imm12 << 10) | (rn << 5) | rd

# ---- CMP 别名（Rd=31=WZR） ----
def cmp_w_imm(rn, imm12):
    """CMP Wn, #imm12 = SUBS WZR, Wn, #imm12 : 71000000 | imm12<<10 | Rn<<5 | 31"""
    return subs_w_imm(31, rn, imm12)

def cmp_w_reg(rn, rm):
    """CMP Wn, Wm = SUBS WZR, Wn, Wm : 6B000000 | Rm<<16 | Rn<<5 | 31"""
    return subs_w(31, rn, rm)

def cmp_x_imm(rn, imm12):
    """CMP Xn, #imm12 = SUBS XZR, Xn, #imm12 : F1000000 | imm12<<10 | Rn<<5 | 31"""
    return subs_x_imm(31, rn, imm12)

# ---- INC/DEC 用法（ADD/SUB #1·不设标志） ----
def inc_w(rn, step=1):
    """INC Wn（x86 inc 语义近似）= ADD Wn, Wn, #step（注意：不写标志）"""
    return add_w_imm(rn, rn, step)

def dec_w(rn, step=1):
    """DEC Wn（x86 dec 语义近似）= SUB Wn, Wn, #step（注意：不写标志）"""
    return sub_w_imm(rn, rn, step)

# ================= 逻辑 =================
def and_w_reg(rd, rn, rm):
    """AND Wd, Wn, Wm : 0A000000 | Rm<<16 | Rn<<5 | Rd"""
    return 0x0A000000 | (rm << 16) | (rn << 5) | rd

def orr_w_reg(rd, rn, rm):
    """ORR Wd, Wn, Wm : 2A000000 | Rm<<16 | Rn<<5 | Rd（储备）"""
    return 0x2A000000 | (rm << 16) | (rn << 5) | rd

def eor_w_reg(rd, rn, rm):
    """EOR Wd, Wn, Wm : 4A000000 | Rm<<16 | Rn<<5 | Rd（储备）"""
    return 0x4A000000 | (rm << 16) | (rn << 5) | rd

# ---- 逻辑立即数（位掩码·N:immr:imms 编码器） ----
def _bitmask_decode(n, immr, imms, width):
    """按 ARM 规范 DecodeBitMasks 解码逻辑立即数位掩码（用于反查编码）
       规则：len=HighestSetBit(N:NOT(imms))；esize=1<<len；welem=Ones(S+1)；
             wmask=ROR(welem,R) 按 esize 重复填充至宽 width"""
    v = (n << 6) | ((~imms) & 0x3F)
    if v == 0:
        return None
    ln = v.bit_length() - 1
    if ln < 1:
        return None
    levels = (1 << ln) - 1
    s = imms & levels
    r = immr & levels
    esize = 1 << ln
    if esize > width:
        return None
    if s + 1 > esize:
        return None
    welem = (1 << (s + 1)) - 1          # S+1 位全 1
    if r:
        welem = ((welem >> r) | (welem << (esize - r))) & ((1 << esize) - 1)
    val = 0
    for i in range(width // esize):
        val |= welem << (i * esize)
    return val

def and_w_imm(rd, rn, mask):
    """AND Wd, Wn, #mask : 12000000 | N<<22 | immr<<16 | imms<<10 | Rn<<5 | Rd
       （mask 须为位掩码形态·本函数暴力反查 immr/imms·32 位下 N 恒 0）"""
    _chk(mask, 0, 0xFFFFFFFF, 'mask')
    for immr in range(64):
        for imms in range(64):
            if _bitmask_decode(0, immr, imms, 32) == mask:
                return 0x12000000 | (immr << 16) | (imms << 10) | (rn << 5) | rd
    raise ValueError('mask 非 32 位逻辑立即数形态: %08X' % mask)

# ================= 位操作（截断/移位） =================
def uxtb_w(rd, rn):
    """UXTB Wd, Wn = UBFM Wd, Wn, #0, #7 : 53001C00 | Rn<<5 | Rd（8 位零扩展截断）"""
    return 0x53001C00 | (rn << 5) | rd

# ---- 位段插入（BFM 族·A-2 扩展：8 位寄存器镜像模拟） ----
def bfi_w(rd, rn, lsb, width):
    """BFI Wd, Wn, #lsb, #width = BFM Wd,Wn,#((32-lsb)%32),#(width-1)
       : 33000000 | immr<<16 | imms<<10 | Rn<<5 | Rd（插源低位段到目标位段·其余保留）"""
    _chk(lsb, 0, 31, 'lsb'); _chk(width, 1, 32 - lsb, 'width')
    immr = (32 - lsb) % 32
    imms = width - 1
    return 0x33000000 | (immr << 16) | (imms << 10) | (rn << 5) | rd

def bfxil_w(rd, rn, lsb, width):
    """BFXIL Wd, Wn, #lsb, #width = BFM Wd,Wn,#lsb,#(lsb+width-1)
       : 33000000 | immr<<16 | imms<<10 | Rn<<5 | Rd（插源 [lsb+width-1:lsb] 到目标低位段）"""
    _chk(lsb, 0, 31, 'lsb'); _chk(width, 1, 32 - lsb, 'width')
    immr = lsb
    imms = lsb + width - 1
    return 0x33000000 | (immr << 16) | (imms << 10) | (rn << 5) | rd

def uxth_w(rd, rn):
    """UXTH Wd, Wn = UBFM Wd, Wn, #0, #15 : 53003C00 | Rn<<5 | Rd（16 位零扩展截断）"""
    return 0x53003C00 | (rn << 5) | rd

def lsl_w(rd, rn, sh):
    """LSL Wd, Wn, #sh = UBFM Wd,Wn,#(-sh mod 32),#(31-sh) : 53000000 | ..."""
    _chk(sh, 0, 31, 'sh')
    immr = (32 - sh) & 31
    imms = 31 - sh
    return 0x53000000 | (immr << 16) | (imms << 10) | (rn << 5) | rd

def lsr_w(rd, rn, sh):
    """LSR Wd, Wn, #sh = UBFM Wd,Wn,#sh,#31 : 53000000 | sh<<16 | 31<<10 | Rn<<5 | Rd"""
    _chk(sh, 1, 31, 'sh')
    return 0x53000000 | (sh << 16) | (31 << 10) | (rn << 5) | rd

def lsr_x(rd, rn, sh):
    """LSR Xd, Xn, #sh = UBFM Xd,Xn,#sh,#63 : D3400000 | sh<<16 | 63<<10 | Rn<<5 | Rd（64 位）"""
    _chk(sh, 1, 63, 'sh')
    return 0xD3400000 | (sh << 16) | (63 << 10) | (rn << 5) | rd

def asr_w(rd, rn, sh):
    """ASR Wd, Wn, #sh = SBFM Wd,Wn,#sh,#31 : 13000000 | sh<<16 | 31<<10 | Rn<<5 | Rd"""
    _chk(sh, 1, 31, 'sh')
    return 0x13000000 | (sh << 16) | (31 << 10) | (rn << 5) | rd

# ================= 内存访问（16/8 位 + 32 位储备） =================
# ---- 无符号立即数偏移（imm12·按访问宽度缩放） ----
def ldrh_w(rt, rn, off=0):
    """LDRH Wt, [Xn, #off] : 79400000 | (off/2)<<10 | Rn<<5 | Rt（读 16 位·零扩展）"""
    assert off % 2 == 0 and off // 2 <= 0xFFF, 'off'
    return 0x79400000 | ((off // 2) << 10) | (rn << 5) | rt

def strh_w(rt, rn, off=0):
    """STRH Wt, [Xn, #off] : 79000000 | (off/2)<<10 | Rn<<5 | Rt（写 16 位）"""
    assert off % 2 == 0 and off // 2 <= 0xFFF, 'off'
    return 0x79000000 | ((off // 2) << 10) | (rn << 5) | rt

def ldrb_w(rt, rn, off=0):
    """LDRB Wt, [Xn, #off] : 39400000 | off<<10 | Rn<<5 | Rt（读 8 位·零扩展）"""
    _chk(off, 0, 0xFFF, 'off')
    return 0x39400000 | (off << 10) | (rn << 5) | rt

def strb_w(rt, rn, off=0):
    """STRB Wt, [Xn, #off] : 39000000 | off<<10 | Rn<<5 | Rt（写 8 位）"""
    _chk(off, 0, 0xFFF, 'off')
    return 0x39000000 | (off << 10) | (rn << 5) | rt

def ldr_w(rt, rn, off=0):
    """LDR Wt, [Xn, #off] : B9400000 | (off/4)<<10 | Rn<<5 | Rt（读 32 位）"""
    assert off % 4 == 0 and off // 4 <= 0xFFF, 'off'
    return 0xB9400000 | ((off // 4) << 10) | (rn << 5) | rt

def str_w(rt, rn, off=0):
    """STR Wt, [Xn, #off] : B9000000 | (off/4)<<10 | Rn<<5 | Rt（写 32 位）"""
    assert off % 4 == 0 and off // 4 <= 0xFFF, 'off'
    return 0xB9000000 | ((off // 4) << 10) | (rn << 5) | rt

# ---- 前/后索引（imm9·标量） ----
def _ldst_imm9(size, opc, rt, rn, imm9, index):
    # size: 00=B,01=H,10=W；opc: 00=ST,01=LD；index: 11=前,01=后
    base = (size << 30) | (0b111 << 27) | (opc << 22) | ((imm9 & 0x1FF) << 12) | (index << 10)
    return base | (rn << 5) | rt

def strh_w_pre(rt, rn, imm9=-2):
    """STRH Wt, [Xn, #imm9]!（前索引写回·压栈用）"""
    _chk(imm9, -256, 255, 'imm9')
    return _ldst_imm9(0b01, 0b00, rt, rn, imm9, 0b11)

def ldrh_w_post(rt, rn, imm9=2):
    """LDRH Wt, [Xn], #imm9（后索引写回·弹栈用）"""
    _chk(imm9, -256, 255, 'imm9')
    return _ldst_imm9(0b01, 0b01, rt, rn, imm9, 0b01)

def strb_w_pre(rt, rn, imm9=-1):
    """STRB Wt, [Xn, #imm9]!（前索引）"""
    _chk(imm9, -256, 255, 'imm9')
    return _ldst_imm9(0b00, 0b00, rt, rn, imm9, 0b11)

def strb_w_post(rt, rn, imm9=1):
    """STRB Wt, [Xn], #imm9（后索引写回·A-3 扩展：服务桩复制循环用）"""
    _chk(imm9, -256, 255, 'imm9')
    return _ldst_imm9(0b00, 0b00, rt, rn, imm9, 0b01)

def ldrb_w_post(rt, rn, imm9=1):
    """LDRB Wt, [Xn], #imm9（后索引）"""
    _chk(imm9, -256, 255, 'imm9')
    return _ldst_imm9(0b00, 0b01, rt, rn, imm9, 0b01)

def str_w_pre(rt, rn, imm9=-4):
    """STR Wt, [Xn, #imm9]!（储备·前索引）"""
    _chk(imm9, -256, 255, 'imm9')
    return _ldst_imm9(0b10, 0b00, rt, rn, imm9, 0b11)

def ldr_w_post(rt, rn, imm9=4):
    """LDR Wt, [Xn], #imm9（储备·后索引）"""
    _chk(imm9, -256, 255, 'imm9')
    return _ldst_imm9(0b10, 0b01, rt, rn, imm9, 0b01)

# ---- 寄存器偏移（[Xn, Xm]·LSL #0·option=011） ----
def _ldst_reg(size, opc, rt, rn, rm):
    base = (size << 30) | (0b111 << 27) | (opc << 22) | (1 << 21) | (0b011 << 13) | (0b10 << 10)
    return base | (rm << 16) | (rn << 5) | rt

def ldrh_w_reg(rt, rn, rm):
    """LDRH Wt, [Xn, Xm] : 78606800 | Rm<<16 | Rn<<5 | Rt"""
    return _ldst_reg(0b01, 0b01, rt, rn, rm)

def strh_w_reg(rt, rn, rm):
    """STRH Wt, [Xn, Xm] : 78206800 | Rm<<16 | Rn<<5 | Rt"""
    return _ldst_reg(0b01, 0b00, rt, rn, rm)

def ldrb_w_reg(rt, rn, rm):
    """LDRB Wt, [Xn, Xm] : 38606800 | Rm<<16 | Rn<<5 | Rt"""
    return _ldst_reg(0b00, 0b01, rt, rn, rm)

def strb_w_reg(rt, rn, rm):
    """STRB Wt, [Xn, Xm] : 38206800 | Rm<<16 | Rn<<5 | Rt"""
    return _ldst_reg(0b00, 0b00, rt, rn, rm)

def ldr_w_reg(rt, rn, rm):
    """LDR Wt, [Xn, Xm] : B8606800 | Rm<<16 | Rn<<5 | Rt（储备）"""
    return _ldst_reg(0b10, 0b01, rt, rn, rm)

def str_w_reg(rt, rn, rm):
    """STR Wt, [Xn, Xm] : B8206800 | Rm<<16 | Rn<<5 | Rt（储备）"""
    return _ldst_reg(0b10, 0b00, rt, rn, rm)

# ================= 栈对（STP/LDP·标量对） =================
def stp_x_pre(rt1, rt2, rn, imm7=-2):
    """STP Xt1, Xt2, [Xn, #imm7*8]!（前索引·64 位对）: A9800000 | ..."""
    _chk(imm7, -64, 63, 'imm7')
    return 0xA9800000 | ((imm7 & 0x7F) << 15) | (rt2 << 10) | (rn << 5) | rt1

def ldp_x_post(rt1, rt2, rn, imm7=2):
    """LDP Xt1, Xt2, [Xn], #imm7*8（后索引·64 位对）: A8C00000 | ..."""
    _chk(imm7, -64, 63, 'imm7')
    return 0xA8C00000 | ((imm7 & 0x7F) << 15) | (rt2 << 10) | (rn << 5) | rt1

def stp_w_pre(rt1, rt2, rn, imm7=-2):
    """STP Wt1, Wt2, [Xn, #imm7*4]!（前索引·32 位对）: 29800000 | ..."""
    _chk(imm7, -64, 63, 'imm7')
    return 0x29800000 | ((imm7 & 0x7F) << 15) | (rt2 << 10) | (rn << 5) | rt1

def ldp_w_post(rt1, rt2, rn, imm7=2):
    """LDP Wt1, Wt2, [Xn], #imm7*4（后索引·32 位对）: 28C00000 | ..."""
    _chk(imm7, -64, 63, 'imm7')
    return 0x28C00000 | ((imm7 & 0x7F) << 15) | (rt2 << 10) | (rn << 5) | rt1

# ================= 分支 =================
def b_imm(off_ins):
    """B label : 14000000 | (off_ins & 0x3FFFFFF)（off_ins 为相对指令数·±128MB 域）"""
    _chk(off_ins, -(1 << 25), (1 << 25) - 1, 'off_ins')
    return 0x14000000 | (off_ins & 0x3FFFFFF)

def bl_imm(off_ins):
    """BL label : 94000000 | (off_ins & 0x3FFFFFF)"""
    _chk(off_ins, -(1 << 25), (1 << 25) - 1, 'off_ins')
    return 0x94000000 | (off_ins & 0x3FFFFFF)

def b_cond(cond, off_ins):
    """B.cond label : 54000000 | (off_ins & 0x7FFFF)<<5 | cond（off_ins 为相对指令数·±1MB 域）"""
    _chk(off_ins, -(1 << 18), (1 << 18) - 1, 'off_ins')
    c = COND[cond] if isinstance(cond, str) else cond
    return 0x54000000 | ((off_ins & 0x7FFFF) << 5) | c

def cbz_w(rt, off_ins):
    """CBZ Wt, label : 34000000 | (off_ins & 0x7FFFF)<<5 | Rt（储备）"""
    _chk(off_ins, -(1 << 18), (1 << 18) - 1, 'off_ins')
    return 0x34000000 | ((off_ins & 0x7FFFF) << 5) | rt

def cbnz_w(rt, off_ins):
    """CBNZ Wt, label : 35000000 | (off_ins & 0x7FFFF)<<5 | Rt（储备）"""
    _chk(off_ins, -(1 << 18), (1 << 18) - 1, 'off_ins')
    return 0x35000000 | ((off_ins & 0x7FFFF) << 5) | rt

def ret_(rn=30):
    """RET {Xn} : D65F0000 | Rn<<5（默认 X30/LR）"""
    return 0xD65F0000 | (rn << 5)

def br_(rn):
    """BR Xn : D61F0000 | Rn<<5（储备）"""
    return 0xD61F0000 | (rn << 5)

def blr_(rn):
    """BLR Xn : D63F0000 | Rn<<5（储备·服务桩间接调用候选）"""
    return 0xD63F0000 | (rn << 5)

# ================= 系统 =================
HVC0 = 0xD4000002     # HVC #0（PSCI 调用）
WFI  = 0xD503207F     # WFI（等待中断·复位兜底）
NOP  = 0xD503201F     # NOP
# ★A-3 勘误（S3-C-113·probe 实测抓出）：原 0x17FFFFFF = B -1（回跳前一条·imm26=0x3FFFFFF 符号扩展 -1），
#   非「B .」。正确「B .（原地自旋）」= 0x14000000（imm26=0 → PC+0）。
#   旧值长期未暴露：兜底场景（WFI 在前/回跳幂等指令）行为近似；但「停住 PC 判据」会偏一条指令。
B_SELF = 0x14000000   # B .（原地自旋·勘误修正）

def hvc(imm16=0):
    """HVC #imm16 : D4000002 | imm16<<5"""
    _chk(imm16, 0, 0xFFFF, 'imm16')
    return 0xD4000002 | (imm16 << 5)
