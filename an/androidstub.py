# -*- coding: utf-8 -*-
# 跨平台/android/androidstub.py —— AN-2 安卓线「桩壳」构造器（S3-C-145）
#   对偶：跨平台/linux/linuxstub.s（x86-64 版）——同一机制在 aarch64 上的重写。
#   承 A 线「纯手写编码」范式（a64enc 公式 · 零外部工具链 · 不引入汇编器）。
#
#   ★机制（映射法 · aarch64 重写）：
#     jiqiA64（A 线裸机产物 · 文件零修改）在 Linux 进程内的全部绝对地址依赖，
#     由壳以 mmap 定址接住（无需任何地址补丁）：
#       UART sink @0x09000000（INT10 内联写 · 1 页匿名 · 输出吞掉）
#       ES0       @0x40200000（x86 低端 0 区模拟 · 64K · 含栈顶 0x4020FC00）
#       ES2       @0x400A0000（ES=0x2000 辅块段模拟 · 64K · S3-C-149 S5 扩容）
#       盘        @0x42000000（内存盘 1.44M · svc_int13 写目标）
#       DS        @0x41000000（源码 128 扇 · X9）
#     寄存器 X18/X9/X10/X7 由壳在跳转前设入（承 mkimg_a64 build_boothead 配方）。
#     停机适配：构建收尾「自旋环」（B_SELF · 裸机停机语义）由装载时单点重定向
#     为「B trap → exit(0)」（进程停机语义；判据从 PC 停住变为 wait4 收割）。
#     {park_off, b_word} 槽由装配器 androidpkg64.py 填写（承 linuxpkg64 装载时
#     补丁惯例——装配器自身不改 jiqiA64 段一个字节，ELF 内 J64 段逐字节原样）。
#
#   ★布局契约（androidpkg64.py 双端同步）：
#     桩区@0x000（保留零填 · AN-2 无服务桩——jiqiA64 自带 svc_int13）
#     壳@0x200（ELF 入口 0x400278）· jiqiA64@0x1E00（VA 差恒 0x1E00）
#     J64 基址占位：movz4(24, 0xE1E1F010)（装配器回填 = base+HDR+0x1E00）
#     park 槽 @数据区 +0x00：2 dword = 0xE2E2E2E2 ×2（装配器填 {park_off, b_word}）
#     meta['trap_off']（blob 内偏移）导出给装配器算 b_word。
#
#   ★运行链（对偶 L-3）：
#     init（本 ELF · PID1）→ 串口 raw → mmap×4 → 装盘（/jie_out.jie · 全量
#     1474560 B）→ 装 DS（/jie_build.jie：lseek 9216 读 128 扇 → X9+0；
#     lseek 114688 读 7 扇 → ES2+0xF100）→ [ES2+0xF000]=14（构建模式）→ clone →
#     子：patch park→trap · 设寄存器组 · BR jiqiA64（构建 → trap → exit(0)）；
#     父：wait4 轮询（500ms×240=120s 上限）→ 子 exit(0)=构建完成 → halt 行 →
#     回传（协议头 S145PROD:1474560 + 22×64KB + 32768 · 直接读共享盘区）
#     → reboot(POWER_OFF) → exit 兜底。
#
#   ★寄存器计划：X19=DS · X20=盘 · X21=ES0 · X22=文件fd · X23=子pid
#     X24=J64_VA（子段用·占位回填）· X28=数据基（全程）· X25-X27/X29=临时
#     系统栈不使用（壳无 push/pop · syscall 不需要用户栈）
#
#   ★壳变体（S3-C-146 · AN-3 · 对偶 linuxstub_e4.s 三处差异）：
#     variant='build' —— 主壳（S3-C-145 定版 · 构建模式 F000=14 · 盘回传 S145PROD:1474560）
#     variant='e4'    —— E4 变体（F000=0 测试模式 · 产物回传 S146PROD:6144〔[ES0+0xA000]〕·
#                        完成检测＝seq_exit 自旋重定向〔槽位点=exit_off+16·由装配器填〕）
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.abspath(os.path.join(HERE, '..', 'arm')))
sys.path.insert(0, HERE)
from a64enc import *          # noqa: E402
import elfpkg64a              # noqa: E402

SVC0 = 0xD4000001             # SVC #0（承 android_smoke 内联惯例）

BASE_VA    = 0x400000         # ELF 基址（elfpkg64a 契约）
HDR        = 0x78             # ehdr+phdr
SHELL_OFF  = 0x200            # 壳起点（blob 内·ELF 入口）
J64_OFF    = 0x1E00           # jiqiA64 起点（blob 内·VA 差恒 0x1E00）
PLACE_HOLD = 0xE1E1F010       # J64_VA 占位 magic（装配器回填）
SLOT_MAGIC = 0xE2E2E2E2       # park 槽占位（装配器填写）

# ---- 数据区偏移表（数据基 X28 相对 · ldr/str 用项保 4 对齐） ----
D_SLOT  = 0x00    # 8B  {park_off, b_word}（E2 占位 → 装配器填）
D_TSBUF = 0x08    # 16B wait4 status 输出
D_TBUF  = 0x18    # 64B termios 缓冲
D_NS1   = 0x58    # 16B nanosleep {0, 500000000}
D_NS2   = 0x68    # 16B nanosleep {0, 200000000}
D_FIN   = 0x78    # 15B "/jie_build.jie\0"
D_FOUT  = 0x88    # 13B "/jie_out.jie\0"
D_HDR   = 0x98    # 17B "S145PROD:1474560\n"
D_HALT  = 0xB0    # 19B "[jie-android] halt\n"
D_RMSG  = 0xC8    # 22B "S145-AN2-READBACK-FAIL\n"
D_FMSG  = 0xE0    # 15B "S145-AN2-FAIL\n"
D_SIZE  = 0xEF

# ---- 运行常量 ----
WAIT_LOOPS     = 240          # 240 × 500ms = 120s 上限
DISK_LEN       = 0x168000     # 1474560 B（1.44M 软盘）
DS_LOAD_OFF    = 9216         # 盘 LBA18（源码段 128 扇）
DS_LOAD_LEN    = 65536        # 128 × 512（S3-C-149 S5：64K 满段）
TAB_LOAD_OFF   = 114688       # 盘 LBA224（表区段 7 扇）
TAB_LOAD_LEN   = 3584         # 7 × 512
BUILD_FLAG_OFF = 0xF000       # [ES2+0xF000] = 14（构建模式·S3-C-149 S5）
ES2_BASE       = 0x400A0000   # ES2 区（ES=0x2000 辅块段模拟·S3-C-149 S5）
REBOOT_MAGIC1  = 0xFEE1DEAD
REBOOT_MAGIC2  = 0x28121969
REBOOT_POWEROFF = 0x4321FEDC

D_HALT_B = b'[jie-android] halt\n'
D_RMSG_B = b'S145-AN2-READBACK-FAIL\n'
D_FMSG_B = b'S145-AN2-FAIL\n'
D_HDR_B  = b'S145PROD:1474560\n'          # build 版协议头（盘回传）
D_HDR_E4_B = b'S146PROD:6144\n'           # e4 版协议头（产物回传）
assert len(D_HALT_B) == 19 and len(D_RMSG_B) == 23 and len(D_FMSG_B) == 14
assert len(D_HDR_B) == 17 and len(D_HDR_E4_B) == 14
E4_PROD_SIZE = 6144                       # e4 产物回传长度（[ES0+0xA000]·覆盖 jiqi16 5545）


def const_x(rd, v):
    """v（<2^32）→ X 寄存器装载序列（movz+movk·两条内）。"""
    assert 0 <= v < (1 << 32), v
    seq = [movz_x(rd, v & 0xFFFF)]
    hi = (v >> 16) & 0xFFFF
    if hi:
        seq.append(movk_x(rd, hi, hw=1))
    return seq


def movz4_words(rd, value):
    """elfpkg64a.movz4 的 4 字形态（movz+movk×3·16 B 序列）。"""
    b = elfpkg64a.movz4(rd, value)
    return list(struct.unpack('<4I', b))


class Gen:
    """单遍字表生成 + 标签回填（承 xfA64 patches 机制）。"""
    def __init__(self):
        self.w = []
        self.patches = []
        self.labels = {}

    def emit(self, *items):
        for it in items:
            if isinstance(it, (list, tuple)):
                self.w.extend(it)
            else:
                self.w.append(it)

    def lbl(self, name):
        assert name not in self.labels, '标签重复: %s' % name
        self.labels[name] = len(self.w)

    def b_to(self, name):
        self.patches.append(('b', len(self.w), name))
        self.w.append(0)

    def bc_to(self, cc, name):
        self.patches.append(('c', len(self.w), name, cc))
        self.w.append(0)

    def cbz_to(self, rt, name):
        self.patches.append(('z', len(self.w), name, rt))
        self.w.append(0)

    def cbnz_to(self, rt, name):
        self.patches.append(('n', len(self.w), name, rt))
        self.w.append(0)

    def finalize(self):
        for p in self.patches:
            k, idx, name = p[0], p[1], p[2]
            assert name in self.labels, '未定义标签: %s' % name
            off = self.labels[name] - idx
            if k == 'b':
                self.w[idx] = b_imm(off)
            elif k == 'c':
                self.w[idx] = b_cond(p[3], off)
            elif k == 'z':
                self.w[idx] = cbz_w(p[3], off)
            else:
                self.w[idx] = cbnz_w(p[3], off)


def build(variant='build', beta=False):
    """生成 stub（0x000-…·前 0x200 零填）与 meta。返回 (bytes, meta)。
       variant='build' 主壳（构建模式·盘回传）／'e4' 变体（测试模式·产物回传）。
       beta=True（S3-C-147·β 段）：路径相对化（配合 adb shell「cd /data/local/tmp」）
       ＋产物写回文件（fout 路径·写后回读 8B 校验·halt 行蕴含写成功）。"""
    assert variant in ('build', 'e4'), variant
    g = Gen()
    SVC = SVC0

    def svc():
        g.w.append(SVC)

    def write_fd1(data_off, length):
        """write(1, X28+off, len)——halt/hdr/rmsg/fmsg 用。"""
        g.emit(movz_w(0, 1), add_x_imm(1, 28, data_off), movz_w(2, length),
               movz_w(8, 64))
        svc()

    def fail_if_ne(reg, val):
        """val(<2^32) 寄存器比较（subs 32 位）·不等 → shell_fail。"""
        g.emit(const_x(9, val), subs_w(31, reg, 9))
        g.bc_to('NE', 'shell_fail')

    def fail_if_neg(reg):
        """有符号 <0 → shell_fail。"""
        g.emit(cmp_w_reg(reg, 31))
        g.bc_to('LT', 'shell_fail')

    # ===== [0] 数据基 X28（占位·finalize 回填 base+HDR+data_off）=====
    base_seq_idx = len(g.w)
    for w in movz4_words(28, 0):
        g.w.append(w)

    # ===== [A] 串口 raw：ioctl(1,TCGETS) → c_oflag&=~OPOST → ioctl(1,TCSETS) =====
    # ioctl(fd=1, req=0x5401, ptr=tbuf)
    g.emit(movz_w(0, 1), const_x(1, 0x5401), add_x_imm(2, 28, D_TBUF),
           movz_w(8, 29))
    svc()
    fail_if_neg(0)
    # tbuf+4 &= 0xFFFFFFFE
    g.emit(ldr_w(9, 28, D_TBUF + 4), and_w_imm(9, 9, 0xFFFFFFFE),
           str_w(9, 28, D_TBUF + 4))
    # ioctl(fd=1, req=0x5402, ptr=tbuf)
    g.emit(movz_w(0, 1), const_x(1, 0x5402), add_x_imm(2, 28, D_TBUF),
           movz_w(8, 29))
    svc()
    fail_if_neg(0)

    # ===== [B] mmap ×5（MAP_FIXED|MAP_ANONYMOUS|MAP_SHARED = 0x31 · PROT RW = 3）=====
    def mmap_fixed(addr, length):
        g.emit(const_x(0, addr), const_x(1, length), movz_w(2, 3),
               movz_w(3, 0x31), movn_x(4, 0), movz_x(5, 0), movz_w(8, 222))
        svc()

    mmap_fixed(0x09000000, 0x1000)          # UART sink（值不持）
    fail_if_ne(0, 0x09000000)
    mmap_fixed(0x40200000, 0x10000)         # ES0
    g.emit(mov_x(21, 0))
    fail_if_ne(21, 0x40200000)
    mmap_fixed(0x42000000, DISK_LEN)        # 内存盘
    g.emit(mov_x(20, 0))
    fail_if_ne(20, 0x42000000)
    mmap_fixed(0x41000000, 0x10000)         # DS
    g.emit(mov_x(19, 0))
    fail_if_ne(19, 0x41000000)
    mmap_fixed(0x400A0000, 0x10000)         # ES2（S3-C-149 S5：辅块段）
    fail_if_ne(0, 0x400A0000)

    # ===== [C] 装盘：openat(AT_FDCWD=-100, "/jie_out.jie", O_RDONLY) → read → close =====
    g.emit(movn_x(0, 99), add_x_imm(1, 28, D_FOUT), movz_x(2, 0), movz_x(3, 0),
           movz_w(8, 56))
    svc()
    g.emit(mov_x(22, 0))
    fail_if_neg(0)
    # read(fd, disk, 0x168000)
    g.emit(mov_x(0, 22), mov_x(1, 20), const_x(2, DISK_LEN), movz_w(8, 63))
    svc()
    fail_if_ne(0, DISK_LEN)
    g.emit(mov_x(0, 22), movz_w(8, 57))
    svc()

    # ===== [D] 装 DS：openat("/jie_build.jie") → lseek/read ×2 → close =====
    g.emit(movn_x(0, 99), add_x_imm(1, 28, D_FIN), movz_x(2, 0), movz_x(3, 0),
           movz_w(8, 56))
    svc()
    g.emit(mov_x(22, 0))
    fail_if_neg(0)
    # lseek(fd, 9216, SEEK_SET)
    g.emit(mov_x(0, 22), const_x(1, DS_LOAD_OFF), movz_x(2, 0), movz_w(8, 62))
    svc()
    fail_if_neg(0)
    # read(fd, X19, 56320)
    g.emit(mov_x(0, 22), mov_x(1, 19), const_x(2, DS_LOAD_LEN), movz_w(8, 63))
    svc()
    fail_if_ne(0, DS_LOAD_LEN)
    # lseek(fd, 114688, SEEK_SET)
    g.emit(mov_x(0, 22), const_x(1, TAB_LOAD_OFF), movz_x(2, 0), movz_w(8, 62))
    svc()
    fail_if_neg(0)
    # read(fd, ES2+0xF100, 3584)（S3-C-149 S5：表区迁 ES2 域）
    g.emit(const_x(1, ES2_BASE), const_x(9, 0xF100), add_x_reg(1, 1, 9),
           const_x(2, TAB_LOAD_LEN), mov_x(0, 22), movz_w(8, 63))
    svc()
    fail_if_ne(0, TAB_LOAD_LEN)
    # 引导扇区预置：[ES0+0x7C00] ← /jie_build.jie[0:512]（承 A 线 F1 loader 配方——
    # 构建收尾「引导扇区重写」从 [0x7C00] 读数据写盘 LBA0）
    g.emit(mov_x(0, 22), movz_x(1, 0), movz_x(2, 0), movz_w(8, 62))
    svc()
    fail_if_neg(0)
    g.emit(mov_x(0, 22), mov_x(1, 21), const_x(9, 0x7C00), add_x_reg(1, 1, 9),
           const_x(2, 512), movz_w(8, 63))
    svc()
    fail_if_ne(0, 512)
    # close(fd)
    g.emit(mov_x(0, 22), movz_w(8, 57))
    svc()

    # ===== [E] 模式标志：[ES2+0xF000] = 14（构建）／0（测试·e4 变体·S3-C-149 S5）=====
    g.emit(const_x(9, ES2_BASE), const_x(10, BUILD_FLAG_OFF), add_x_reg(9, 9, 10),
           movz_w(11, 14 if variant == 'build' else 0), strb_w(11, 9))

    # ===== [F] clone（SIGCHLD=17）→ 父存 pid·落空入 parent_watch =====
    g.emit(movz_w(0, 17), movz_x(1, 0), movz_x(2, 0), movz_x(3, 0), movz_x(4, 0),
           movz_w(8, 220))
    svc()
    fail_if_neg(0)
    g.cbz_to(0, 'child_init')
    g.emit(mov_x(23, 0))                    # 父：子 pid

    # ===== [G] 父监视：wait4 轮询 → 完成/超时 → 回传 → reboot =====
    g.lbl('parent_watch')
    g.emit(movz_w(26, WAIT_LOOPS))
    g.lbl('wloop')
    # nanosleep(500ms)
    g.emit(add_x_imm(0, 28, D_NS1), movz_x(1, 0), movz_w(8, 101))
    svc()
    # wait4(pid, &status, WNOHANG, NULL)
    g.emit(mov_x(0, 23), add_x_imm(1, 28, D_TSBUF), movz_w(2, 1), movz_x(3, 0),
           movz_w(8, 260))
    svc()
    g.emit(subs_w(31, 0, 23))
    g.bc_to('EQ', 'wchild')
    fail_if_neg(0)                          # wait4 出错（<0）
    g.emit(subs_w_imm(26, 26, 1))
    g.cbnz_to(26, 'wloop')
    # 落空 → 超时
    g.lbl('wtimeout')
    g.emit(mov_x(0, 23), movz_w(1, 9), movz_w(8, 129))
    svc()
    g.b_to('wfail')

    g.lbl('wchild')
    g.emit(ldr_w(9, 28, D_TSBUF))
    g.cbz_to(9, 'wdone')                    # exit(0) ⇒ 完成
    g.b_to('wfail')

    g.lbl('wdone')
    write_fd1(D_HALT, 19)                   # halt 行
    if beta:
        # β 段：产物写回文件（fout 路径·O_RDWR|O_CREAT|O_TRUNC=0x242·
        # 写后回读 8B 校验——须 RDWR 否则 read 为 EBADF）
        g.emit(movn_x(0, 99), add_x_imm(1, 28, D_FOUT), const_x(2, 0x242),
               const_x(3, 0o644), movz_w(8, 56))
        svc()
        fail_if_neg(0)
        g.emit(mov_x(22, 0))                # fd
        src_len = DISK_LEN if variant == 'build' else E4_PROD_SIZE
        if variant == 'build':
            g.emit(mov_x(0, 22), mov_x(1, 20), const_x(2, src_len), movz_w(8, 64))
        else:
            g.emit(mov_x(0, 22), mov_x(1, 21), const_x(9, 0xA000),
                   add_x_reg(1, 1, 9), const_x(2, src_len), movz_w(8, 64))
        svc()
        fail_if_ne(0, src_len)
        # 回读校验：lseek(0) + read 8B → 与源前 8B 比对（两半）
        g.emit(mov_x(0, 22), movz_x(1, 0), movz_x(2, 0), movz_w(8, 62))
        svc()
        g.emit(mov_x(0, 22), add_x_imm(1, 28, D_TBUF), const_x(2, 8),
               movz_w(8, 63))
        svc()
        fail_if_ne(0, 8)
        if variant == 'build':
            g.emit(ldr_w(9, 28, D_TBUF), ldr_w(10, 20, 0))
        else:
            g.emit(ldr_w(9, 28, D_TBUF), const_x(11, 0xA000),
                   add_x_reg(11, 21, 11), ldr_w(10, 11, 0))
        g.emit(subs_w(31, 9, 10))
        g.bc_to('NE', 'wfail')
        if variant == 'build':
            g.emit(ldr_w(9, 28, D_TBUF + 4), ldr_w(10, 20, 4))
        else:
            g.emit(ldr_w(9, 28, D_TBUF + 4), ldr_w(10, 11, 4))
        g.emit(subs_w(31, 9, 10))
        g.bc_to('NE', 'wfail')
        g.emit(mov_x(0, 22), movz_w(8, 57))
        svc()
    elif variant == 'build':
        write_fd1(D_HDR, 17)                # 协议头（盘回传）
        # 回传：22 × 64KB + 32768（直接读共享盘区）
        g.emit(mov_x(26, 20), movz_w(27, 22), const_x(29, 0x10000))
        g.lbl('rloop')
        g.emit(movz_w(0, 1), mov_x(1, 26), mov_x(2, 29), movz_w(8, 64))
        svc()
        g.emit(subs_w(31, 0, 29))
        g.bc_to('NE', 'wfail')
        g.emit(add_x_reg(26, 26, 29), subs_w_imm(27, 27, 1))
        g.cbnz_to(27, 'rloop')
        # 尾块 32768
        g.emit(const_x(29, 0x8000), movz_w(0, 1), mov_x(1, 26), mov_x(2, 29),
               movz_w(8, 64))
        svc()
        g.emit(subs_w(31, 0, 29))
        g.bc_to('NE', 'wfail')
    else:
        # e4：产物回传（[ES0+0xA000] 6144 B——测试模式产物 dump）
        write_fd1(D_HDR, 14)                # 协议头（S146PROD:6144）
        g.emit(mov_x(1, 21), const_x(9, 0xA000), add_x_reg(1, 1, 9),
               const_x(2, E4_PROD_SIZE), movz_w(0, 1), movz_w(8, 64))
        svc()
        g.emit(const_x(9, E4_PROD_SIZE), subs_w(31, 0, 9))
        g.bc_to('NE', 'wfail')
    # 排空
    g.emit(add_x_imm(0, 28, D_NS2), movz_x(1, 0), movz_w(8, 101))
    svc()
    g.b_to('wreboot')

    g.lbl('wfail')
    write_fd1(D_RMSG, 23)
    g.emit(mov_x(0, 23), movz_w(1, 9), movz_w(8, 129))
    svc()
    # 落空 → wreboot

    g.lbl('wreboot')
    g.emit(const_x(0, REBOOT_MAGIC1), const_x(1, REBOOT_MAGIC2),
           const_x(2, REBOOT_POWEROFF), movz_x(3, 0), movz_w(8, 142))
    svc()
    # 兜底 exit(0)（Android 环境 reboot 被拒时）
    g.emit(movz_w(0, 0), movz_w(8, 93))
    svc()

    # ===== [I] shell_fail（装载阶段失败·无子）=====
    g.lbl('shell_fail')
    write_fd1(D_FMSG, 14)
    g.b_to('wreboot')

    # ===== [J] 子：patch park → trap · 设寄存器组 · BR jiqiA64 =====
    g.lbl('child_init')
    g.emit(ldr_w(25, 28, D_SLOT), ldr_w(26, 28, D_SLOT + 4))
    # J64 基址占位（装配器回填 = base+HDR+0x1E00）
    place_idx = len(g.w)
    for w in movz4_words(24, PLACE_HOLD):
        g.w.append(w)
    g.emit(add_x_reg(25, 24, 25), str_w(26, 25, 0))    # [J64+park_off] ← b_word
    # 寄存器组（承 build_boothead：设值 + 清零·保留 X24/X28）
    g.emit(mov_x(9, 19), mov_x(18, 24), movz_x(10, 0x4020, hw=1))
    g.emit(const_x(7, 0x4020FC00))
    for r in [0, 1, 2, 3, 4, 5, 6, 8] + list(range(11, 18)) + \
             [19, 20, 21, 22, 23] + [25, 26, 27] + [29, 30]:
        g.emit(movz_x(r, 0))
    g.w.append(br_(24))

    # ===== [M] trap（构建完成 → exit(0)）=====
    g.lbl('trap')
    trap_idx = len(g.w)
    g.emit(movz_w(0, 0), movz_w(8, 93))
    svc()

    # ===== 回填与组装 =====
    g.finalize()
    code = b''.join(w.to_bytes(4, 'little') for w in g.w)
    data_off = SHELL_OFF + len(code)
    # X28 数据基回填（VA = base+HDR+data_off）
    val = BASE_VA + HDR + data_off
    segs = [(val >> (16 * i)) & 0xFFFF for i in range(4)]
    g.w[base_seq_idx + 0] = movz_x(28, segs[0])
    g.w[base_seq_idx + 1] = movk_x(28, segs[1], hw=1)
    g.w[base_seq_idx + 2] = movk_x(28, segs[2], hw=2)
    g.w[base_seq_idx + 3] = movk_x(28, segs[3], hw=3)
    code = b''.join(w.to_bytes(4, 'little') for w in g.w)

    # 数据区
    data = bytearray(D_SIZE)
    data[D_SLOT:D_SLOT + 8] = struct.pack('<II', SLOT_MAGIC, SLOT_MAGIC)
    data[D_NS1:D_NS1 + 16] = struct.pack('<qq', 0, 500000000)
    data[D_NS2:D_NS2 + 16] = struct.pack('<qq', 0, 200000000)
    fin_b = b'jie_build.jie\x00' if beta else b'/jie_build.jie\x00'
    fout_b = b'jie_out.jie\x00' if beta else b'/jie_out.jie\x00'
    assert len(fin_b) <= 16 and len(fout_b) <= 16, '路径超数据区'
    data[D_FIN:D_FIN + len(fin_b)] = fin_b
    data[D_FOUT:D_FOUT + len(fout_b)] = fout_b
    hdr_b = D_HDR_B if variant == 'build' else D_HDR_E4_B
    data[D_HDR:D_HDR + len(hdr_b)] = hdr_b
    data[D_HALT:D_HALT + 19] = D_HALT_B
    data[D_RMSG:D_RMSG + 22] = D_RMSG_B
    data[D_FMSG:D_FMSG + 15] = D_FMSG_B

    stub = bytes(SHELL_OFF) + code + bytes(data)     # 前 0x200 零填（桩区保留）
    assert len(stub) <= J64_OFF, 'stub 超 0x1E00：%d' % len(stub)

    meta = dict(trap_off=SHELL_OFF + trap_idx * 4, data_off=data_off,
                stub_len=len(stub), place_off=SHELL_OFF + place_idx * 4,
                code_len=len(code), variant=variant, beta=beta)
    return stub, meta


def main():
    variant = 'e4' if '--e4' in sys.argv else 'build'
    beta = '--beta' in sys.argv
    args = [a for a in sys.argv[1:] if not a.startswith('--')]
    default = 'androidstub%s%s.bin' % ('_e4' if variant == 'e4' else '',
                                       '_beta' if beta else '')
    out = args[0] if args else os.path.join(HERE, default)
    stub, meta = build(variant=variant, beta=beta)
    open(out, 'wb').write(stub)
    import hashlib
    print('%s（variant=%s）= %d B（0x%X）·md5 %s' %
          (os.path.basename(out), variant, len(stub), len(stub),
           hashlib.md5(stub).hexdigest()))
    print('  trap_off=0x%X · data_off=0x%X · place_off=0x%X · code_len=0x%X' %
          (meta['trap_off'], meta['data_off'], meta['place_off'], meta['code_len']))


if __name__ == '__main__':
    main()
