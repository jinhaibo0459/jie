# -*- coding: utf-8 -*-
# 跨平台/mac/macpkg64.py —— M-3 装配器：macstub.bin + jiqi64.jie → jiqi64m（Mach-O）
#   对照 linuxpkg64.py 同构（ELF 头→Mach-O 头·IAT→syscall 直通·节内相对布局不变）
#   用法：python macpkg64.py <stub.bin> [out]（默认 macstub.bin / jiqi64m）
#   布局（blob 内·与 macstub.s 头部契约双端同步）：
#     桩@0x000 · 壳@0x200（rip 入口）· jiqi64@0x1E00（★VA 差恒 0x1E00 ⇒ 桩自动命中）
#   回填：①2 处 jiqi 基址占位（movabs $0xE1E1F010）②补丁表 12 项（24 dword）
#   包装（M-3 专用·与 M-2 machopkg64 差异三处）：
#     PAGEZERO vmsize 0x10000（缩至一页护 NULL——低地址块需空闲）· TEXT prot RWX（补丁需可写）
#     · blob 含补丁表（运行期写入）+ UNIXTHREAD rip=壳
#   产出：static Mach-O 64（fileoff 0 覆盖全文件·补零 ≥ 0x1000·S3-C-137 内核要求）
import struct, os, sys, re, hashlib
sys.stdout.reconfigure(encoding='utf-8')
D = os.path.dirname(os.path.abspath(__file__))

STUB_P = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else os.path.join(D, 'macstub.bin')
OUT_P = os.path.abspath(sys.argv[2]) if len(sys.argv) > 2 else os.path.join(D, 'jiqi64m')

STUB = open(STUB_P, 'rb').read()
J64 = open(os.path.join(D, '..', 'x86-64', 'jiqi64.jie'), 'rb').read()
print('macstub.bin %d B · jiqi64.jie %d B' % (len(STUB), len(J64)))
assert len(STUB) <= 0x1E00, 'STUB 超 0x1E00！'

BASE = 0x100000000                # macOS x86-64 默认映像基址
HDR = 32 + 72 + 152 + 184         # mach_header_64 + PAGEZERO + TEXT/__text + UNIXTHREAD
CODE_OFF = HDR                    # 0x1B8 —— blob 起点
J64_VA = BASE + CODE_OFF + 0x1E00 # = 0x1000021B8（桩@0x100001B8·VA 差恒 0x1E00）
ENTRY_OFF = CODE_OFF + 0x200      # 壳（blob 偏移 0x200 → rip 0x1000003B8）
PZ_SIZE = 0x10000                 # PAGEZERO 缩至一页（候选 A：低地址块 0x10000000 需空闲）

# ===== 1) 扫描 jiqi64 补丁位点（同 wpe64/linuxpkg64 四组）=====
def find_all(pat):
    return [m.start() for m in re.finditer(re.escape(bytes.fromhex(pat)), J64)]
pA = find_all('bf20900000')   # mov edi,0x9020
pB = find_all('41be00000000') # mov r14d,0
pC = find_all('41be00000100') # mov r14d,0x10000
pD = find_all('bf00800b00')   # mov edi,0xB8000
print('位点：0x9020×%d · r14d,0×%d · r14d,0x10000×%d · 0xB8000×%d' % (len(pA), len(pB), len(pC), len(pD)))
assert (len(pA), len(pB), len(pC), len(pD)) == (5, 2, 2, 3), '位点数不符！'
patch = []
for p in pA: patch.append((p + 1, 0))   # X+0x9020
for p in pB: patch.append((p + 2, 1))   # X
for p in pC: patch.append((p + 2, 2))   # Y
for p in pD: patch.append((p + 1, 3))   # Z
assert len(patch) == 12

# ===== 2) blob 组装（回填前）=====
blob = bytearray(STUB) + b'\x00' * (0x1E00 - len(STUB)) + bytearray(J64)
assert len(blob) == 0x1E00 + len(J64)
print('blob: STUB 0x0-0x%X · pad→0x1E00 · J64 0x1E00-0x%X' % (len(STUB), len(blob)))

# ===== 3) 基址占位回填：10 F0 E1 E1 00 00 00 00 =====
pat = bytes.fromhex('10f0e1e100000000')
n_base = 0
i = 0
while True:
    i = blob.find(pat, i)
    if i < 0: break
    struct.pack_into('<Q', blob, i, J64_VA)
    n_base += 1
    i += 8
print('基址回填: %d 处（值 0x%X）' % (n_base, J64_VA))
assert n_base == 2, '基址占位数不符（期望 2）'

# ===== 4) 补丁表：24 个连续 E2E2E2E2 dword =====
pat = bytes.fromhex('e2e2e2e2')
pos = bytes(blob).find(pat)
assert pos >= 0 and bytes(blob)[pos:pos + 96] == pat * 24, '补丁表区异常'
for i, (off, kind) in enumerate(patch):
    struct.pack_into('<II', blob, pos + i * 8, off, kind)
print('补丁表：12 项写入 @blob 0x%X' % pos)

# ===== 5) 残留断言（占位全消）=====
assert b'\x10\xf0\xe1\xe1' not in bytes(blob), '基址占位残留！'
assert b'\xe2\xe2\xe2\xe2' not in bytes(blob), '补丁表占位残留！'

# ===== 6) Mach-O 包装（M-3 专用·三处适配）=====
total = CODE_OFF + len(blob)
vsize = ((total + 0xFFF) // 0x1000) * 0x1000

h = struct.pack('<IiiIIIII',
                0xFEEDFACF,   # magic（64 位）
                0x01000007,   # cputype = CPU_TYPE_X86_64
                3,            # cpusubtype
                2,            # filetype = MH_EXECUTE
                3,            # ncmds
                72 + 152 + 184,
                0, 0)         # flags / reserved
assert len(h) == 32

pg = struct.pack('<II16sQQQQiiII',
                 0x19, 72, b'__PAGEZERO',
                 0, PZ_SIZE,      # ★缩至 0x10000（M-3：低地址块空闲前提）
                 0, 0,
                 0, 0, 0, 0)

seg = struct.pack('<II16sQQQQiiII',
                  0x19, 152, b'__TEXT',
                  BASE, vsize,
                  0, total,
                  7, 7, 1, 0)      # ★RWX（补丁需可写·无签名进程）
sect = struct.pack('<16s16sQQIIIIIIII',
                   b'__text', b'__TEXT',
                   BASE + CODE_OFF, len(blob),
                   CODE_OFF, 4,
                   0, 0,
                   0x80000400, 0, 0, 0)
txt = seg + sect
assert len(txt) == 152

st = [0] * 21
st[16] = BASE + ENTRY_OFF    # rip = 壳
ut = struct.pack('<IIII', 0x5, 184, 4, 42) + struct.pack('<21Q', *st)
assert len(ut) == 184

out = h + pg + txt + ut + bytes(blob)
if len(out) < 0x1000:
    out = out + b'\x00' * (0x1000 - len(out))
assert len(out) >= total
open(OUT_P, 'wb').write(out)
print()
print('%s 写出：%d B（0x%X）· md5 %s' % (os.path.basename(OUT_P), len(out), len(out), hashlib.md5(out).hexdigest()))
print('  rip 0x%X · J64_VA 0x%X · 桩VA 0x%X（VA 差 0x%X）· PAGEZERO 0x%X' %
      (BASE + ENTRY_OFF, J64_VA, BASE + CODE_OFF, J64_VA - (BASE + CODE_OFF), PZ_SIZE))
