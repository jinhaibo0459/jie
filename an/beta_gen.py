# -*- coding: utf-8 -*-
# 跨平台/android/ci/beta_gen.py —— β 段素材生成器（CI 侧 · S3-C-147）
#   输入：jie_build.jie（1474560 · 干净 REF）
#   输出（工作目录·默认 _tmp_ci/）：jie_build.jie（复制·干净）+ jie_out.jie（金丝雀版）
#   判据：md5 冻结值（REF 4d171bb0…；金丝雀＝偏移 [100,6512,9316,114698]=0xA5）
#   用法：python3 an/beta_gen.py [工作目录]
import hashlib
import os
import sys

sys.stdout.reconfigure(encoding='utf-8')
WORK = sys.argv[1] if len(sys.argv) > 1 else '_tmp_ci'
os.makedirs(WORK, exist_ok=True)

HERE = os.path.dirname(os.path.abspath(__file__))
cand = [os.path.join(HERE, '..', 'jie_build.jie'),                    # CI：an/../ = 仓库根
        os.path.join(HERE, '..', '..', '..', 'jie_build.jie')]        # 本地：ci/../../../ = 项目根
src = next((p for p in cand if os.path.exists(p)), None)
assert src, '未找到 jie_build.jie（尝试：%s）' % cand
ref = open(src, 'rb').read()
assert len(ref) == 1474560, len(ref)
assert hashlib.md5(ref).hexdigest() == '4d171bb0747d2dcd61c5e842bc3aaf47', 'REF md5 不符'
disk = bytearray(ref)
for off in (100, 6512, 9316, 114698):
    assert ref[off] != 0xA5, '金丝雀位冲突 @%d' % off
    disk[off] = 0xA5
open(os.path.join(WORK, 'jie_build.jie'), 'wb').write(ref)
open(os.path.join(WORK, 'jie_out.jie'), 'wb').write(bytes(disk))
print('beta_gen: jie_build.jie（%s…）+ jie_out.jie（金丝雀 %s…）→ %s'
      % (hashlib.md5(ref).hexdigest()[:12], hashlib.md5(bytes(disk)).hexdigest()[:12], WORK))
