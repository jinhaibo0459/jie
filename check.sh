#!/bin/bash
# =============================================================
# 杰汇编 · M 线（macOS）运行级验证——样本执行与核对
# -------------------------------------------------------------
# 内容：执行 samples/ 下 6 个 Mach-O 样本（x86_64），核对输出与
#       退出码。6/6 一致 ⇒ 运行级验证达成。
# 用法：bash check.sh（在本目录运行）
# 退出码：全绿 0；任一 FAIL ⇒ 1（并打印现场供诊断）
# 说明：适配 GitHub Actions（macos-15-intel）与真实 Mac 真机。
# =============================================================
set -u
cd "$(dirname "$0")"

echo "== 杰汇编 M 线运行级验证（环境信息）=="
sw_vers 2>/dev/null || true
echo "架构: $(uname -m)"
echo "bash: $BASH_VERSION"
echo

p=0
f=0

t() {   # t <样本名> <期望输出>
  n="$1"
  w="$2"
  chmod +x "samples/$n.macho" 2>/dev/null
  o=$(./samples/"$n.macho" 2>&1)
  r=$?
  if [ "$r" -eq 0 ] && [ "$o" = "$w" ]; then
    echo "  [PASS] ${n}（rc=0）"
    p=$((p+1))
  else
    echo "  [FAIL] ${n}（rc=${r}）"
    echo "         期望输出: [$w]"
    echo "         实际输出: [$o]"
    file "samples/$n.macho" 2>/dev/null || true
    f=$((f+1))
  fi
}

t s1 "M2-S1-OK"
t s2 "M2-S2-A
M2-S2-B"
t s3 "M2-S3-PAGE-OK"
t e1 "M2-E1-EDGE"
t e2 "M2-E2-EDGE"
t e3 "M2-E3-ENTRY"

echo
echo "== 汇总：PASS ${p} / FAIL ${f}（共 6）=="

# ===== [DIAG] 临时诊断段（S3-C-137·探究 <4096B 被 SIGKILL 的机制）=====
set +e
echo
echo "[DIAG] == 小文件 vs 一页 变体实验 =="
di() {  # di <标签> <可执行路径>
  "$2"
  echo "[DIAG]   ${1}: rc=$?"
}
di "A1 原样(485B)" "./samples/s1.macho"
cp samples/s1.macho /tmp/m2a2 && dd if=/dev/zero bs=1 count=3611 >> /tmp/m2a2 2>/dev/null && chmod +x /tmp/m2a2
di "A2 补零至4096" "/tmp/m2a2"
cp samples/s1.macho /tmp/m2a3 && dd if=/dev/zero bs=1 count=1564 >> /tmp/m2a3 2>/dev/null && chmod +x /tmp/m2a3
di "A3 补零至2049" "/tmp/m2a3"
cp samples/s1.macho /tmp/m2a4 && dd if=/dev/zero bs=1 count=3610 >> /tmp/m2a4 2>/dev/null && chmod +x /tmp/m2a4
di "A4 补零至4095" "/tmp/m2a4"
cp samples/s1.macho /tmp/m2a5 && codesign -s - --force /tmp/m2a5 2>&1 | sed 's/^/[DIAG]   (codesign) /'
chmod +x /tmp/m2a5
echo "[DIAG]   A5 签名后大小: $(stat -f %z /tmp/m2a5 2>/dev/null) B"
di "A5 ad-hoc签名" "/tmp/m2a5"
echo "[DIAG] == codesign -dvvv 对比（s1 vs e1）=="
codesign -dvvv samples/s1.macho 2>&1 | head -3 | sed 's/^/[DIAG]   /'
codesign -dvvv samples/e1.macho 2>&1 | head -3 | sed 's/^/[DIAG]   /'
echo "[DIAG] == 内核日志（近 2 分钟·amfi 相关）=="
log show --last 2m --predicate 'eventMessage CONTAINS "amfi"' --style compact 2>/dev/null | tail -10 | sed 's/^/[DIAG]   /'
set -e

[ "$f" -eq 0 ] || exit 1
echo "== 运行级验证：6/6 全绿 =="
