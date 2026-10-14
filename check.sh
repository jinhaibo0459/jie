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
    echo "  [PASS] $n（rc=0）"
    p=$((p+1))
  else
    echo "  [FAIL] $n（rc=$r）"
    echo "         期望输出: [$w]"
    echo "         实际输出: [$o]"
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
echo "== 汇总：PASS $p / FAIL $f（共 6）=="
[ "$f" -eq 0 ] || exit 1
echo "== 运行级验证：6/6 全绿 =="
