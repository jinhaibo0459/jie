#!/bin/bash
# =============================================================
# 杰汇编 · M 线（macOS）运行级验证——样本执行与核对
# -------------------------------------------------------------
# 内容：①执行 samples/ 下 M-2 六样本（x86_64），核对输出与退出码
#       ②实验样本（x1/x3/x2·S3-C-140 联调诊断·信息段）
#       ③M-3：jiqi64m 完整构建（BSD syscall 桩壳·产物 md5 判据）
# 用法：bash check.sh（在本目录运行）
# 退出码：全绿 0；任一 FAIL ⇒ 1（并打印现场供诊断）
# 说明：适配 GitHub Actions（macos-15-intel）与真实 Mac 真机。
#       纪律：bash 3.2（macOS 自带）——`$变量` 后接非 ASCII 须用 `${变量}`。
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
echo "== 实验样本（S3-C-140 联调诊断·信息段）=="
run_exp() {   # run_exp <名>
  n="$1"
  if [ ! -f "samples/${n}" ]; then
    echo "  （无 samples/${n}·跳过）"
    return
  fi
  chmod +x "samples/${n}"
  o=$(./samples/"${n}" 2>&1)
  r=$?
  echo "  --- ${n} rc=${r} ---"
  echo "${o}"
  echo "  --- end ${n} ---"
}
run_exp x1
run_exp x3
run_exp x2
run_exp x4

echo
echo "== M-3：jiqi64m 完整构建（BSD syscall 桩壳·运行级）=="
if [ -f m3/jiqi64m ]; then
  chmod +x m3/jiqi64m
  cp m3/jie_build.jie m3/jie_out.jie
  ( cd m3 && ./jiqi64m ) > m3_run.log 2>&1
  mrc=${?}
  echo "  jiqi64m rc=${mrc}"
  tail -4 m3_run.log
  if [ "${mrc}" -eq 0 ]; then
    echo "  [PASS] rc=0（监控正常收割）"
    p=$((p+1))
  else
    echo "  [FAIL] rc=${mrc}"
    f=$((f+1))
  fi
  if grep -q '\[jie-mac\] halt; screen=' m3_run.log; then
    echo "  [PASS] halt 行（构建已发生·防假绿）"
    p=$((p+1))
  else
    echo "  [FAIL] 无 halt 行"
    f=$((f+1))
  fi
  if command -v md5sum >/dev/null 2>&1; then
    got=$(md5sum m3/jie_out.jie | cut -d' ' -f1)
  else
    got=$(md5 -q m3/jie_out.jie)
  fi
  echo "  jie_out.jie md5=${got}"
  if [ "${got}" = "7a0020b1206f4e92312aafcf6b596219" ]; then
    echo "  [PASS] 产物 md5 == 预期（W-3/L-3 同值·三方同构）"
    p=$((p+1))
  else
    echo "  [FAIL] 产物 md5 不符（期望 7a0020b1206f4e92312aafcf6b596219）"
    f=$((f+1))
  fi
else
  echo "  [FAIL] 缺 m3/jiqi64m"
  f=$((f+1))
fi

echo
echo "== 汇总：PASS ${p} / FAIL ${f} =="
[ "$f" -eq 0 ] || exit 1
echo "== 运行级验证：全绿 =="
