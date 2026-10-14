#!/bin/bash
# =============================================================
# 杰汇编 · M 线（macOS）运行级验证——样本执行与核对
# -------------------------------------------------------------
# 内容：①执行 samples/ 下 M-2 六样本（x86_64），核对输出与退出码
#       ②实验样本（x1/x3/x2·S3-C-140 联调诊断·信息段）
#       ③M-3：jiqi64m 完整构建（BSD syscall 桩壳·产物 md5 判据）
#       ④M-4：自举闭环 E1-E4（S3-C-142·对照 W-4/L-4）——
#          E1 一代构建（jiqi64m·构建模式）→ jiqi16a ≡ jiqi16
#          E2 自举链（xf64 → macpkg64）→ jiqi64a ≡ jiqi64 基线·jiqi64ma ≡ jiqi64m
#          E3 二代构建（jiqi64ma）→ 产物 == 一代产物（闭环达成）
#          E4 测试模式（macstub_e4 变体）编译 打包器.j → 产物 ≡ fanyi（945 B）
# 用法：bash check.sh（在本目录运行）
# 退出码：全绿 0；任一 FAIL ⇒ 1（并打印现场供诊断）
# 说明：适配 GitHub Actions（macos-15-intel）与真实 Mac 真机。
#       纪律：bash 3.2（macOS 自带）——`$变量` 后接非 ASCII 须用 `${变量}`。
# =============================================================
set -u
cd "$(dirname "$0")"
R="$(pwd)"

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
echo "== 实验样本（S3-C-140 诊断常驻·信息段·含历史对照）=="
run_exp() {   # run_exp <名>（不存在则静默跳过）
  n="$1"
  if [ ! -f "samples/${n}" ]; then
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
run_exp x5
run_exp x5ns

echo
echo "== M-3：jiqi64m 完整构建（BSD syscall 桩壳·运行级）=="
if [ -f m3/jiqi64m ]; then
  chmod +x m3/jiqi64m
  cp m3/jie_build.jie m3/jie_out.jie
  ( cd m3 && ./jiqi64m ) > m3_run.log 2>&1
  mrc=${?}
  echo "  jiqi64m rc=${mrc}"
  echo "  --- m3_run.log ---"
  cat m3_run.log
  echo "  --- end ---"
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
echo "== M-4：自举闭环（E1-E4·对照 W-4/L-4）=="
md5f() {   # md5f <文件> → md5 hex
  if command -v md5sum >/dev/null 2>&1; then md5sum "$1" | cut -d' ' -f1
  else md5 -q "$1"; fi
}

# ---- E1：一代构建（主壳·构建模式）----
cd "$R/m4/e1"
cp jie_build.jie jie_out.jie
chmod +x jiqi64m
./jiqi64m > run.log 2>&1
e1rc=$?
if [ "${e1rc}" -eq 0 ] && grep -q '\[jie-mac\] halt; screen=' run.log; then
  echo "  [PASS] E1 rc=0 + halt 行（一代构建已发生）"
  p=$((p+1))
else
  echo "  [FAIL] E1 rc=${e1rc}（尾 20 行：）"
  tail -20 run.log
  f=$((f+1))
fi
e1md5=$(md5f jie_out.jie 2>/dev/null || echo missing)
echo "  E1 jie_out.jie md5=${e1md5}"
if [ "${e1md5}" = "7a0020b1206f4e92312aafcf6b596219" ]; then
  echo "  [PASS] E1 产物盘 md5 == L-3/W-3 定版（三方同构）"
  p=$((p+1))
else
  echo "  [FAIL] E1 产物盘 md5 不符（期望 7a0020b1206f4e92312aafcf6b596219）"
  f=$((f+1))
fi

# ---- E2：自举链（隔离目录·jiqi16a → xf64 → jiqi64a → macpkg64 → jiqi64ma）----
cd "$R/m4/chain/x86-64"
dd if="$R/m4/e1/jie_out.jie" of=jiqi16.jie bs=1 skip=512 count=5382 2>/dev/null
if cmp -s jiqi16.jie "$R/m4/ref/jiqi16.jie"; then
  echo "  [PASS] E1★ 编译不动点·一级：jiqi16a ≡ jiqi16（5382 B 逐字节）"
  p=$((p+1))
else
  echo "  [FAIL] jiqi16a != jiqi16（提取差异）"
  f=$((f+1))
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "  [FAIL] E2 无 python3（xf64 需宿主 Python）"
  f=$((f+1))
else
  python3 xf64.py > run.log 2>&1
  e2rc=$?
  if [ "${e2rc}" -eq 0 ]; then
    echo "  [PASS] E2 xf64 rc=0"
    p=$((p+1))
  else
    echo "  [FAIL] E2 xf64 rc=${e2rc}（尾 20 行：）"
    tail -20 run.log
    f=$((f+1))
  fi
  j64md5=$(md5f jiqi64.jie 2>/dev/null || echo missing)
  echo "  E2 jiqi64a md5=${j64md5}"
  if [ "${j64md5}" = "4807855a2091cd031fa6478b60c7316f" ]; then
    echo "  [PASS] E2 翻译不动点：jiqi64a ≡ jiqi64（8574 B）"
    p=$((p+1))
  else
    echo "  [FAIL] E2 jiqi64a md5 不符"
    f=$((f+1))
  fi
fi
cd "$R/m4/chain/mac"
python3 macpkg64.py macstub.bin jiqi64ma > run.log 2>&1
e2brc=$?
if [ "${e2brc}" -eq 0 ] && [ -f jiqi64ma ]; then
  e2amd5=$(md5f jiqi64ma)
  echo "  E2 jiqi64ma md5=${e2amd5}"
  if [ "${e2amd5}" = "c6ff46def37faf8eb0f64dd630c4caed" ]; then
    echo "  [PASS] E2★ 装配不动点：jiqi64ma ≡ jiqi64m（16694 B 逐字节全等）"
    p=$((p+1))
  else
    echo "  [FAIL] E2 jiqi64ma md5 不符（期望 c6ff46def37faf8eb0f64dd630c4caed）"
    f=$((f+1))
  fi
else
  echo "  [FAIL] E2 macpkg64 rc=${e2brc}（尾 20 行：）"
  tail -20 run.log
  f=$((f+1))
fi

# ---- E3：二代构建 → 闭环 ----
cd "$R/m4/e3"
cp "$R/m4/chain/mac/jiqi64ma" .
cp jie_build.jie jie_out.jie
chmod +x jiqi64ma
./jiqi64ma > run.log 2>&1
e3rc=$?
if [ "${e3rc}" -eq 0 ] && grep -q '\[jie-mac\] halt; screen=' run.log; then
  echo "  [PASS] E3 rc=0 + halt 行（二代构建已发生）"
  p=$((p+1))
else
  echo "  [FAIL] E3 rc=${e3rc}（尾 20 行：）"
  tail -20 run.log
  f=$((f+1))
fi
if cmp -s jie_out.jie "$R/m4/e1/jie_out.jie"; then
  echo "  [PASS] E3★ 编译不动点·二级：二代产物 ≡ 一代产物（1474560 B 逐字节）——闭环达成"
  p=$((p+1))
else
  echo "  [FAIL] E3 二代产物 != 一代产物"
  f=$((f+1))
fi

# ---- E4：测试程序回归（测试模式壳变体·打包器.j）----
cd "$R/m4/e4"
cp jie_build.jie jie_out.jie
chmod +x jiqi64me4
./jiqi64me4 > run.log 2>&1
e4rc=$?
if [ "${e4rc}" -eq 0 ] && grep -q '\[jie-mac\] halt; screen=' run.log; then
  echo "  [PASS] E4 rc=0 + halt 行（测试模式编译已发生）"
  p=$((p+1))
else
  echo "  [FAIL] E4 rc=${e4rc}（尾 20 行：）"
  tail -20 run.log
  f=$((f+1))
fi
e4sz=$(wc -c < e4_out.bin 2>/dev/null | tr -d ' ')
if [ "${e4sz}" = "2048" ]; then
  echo "  [PASS] E4 产物取回 e4_out.bin = 2048 B"
  p=$((p+1))
else
  echo "  [FAIL] E4 产物取回大小异常（${e4sz}）"
  f=$((f+1))
fi
dd if=e4_out.bin of=e4_head.bin bs=1 count=945 2>/dev/null
if cmp -s e4_head.bin "$R/m4/ref/fanyi_e4.bin"; then
  echo "  [PASS] E4★ 测试程序回归：编译产物 ≡ fanyi（945 B 逐字节全等·416d64c5…）"
  p=$((p+1))
else
  echo "  [FAIL] E4 产物 != fanyi（首 945 B）"
  f=$((f+1))
fi
cd "$R"

echo
echo "== 汇总：PASS ${p} / FAIL ${f} =="
[ "$f" -eq 0 ] || exit 1
echo "== 运行级验证：全绿 =="
