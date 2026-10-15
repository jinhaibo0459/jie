#!/usr/bin/env bash
# @JIE:ANCI
# =============================================================
# 杰汇编 · AN 线 CI 判据（S3-C-144 · β 段 · 在 Android 模拟器内运行）
# -------------------------------------------------------------
# 前置：①样本已生成于 _tmp_ci/（md5 冻结值由 workflow 步骤核验）
#       ②adb 已连接 Android 设备/模拟器/Redroid 容器（android-verify.yml 就绪）
# 判据：①环境真实性（设备 ABI=arm64-v8a）
#       ②三样本运行输出文本（S144-A64-OK / OK2 / A64-OK3）
#       ③三样本 rc=0（★Android 语义：shell 无 CAP_SYS_BOOT ⇒ reboot 被拒 ⇒
#         exit(0) 兜底——「同一 ELF 跨环境行为」实证）
# 用法：bash an/check.sh（仓库根 cwd 或 an/ 内均可）
# 退出码：全绿 0；任一 FAIL ⇒ 1（并打印现场供诊断）
# 说明：适配 GitHub Actions（ubuntu-24.04-arm + Redroid 容器）与真实设备 + adb。
#       纪律：bash 3.2（macOS 自带）——`$变量` 后接非 ASCII 须用 `${变量}`。
# =============================================================
set -u
cd "$(dirname "$0")/.."

p=0; f=0
say_pass() { echo "  [PASS] $1"; p=$((p+1)); }
say_fail() { echo "  [FAIL] $1"; f=$((f+1)); }

echo "== 设备 =="
adb devices
# 设备选择（联调 #2 教训：5555＝emulator 标准端口 ⇒ adb 自动识别 emulator-XXXX
# 与 connect 条目双现 ⇒ 裸 adb 命令歧义失败——锁定单设备，通用模拟器/redroid/真机）
if [ -z "${ANDROID_SERIAL:-}" ]; then
  dsr=$(adb devices | tr -d '\r' | awk 'NR>1 && $2=="device" {print $1; exit}')
  if [ -n "${dsr}" ]; then export ANDROID_SERIAL="${dsr}"; fi
fi
if [ -n "${ANDROID_SERIAL:-}" ]; then
  echo "  使用设备：${ANDROID_SERIAL}"
else
  echo "  使用设备：（未指定）"
fi
abi=$(adb shell getprop ro.product.cpu.abi 2>/dev/null | tr -d '\r')
sdk=$(adb shell getprop ro.build.version.sdk 2>/dev/null | tr -d '\r')
rel=$(adb shell getprop ro.build.version.release 2>/dev/null | tr -d '\r')
echo "  ABI=${abi} · SDK=${sdk} · Android ${rel}"
if [ "${abi}" = "arm64-v8a" ]; then
  say_pass "环境真实性：设备 ABI arm64-v8a"
else
  say_fail "环境真实性：设备 ABI 非 arm64-v8a（${abi}）"
fi

echo
echo "== AN 线冒烟：aarch64 静态 ELF · 直接 syscall（三样本）=="
adb shell "mkdir -p /data/local/tmp" >/dev/null 2>&1 || true
for name in s1 s2 s3; do
  case "${name}" in
    s1) want="S144-A64-OK" ;;
    s2) want="S144-A64-OK2" ;;
    s3) want="A64-OK3" ;;
  esac
  if ! adb push "_tmp_ci/${name}.elf" "/data/local/tmp/${name}.elf" >/dev/null 2>&1; then
    say_fail "${name}：adb push"
    continue
  fi
  adb shell "chmod 755 /data/local/tmp/${name}.elf" >/dev/null 2>&1
  out=$(adb shell "/data/local/tmp/${name}.elf; echo __RC=\$?" 2>&1)
  echo "--- ${name} 输出 ---"
  printf '%s\n' "${out}"
  if printf '%s' "${out}" | grep -q "${want}"; then
    say_pass "${name}：判据「${want}」"
  else
    say_fail "${name}：判据「${want}」"
  fi
  if printf '%s' "${out}" | grep -q '__RC=0'; then
    say_pass "${name}：rc=0（reboot 被拒 ⇒ exit 兜底）"
  else
    say_fail "${name}：rc=0"
  fi
done

echo
echo "== β 段：完成定义三项（AN-3 产物 · Android 运行时级 · S3-C-147）=="
# 前置：_tmp_ci/ 已有 β 产物（workflow：androidstub/androidpkg64 --beta ＋ beta_gen.py 素材）
# 判据：①自举不动点（Android 上构建产物盘 == REF·金丝雀打平）
#       ②测试程序回归（测试模式 prod ≡ jiqi16）③「宿主 OS 编译产物在该 OS 运行」（①②本身即是）
for name in jiqiA64an_beta jiqiA64an_e4beta; do
  if adb push "_tmp_ci/${name}.elf" "/data/local/tmp/${name}.elf" >/dev/null 2>&1; then
    adb shell "chmod 755 /data/local/tmp/${name}.elf" >/dev/null 2>&1
    say_pass "push ${name}"
  else
    say_fail "push ${name}"
  fi
done
if adb push _tmp_ci/jie_build.jie /data/local/tmp/jie_build.jie >/dev/null 2>&1; then
  say_pass "push 素材（jie_build）"
else
  say_fail "push 素材（jie_build）"
fi

# β-E1：构建模式 → 产物写回 jie_out.jie（写后回读校验）→ pull → md5==REF
adb push _tmp_ci/jie_out.jie /data/local/tmp/jie_out.jie >/dev/null 2>&1
out=$(adb shell "cd /data/local/tmp && ./jiqiA64an_beta.elf; echo __RC=\$?" 2>&1)
echo "--- β-E1 输出 ---"
printf '%s\n' "${out}"
if printf '%s' "${out}" | grep -q "\[jie-android\] halt"; then
  say_pass "β-E1：halt 行"
else
  say_fail "β-E1：halt 行"
fi
if printf '%s' "${out}" | grep -q '__RC=0'; then
  say_pass "β-E1：rc=0（reboot 被拒 ⇒ exit 兜底）"
else
  say_fail "β-E1：rc=0"
fi
adb pull /data/local/tmp/jie_out.jie _tmp_ci/prod_beta.bin >/dev/null 2>&1 || true
pb=$(md5sum _tmp_ci/prod_beta.bin 2>/dev/null | cut -d' ' -f1)
if [ "${pb}" = "4d171bb0747d2dcd61c5e842bc3aaf47" ]; then
  say_pass "β-E1 ★自举不动点：Android 构建产物盘 == REF（md5 全等）"
else
  say_fail "β-E1 产物盘 md5 ${pb} != REF"
fi

# β-E2：测试模式（e4beta）→ 产物写回 jie_out.jie → pull → 前 5545 == jiqi16
adb push _tmp_ci/jie_out.jie /data/local/tmp/jie_out.jie >/dev/null 2>&1
out=$(adb shell "cd /data/local/tmp && ./jiqiA64an_e4beta.elf; echo __RC=\$?" 2>&1)
echo "--- β-E2 输出 ---"
printf '%s\n' "${out}"
if printf '%s' "${out}" | grep -q "\[jie-android\] halt"; then
  say_pass "β-E2：halt 行"
else
  say_fail "β-E2：halt 行"
fi
if printf '%s' "${out}" | grep -q '__RC=0'; then
  say_pass "β-E2：rc=0"
else
  say_fail "β-E2：rc=0"
fi
adb pull /data/local/tmp/jie_out.jie _tmp_ci/prod_e4b.bin >/dev/null 2>&1 || true
pe=$(head -c 5545 _tmp_ci/prod_e4b.bin 2>/dev/null | md5sum | cut -d' ' -f1)
if [ "${pe}" = "e01cbafb85b2843df1f5917b580e09ec" ]; then
  say_pass "β-E2 ★测试程序回归：prod ≡ jiqi16（5545 B·md5 全等）"
else
  say_fail "β-E2 产物 md5 ${pe} != jiqi16"
fi

echo
echo "== 汇总：PASS ${p} / FAIL ${f} =="
[ "${f}" -eq 0 ] || exit 1
echo "== AN 线 CI 判据全绿 =="
