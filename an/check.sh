#!/usr/bin/env bash
# @JIE:ANCI
# =============================================================
# 杰汇编 · AN 线 CI 判据（S3-C-144 · β 段 · 在 Android 模拟器内运行）
# -------------------------------------------------------------
# 前置：①样本已生成于 _tmp_ci/（md5 冻结值由 workflow 步骤核验）
#       ②adb 已连接 Android 设备/模拟器（android-emulator-runner action 就绪）
# 判据：①环境真实性（设备 ABI=arm64-v8a）
#       ②三样本运行输出文本（S144-A64-OK / OK2 / A64-OK3）
#       ③三样本 rc=0（★Android 语义：shell 无 CAP_SYS_BOOT ⇒ reboot 被拒 ⇒
#         exit(0) 兜底——「同一 ELF 跨环境行为」实证）
# 用法：bash an/check.sh（仓库根 cwd 或 an/ 内均可）
# 退出码：全绿 0；任一 FAIL ⇒ 1（并打印现场供诊断）
# 说明：适配 GitHub Actions（macos-15 arm64·HVF 加速）与真实 Mac + Android 设备。
#       纪律：bash 3.2（macOS 自带）——`$变量` 后接非 ASCII 须用 `${变量}`。
# =============================================================
set -u
cd "$(dirname "$0")/.."

p=0; f=0
say_pass() { echo "  [PASS] $1"; p=$((p+1)); }
say_fail() { echo "  [FAIL] $1"; f=$((f+1)); }

echo "== 设备 =="
adb devices
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
echo "== 汇总：PASS ${p} / FAIL ${f} =="
[ "${f}" -eq 0 ] || exit 1
echo "== AN 线 CI 判据全绿 =="
