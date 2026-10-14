# 杰汇编 · M 线（macOS）运行级验证包

本仓库是「杰汇编」项目 M 线（macOS Mach-O 目标）的**运行级验证**装置：
把自构造的 x86_64 Mach-O 样本与工具放到真实 macOS 环境中执行，
核对输出与退出码——补齐「结构正确」之外的「能跑」实证。

- 产物来源：杰汇编 M-2 构造器（由 x86-64 机器码直接构造 Mach-O，无导入表）

- 样本：`samples/s1..s3, e1..e3.macho`（各打印自证消息后 exit(0)）

- **M-3**：`m3/jiqi64m`——BSD syscall 桩壳承载 jiqi64，在 macOS 进程内
  完整构建 `jie_build.jie` → `jie_out.jie`（判据 md5 == W-3/L-3 同值·三方同构）

- **M-4**：`m4/`——自举闭环 E1–E4（S3-C-142·对照 W-4/L-4）：
  - E1 一代构建（`jiqi64m` 构建模式）→ 产物盘 md5 定版 ＋ `jiqi16a ≡ jiqi16`
  - E2 自举链（隔离目录·`xf64` → `macpkg64`）→ `jiqi64a ≡ 基线`；`jiqi64ma ≡ jiqi64m`
  - E3 二代构建（`jiqi64ma`）→ 产物 == 一代产物（1474560 B 逐字节·闭环达成）
  - E4 测试模式（`macstub_e4` 壳变体）编译 `打包器.j` → 产物 ≡ fanyi（945 B·逐字节）

- 核对脚本：`check.sh`（M-2 样本 + M-3 构建 + M-4 闭环 E1–E4 + 汇总）

- CI：`.github/workflows/mac-verify.yml`（macos-15-intel · 标准免费档）

## 期望输出

| 样本 | 输出 | 备注 |
| --- | --- | --- |
| s1 | `M2-S1-OK` | 基本 write+exit |
| s2 | `M2-S2-A`、`M2-S2-B` | 双 write（两处回填） |
| s3 | `M2-S3-PAGE-OK` | 跨页（vmsize 0x2000） |
| e1 | `M2-E1-EDGE` | 文件总长恰一页 |
| e2 | `M2-E2-EDGE` | 超一页一字节 |
| e3 | `M2-E3-ENTRY` | 自定义入口（前导 5×nop） |

6/6 PASS ⇒ M-2 运行级达成；M-3 构建判据全绿；M-4 E1–E4 全绿 ⇒
**M 线（macOS）自举闭环达成**。

## 本地复跑（Mac 真机）

    bash check.sh
