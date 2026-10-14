# 杰汇编 · M 线（macOS）运行级验证包

本仓库是「杰汇编」项目 M 线（macOS Mach-O 目标）的**运行级验证**装置：
把 6 个自构造的 x86_64 Mach-O 样本放到真实 macOS 环境中执行，
核对输出与退出码——补齐「结构正确」之外的「能跑」实证。

- 产物来源：杰汇编 M-2 构造器（由 x86-64 机器码直接构造 Mach-O，无导入表）

- 样本：`samples/s1..s3, e1..e3.macho`（各打印自证消息后 exit(0)）

- 核对脚本：`check.sh`（逐个执行 + 输出比对 + 汇总）

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

6/6 PASS ⇒ 运行级验证达成。

## 本地复跑（Mac 真机）

    bash check.sh
