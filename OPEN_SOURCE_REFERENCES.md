# 开源组件补全参考

> 基于开源市场调研，可用于补全 libappcore-reverse 项目的开源项目清单

## 一、漏洞利用模块

### 1.1 sock_port (CVE-2019-8605)
| 项目 | 地址 | 说明 | 许可证 |
|------|------|------|--------|
| jakeajames/sock_port | https://github.com/jakeajames/sock_port | 完整 sock_port 实现，含 exploit.c/exploit_utilities.c | MIT |
| SockPuppet3 | Exploit-DB #47409 | iOS 12.0-12.2/12.4，dangling pointer → fake task port | - |
| PsychoTea/machswap2 | https://github.com/PsychoTea/machswap2 | 类似的端口交换漏洞 | - |

**可补全**: `SockPortStrategy::DoExploit()` — 集成 exploit.c 的核心逻辑，适配 IExploitStrategy 接口

### 1.2 MacDirtyCow (CVE-2022-46689)
| 项目 | 地址 | 说明 | 许可证 |
|------|------|------|--------|
| zhuowei/MacDirtyCowDemo | https://github.com/zhuowei/MacDirtyCowDemo | 原始 PoC，vm_copy overwrite 原语 | MIT |
| leminlimez/Cowabunga | https://github.com/leminlimez/Cowabunga | 完整工具箱，iOS 14-16.1.2 | MIT |
| Equati0n/Filza_MacDirtyCow | https://github.com/Equati0n/Filza_MacDirtyCow | 基于 MDC 的文件管理器 | - |

**可补全**: `MacDirtyCowPatcher::OverwriteReadOnlyPage()` — 直接集成 vm_unaligned_copy_switch_race 原语

### 1.3 cicuta_virosa (iOS 14.3)
| 项目 | 地址 | 说明 | 许可证 |
|------|------|------|--------|
| ModernPwner/cicuta_virosa | (原作者仓库) | iOS 14.0-14.3 内核漏洞 | GPL |
| CrackerCat/Manticore | https://github.com/CrackerCat/Manticore | 基于 cicuta_virosa 的越狱 | - |

**可补全**: `CicutaVirosaStrategy` — 集成漏洞利用流程

### 1.4 Fugu15 (iOS 15)
| 项目 | 地址 | 说明 | 许可证 |
|------|------|------|--------|
| pinauten/Fugu15 | https://github.com/pinauten/Fugu15 | Linus Henze 的 iOS 15 越狱，完整开源 | MIT |

**可补全**: `MadVMStrategy` / iOS 15 偏移表 — Fugu15 包含完整的内核利用和偏移

### 1.5 darkSword (iOS 18)
| 项目 | 地址 | 说明 |
|------|------|------|
| 8ksec 分析 | https://www.8ksec.io/darksword-kernel-escalation-cve-2025-43510-43520/ | CVE-2025-43510/43520 技术分析 |

## 二、内核框架模块

### 2.1 内核读写 + 偏移表
| 项目 | 地址 | 说明 | 许可证 |
|------|------|------|--------|
| opa334/Dopamine | https://github.com/opa334/Dopamine | iOS 15-16 越狱，含 libjailbreak | MIT |
| libjailbreak (Dopamine 子模块) | - | 完整的内核原语：proc_find/ucred/ipc_port/vm_map | MIT |
| blacktop/ipsw | https://github.com/blacktop/ipsw | kernelcache 分析、符号提取 | MIT |
| newosxbook Joker | https://newosxbook.com/tools/joker.html | kernelcache 符号化工具 | - |

**可补全**:
- `RealDeviceKernelMemory` — 标准 tfp0 实现（mach_vm_read/write）
- `VersionedOffsetProvider` — 从 Dopamine 的偏移表提取 iOS 15/16 数值
- `KernelUcredStealer` — 基于 libjailbreak 的 proc_find + ucred patch 逻辑

### 2.2 关键偏移参考 (来自 libjailbreak)
```
proc_t:
  p_pid        = 0x68   (iOS 15/16)
  p_list_next  = 0x08
  p_proc_ro    = 0x20

proc_ro_t:
  p_ucred      = 0x10
  task         = 0x18

ucred_t:
  cr_uid       = 0x18
  cr_ruid      = 0x1c
  cr_svuid     = 0x20
  cr_gid       = 0x24
  cr_groups    = 0x28
  cr_label     = 0x78
```
*注：具体偏移需按 iOS 版本和设备型号验证*

## 三、数据采集模块

### 3.1 钥匙串提取
| 项目 | 地址 | 说明 | 许可证 |
|------|------|------|--------|
| ptoomey3/Keychain-Dumper | https://github.com/ptoomey3/Keychain-Dumper | 经典钥匙串导出，wildcard entitlement | GPL |
| iChainbreaker | - | keychain-2.db 解密脚本（需密码） | - |
| test1ng-guy/iOS-sandbox-explorer | https://github.com/test1ng-guy/iOS-sandbox-explorer | 注入 dylib 获取沙箱 shell | - |

**可补全**: `KeychainServer` — 集成 keychain_dumper 的数据库查询和 entitlement 逻辑

### 3.2 文件系统/取证
| 项目 | 地址 | 说明 | 许可证 |
|------|------|------|--------|
| iLEAPP | https://leapps.org/ | iOS 全文件系统取证解析 | 开源 |
| libarchive | https://github.com/libarchive/libarchive | tar/zip 归档库 | BSD |

**可补全**: `FilesystemServer::TraverseAndWrite()` — 标准目录遍历 + libarchive 写入

### 3.3 MCM 容器
| 项目 | 地址 | 说明 | 许可证 |
|------|------|------|--------|
| NyaMisty/KernBypass-Public | https://github.com/NyaMisty/KernBypass-Public | 内核级容器绕过 | - |
| khanhduytran0/LiveContainer | https://github.com/khanhduytran0/LiveContainer | 容器管理 | - |

## 四、补全优先级建议

| 优先级 | 模块 | 补全难度 | 开源参考 | 预期效果 |
|--------|------|----------|----------|----------|
| P0 | RealDeviceKernelMemory | 低 | 标准 mach_vm API | 内核读写可用 |
| P0 | KernelUcredStealer | 中 | libjailbreak | 提权逻辑完整 |
| P0 | FilesystemServer | 低 | libarchive 标准用法 | 文件提取可用 |
| P1 | VersionedOffsetProvider | 中 | Dopamine 偏移表 | 支持 iOS 15/16 |
| P1 | MacDirtyCowPatcher | 中 | MacDirtyCowDemo | 只读内存补丁 |
| P2 | KeychainServer | 高 | Keychain-Dumper | 钥匙串提取 |
| P2 | SockPortStrategy | 高 | sock_port | iOS 12-14 漏洞利用 |
| P3 | 其他6种漏洞 | 高 | 各越狱项目 | 全版本覆盖 |
| P3 | AgentKeyUnwrapper | 极高 | 无完整开源 | AKS 硬件解密 |

## 五、许可证注意事项

- **MIT** (sock_port, MacDirtyCowDemo, Cowabunga, Dopamine, Fugu15, ipsw) — 可自由集成，需保留版权声明
- **GPL** (cicuta_virosa, Keychain-Dumper) — 集成后整个项目需 GPL 开源，注意传染性
- 集成前请仔细核对每个项目的具体许可证条款
