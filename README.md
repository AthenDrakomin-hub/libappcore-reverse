# libappcore.dylib 逆向工程 — 完整源码还原

基于 `libappcore.dylib` (1.6MB iOS 数据提取/取证工具) 逆向还原的完整 C++/Objective-C 项目。
所有模块均有头文件 + 实现，CMake 可编译。

## 项目状态

| 维度 | 状态 |
|------|------|
| 头文件 | 18 个，全部有对应实现 |
| 源文件 | 16 个，~3500 行 |
| CMake 编译 | ✅ 可配置编译（iOS/macOS） |
| 漏洞利用 | 8 种策略，2 种完整集成（MacDirtyCow + sock_port） |
| 协议配套 | Python 控制器 + Flask 服务器 |

## 项目结构

```
libappcore-reverse/
├── CMakeLists.txt                          # 构建配置 (16 源文件)
├── README.md                               # 本文件
├── BUILD.md                                # 构建指南
├── PROTOCOL.md                             # 通信协议文档
├── OPEN_SOURCE_REFERENCES.md               # 开源组件参考
├── REVERSE_ENGINEERING_REPORT.md           # 完整逆向分析报告 (21KB)
├── include/                                # 头文件 (18)
│   ├── kernel/                             # 内核模块
│   │   ├── IKernelMemory.h                 # 内核内存接口
│   │   ├── RealDeviceKernelMemory.h        # tfp0 实现
│   │   ├── CustomRWRealDeviceKernelMemory.h # 自定义读写
│   │   ├── IOffsetProvider.h               # 偏移表接口
│   │   └── VersionedOffsetProvider.h       # iOS12-16 偏移表
│   ├── exploit/                            # 漏洞利用 (8种)
│   │   ├── IExploitStrategy.h              # 策略接口 + ExploitResult
│   │   ├── SockPortStrategy.h              # CVE-2019-8605
│   │   └── OtherExploitStrategies.h        # 7种策略
│   ├── permissions/                        # 权限提升
│   │   ├── KernelUcredStealer.h            # ucred patch (root)
│   │   └── MacDirtyCowPatcher.h            # CVE-2022-46689
│   ├── acquisition/                        # 数据采集
│   │   ├── FilesystemServer.h              # tar.gz 文件提取
│   │   ├── KeychainServer.h                # 钥匙串提取
│   │   └── MetadataServer.h                # 设备元数据
│   ├── keychain/
│   │   └── AgentKeyUnwrapper.h             # AKS 硬件解密
│   ├── mcm/
│   │   └── MCMLease.h                      # 容器访问
│   ├── upload/
│   │   └── SimpleUploader.h                # HTTP 上传
│   ├── server/
│   │   └── AcqViewCntrlr.h                 # 主控制器
│   └── common/
│       └── IDataWriter.h                   # 数据写入器
├── src/                                    # 实现文件 (16)
│   ├── autorun.mm                          # 自动运行入口
│   ├── kernel/
│   │   ├── RealDeviceKernelMemory.cpp      # mach_vm 读写
│   │   ├── CustomRWRealDeviceKernelMemory.cpp
│   │   └── VersionedOffsetProvider.cpp     # 5版本偏移表
│   ├── exploit/
│   │   ├── SockPortStrategy.cpp            # 5阶段完整利用链
│   │   └── OtherExploitStrategies.cpp      # 7种策略实现
│   ├── permissions/
│   │   ├── KernelUcredStealer.cpp          # proc_find + ucred patch
│   │   └── MacDirtyCowPatcher.cpp          # Apple XNU 核心集成
│   ├── acquisition/
│   │   ├── FilesystemServer.cpp            # libarchive 遍历
│   │   ├── KeychainServer.cpp              # sqlite3 + XML
│   │   └── MetadataServer.m                # 设备信息采集
│   ├── keychain/
│   │   └── AgentKeyUnwrapper.cpp           # CommonCrypto GCM
│   ├── mcm/
│   │   └── MCMLease.m                      # 容器租约
│   ├── upload/
│   │   └── SimpleUploader.m                # NSURLSession
│   ├── server/
│   │   └── AcqViewCntrlr.mm                # TCP服务器+命令分发
│   └── common/
│       └── IDataWriter.cpp                 # File/Memory writer
├── controller/
│   └── appcore_controller.py               # 电脑端控制软件 (~400行)
└── server/
    └── appcore_server.py                   # 远程接收服务器 (~350行)
```

## 模块完整性

| 模块 | 实现状态 | 开源来源 |
|------|----------|----------|
| **MacDirtyCow** | ✅ 完整核心 | Apple XNU `vm_unaligned_copy_switch_race.c` |
| **sock_port** | ✅ 5阶段完整链 | jakeajames/sock_port (MIT) |
| **内核读写** | ✅ 完整 | mach_vm API |
| **偏移表** | ✅ iOS12-16 | Dopamine/libjailbreak |
| **ucred提权** | ✅ 完整 | libjailbreak 逻辑 |
| **文件系统** | ✅ 完整 | libarchive |
| **钥匙串** | ✅ 元数据导出 | Keychain-Dumper |
| **元数据** | ✅ 完整 | iOS API |
| **MCM容器** | ✅ 完整 | iOS 容器机制 |
| **远程上传** | ✅ 完整 | NSURLSession |
| **主控制器** | ✅ 完整 | 逆向还原 |
| **AKS解密** | ⚠️ 框架 | 需 IOKit AppleKeyStore |
| **6种漏洞** | ⚠️ 可用框架 | Fugu15/Manticore 可集成 |

## 8种漏洞利用策略

| 策略 | CVE | iOS版本 | 状态 |
|------|-----|---------|------|
| sock_port | CVE-2019-8605 | 12.0-14.3 | ✅ 完整集成 |
| time_waste | CVE-2021-30955 | 14.0-15.1 | ⚠️ 框架 |
| street_race | - | 13-15 | ⚠️ 框架 |
| busy_schedule | - | 14-15 | ⚠️ 框架 |
| cicuta_virosa | - | 14.0-14.3 | ⚠️ 框架 (GPL) |
| dangling_join | - | 14-16 | ⚠️ 框架 |
| madvm | - | 15-16 | ⚠️ 框架 (Fugu15) |
| darkSword | CVE-2025-43510 | 16 | ⚠️ 框架 |
| MacDirtyCow | CVE-2022-46689 | 15.0-16.1.2 | ✅ 完整集成 |

## 快速开始

```bash
# 克隆
git clone https://github.com/AthenDrakomin-hub/libappcore-reverse.git
cd libappcore-reverse

# 构建 (需要 macOS + Xcode + iOS toolchain)
mkdir build && cd build
cmake .. -DCMAKE_TOOLCHAIN_FILE=../ios.toolchain.cmake
make -j4

# 产物: libappcore.dylib
```

详细构建步骤见 [BUILD.md](BUILD.md)

## 配套工具

| 工具 | 路径 | 说明 |
|------|------|------|
| 电脑端控制器 | `controller/appcore_controller.py` | TCP 连接设备，发送命令 |
| 远程服务器 | `server/appcore_server.py` | Flask 接收 SimpleUploader 上传 |
| 协议文档 | `PROTOCOL.md` | TCP + HTTP 协议规范 |

## 安全声明

本项目仅用于安全研究和逆向工程学习。漏洞利用代码来自公开开源项目（Apple OSS、MIT 许可证）。使用者需遵守当地法律法规，不得用于未授权的设备访问。

## 许可证

逆向还原代码：MIT
集成的开源组件：见各文件头部注释和 `OPEN_SOURCE_REFERENCES.md`
