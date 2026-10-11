# libappcore.dylib 逆向工程代码骨架

基于 `libappcore.dylib` (1.53MB iOS 数据提取工具) 逆向还原的 C++/Objective-C 代码骨架。

## 项目结构

```
libappcore-reverse/
├── CMakeLists.txt                          # 构建配置
├── README.md                               # 本文件
├── REVERSE_ENGINEERING_REPORT.md           # 完整逆向分析报告
├── include/
│   ├── kernel/                             # 内核读写模块
│   │   ├── IKernelMemory.h                 # 内核内存接口
│   │   ├── RealDeviceKernelMemory.h        # tfp0 实现
│   │   ├── CustomRWRealDeviceKernelMemory.h # 自定义读写实现
│   │   ├── IOffsetProvider.h               # 偏移表接口
│   │   └── VersionedOffsetProvider.h       # 多版本偏移表
│   ├── exploit/                            # 漏洞利用模块
│   │   ├── IExploitStrategy.h              # 策略接口
│   │   ├── SockPortStrategy.h              # sock_port 漏洞
│   │   └── OtherExploitStrategies.h        # 其他7种漏洞
│   ├── permissions/                        # 权限提升模块
│   │   ├── KernelUcredStealer.h            # ucred 窃取
│   │   └── MacDirtyCowPatcher.h            # MacDirtyCow + 沙箱补丁
│   ├── acquisition/                        # 数据采集模块
│   │   ├── FilesystemServer.h              # 文件系统服务器
│   │   ├── KeychainServer.h                # 钥匙串服务器
│   │   └── MetadataServer.h                # 元数据服务器
│   ├── keychain/                           # 钥匙串解析
│   │   └── AgentKeyUnwrapper.h             # AKS 密钥解包
│   ├── mcm/                                # MCM 容器
│   │   └── MCMLease.h                      # 容器租约
│   ├── upload/                             # 远程上传
│   │   └── SimpleUploader.h                # HTTP 上传器
│   ├── server/                             # 主控制器
│   │   └── AcqViewCntrlr.h                 # 采集视图控制器
│   └── common/                             # 公共组件
│       └── IDataWriter.h                   # 数据写入器
└── src/
    ├── autorun.mm                          # 自动运行入口
    ├── server/
    │   └── AcqViewCntrlr.mm                # 主控制器实现
    └── upload/
        └── SimpleUploader.m                # 上传器实现
```

## 已还原模块

| 模块 | 状态 | 说明 |
|------|------|------|
| 自动运行入口 | ✅ 完整 | constructor + load 双保险 |
| 内核读写接口 | ✅ 完整 | IKernelMemory + 2个实现 |
| 偏移表接口 | ✅ 完整 | iOS 12-16 五版本 |
| 漏洞利用架构 | ✅ 框架 | 8种策略接口，sock_port 详细 |
| 权限提升 | ✅ 框架 | ucred patcher + MacDirtyCow |
| 文件系统服务器 | ✅ 框架 | tar 归档 + 遍历 |
| 钥匙串服务器 | ✅ 框架 | AKS 解密 + XML 导出 |
| 元数据服务器 | ✅ 框架 | 设备信息采集 |
| 远程上传 | ✅ 完整 | SimpleUploader 完整实现 |
| MCM 容器 | ✅ 框架 | 容器租约访问 |
| 主控制器 | ✅ 框架 | 服务器主循环 + 命令分发 |

## 构建

```bash
mkdir build && cd build
cmake .. -DCMAKE_TOOLCHAIN_FILE=<iOS toolchain>
make
```

依赖: libarchive, sqlite3, OpenSSL

## 注意事项

1. **漏洞利用代码**: 8 种内核漏洞的具体 exploit 实现仅提供架构和流程，未提供可直接运行的代码（安全敏感）
2. **偏移表**: 具体的内核结构体偏移数值需要按 iOS 版本调试填入
3. **AKS 解密**: AppleKeyStore 的 IOKit 调用需要在实际设备上调试
4. **第三方库**: 二进制中约 40% 是 OpenSSL/abseil/protobuf 等第三方库代码，未还原

## 详细报告

见 [REVERSE_ENGINEERING_REPORT.md](REVERSE_ENGINEERING_REPORT.md)
