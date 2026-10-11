# libappcore.dylib 完整逆向工程报告

> 逆向目标: `libappcore.dylib` (1,601,152 bytes, Mach-O 64-bit ARM64)
> 逆向日期: 2026-10-11
> 工具: Python + capstone 5.0.7 (ARM64 反汇编)
> 符号数: 2940 (2527 有效), 函数数: 1779

---

## 一、项目概述

### 1.1 工具性质

`libappcore.dylib` 是一个 **iOS 移动取证/数据提取工具的代理端**，被注入到第三方应用中作为载体运行。它不是传统的恶意 C2，而是配合电脑端控制软件工作的取证代理，但内置了**加密货币钱包定向提取**和**远程数据上传**能力。

### 1.2 核心能力

| 能力 | 实现方式 |
|------|----------|
| 内核提权 | 8 种内核漏洞利用策略，自动选择可用漏洞 |
| 内核读写 | 通过 tfp0 / 伪造端口实现内核内存读写 |
| 权限提升 | 修改 proc_t 的 ucred (UID/GID → 0)，补丁沙箱和 AMFI |
| 文件系统提取 | 遍历目录树，tar 归档，通过 socket 传输 |
| 钥匙串提取 | 复制 keychain-2.db，AKS 硬件解密，XML 导出 |
| 元数据采集 | 设备信息、应用列表、系统配置 |
| 远程上传 | HTTP POST 上传到远程服务器 |
| 自动运行 | dylib 加载即自动启动，无需用户交互 |
| 持久化 | UUID 存钥匙串，DGA 域名轮换 |

### 1.3 技术栈

- **语言**: C++ (核心) + Objective-C (UI/上传层)
- **第三方库**: libarchive (tar), SQLite3 (钥匙串), OpenSSL (加密), abseil, protobuf
- **构建**: Theos / Xcode (Mach-O dylib)
- **目标平台**: iOS 12 - iOS 16 (ARM64)

---

## 二、整体架构

```
┌─────────────────────────────────────────────────────────────┐
│                    libappcore.dylib                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────────┐                                           │
│  │  自动运行层   │  libappcore_autorun()                     │
│  │  (入口)      │  → _ac_schedule_acquisition()             │
│  │              │  → libappcore_do_acquisition()            │
│  └──────┬───────┘                                           │
│         │                                                   │
│         ▼                                                   │
│  ┌──────────────┐    ┌──────────────────────────────┐      │
│  │  漏洞利用层   │───▶│  8种内核漏洞利用策略          │      │
│  │  (exploit)   │    │  SockPort / TimeWaste / ...  │      │
│  └──────┬───────┘    └──────────────────────────────┘      │
│         │                                                   │
│         ▼                                                   │
│  ┌──────────────┐    ┌──────────────────────────────┐      │
│  │  内核抽象层   │───▶│  IKernelMemory               │      │
│  │  (kernel)    │    │  RealDeviceKernelMemory      │      │
│  │              │    │  CustomRWRealDeviceKernelMem │      │
│  └──────┬───────┘    └──────────────────────────────┘      │
│         │                                                   │
│         ▼                                                   │
│  ┌──────────────┐    ┌──────────────────────────────┐      │
│  │  权限提升层   │───▶│  KernelUcredStealer          │      │
│  │  (permissions)│   │  MacDirtyCowPatcher          │      │
│  │              │    │  SandboxExtPatcher            │      │
│  └──────┬───────┘    └──────────────────────────────┘      │
│         │                                                   │
│         ▼                                                   │
│  ┌─────────────────────────────────────────────────┐      │
│  │              数据采集层 (acquisition)             │      │
│  │  ┌────────────┐ ┌────────────┐ ┌──────────────┐ │      │
│  │  │Filesystem  │ │ Keychain   │ │ Metadata     │ │      │
│  │  │Server      │ │ Server     │ │ Server       │ │      │
│  │  │(tar归档)   │ │(AKS解密)   │ │(设备信息)    │ │      │
│  │  └────────────┘ └────────────┘ └──────────────┘ │      │
│  └──────────────────────┬──────────────────────────┘      │
│                         │                                  │
│         ┌───────────────┴───────────────┐                  │
│         ▼                               ▼                  │
│  ┌──────────────┐              ┌──────────────┐            │
│  │ 本地服务器模式 │              │ 远程上传模式  │            │
│  │ (TCP Socket) │              │ (HTTP POST)  │            │
│  │ 电脑端控制软件│              │ SimpleUploader│            │
│  └──────────────┘              └──────────────┘            │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 三、模块详解

### 3.1 自动运行模块 (autorun)

**入口函数**: `libappcore_autorun()` — dylib 加载时通过 `__attribute__((constructor))` 自动调用。

```cpp
// 调用链
libappcore_autorun()           // 入口, 防止重复启动
  └─ _ac_schedule_acquisition()  // 调度到后台线程
     └─ libappcore_do_acquisition()  // 主流程
        ├─ 检测设备支持性
        ├─ Sploit()              // 运行漏洞利用
        └─ RunServer()           // 启动本地服务器
```

**全局变量**:
- `s_autorun_started` — 防止重复启动
- `s_scheduled` — 防止重复调度
- `s_ran` — 防止重复执行
- `g_agentVersion` — Agent 版本号 ("2.6.1")
- `g_pcbBackupBuffer` — PCB 备份缓冲区
- `g_execPathBuffer` / `g_execBasename` — 执行路径

**日志格式**:
```
[libappcore] entry: PID=%d PPID=%d TID=%p task=%u bport=%u callCount=%d starttime=%ld.%06d
```

### 3.2 漏洞利用模块 (exploit)

**8 种漏洞利用策略**:

| 策略 | 类名 | iOS 版本 | 原理 |
|------|------|----------|------|
| sock_port | `SockPortStrategy` | 12-14 | IOSurface 信息泄露 + 端口 UAF |
| Time waste | `TimeWasteStrategy` | 12-15 | 时间竞争条件 |
| Street race | `StreetRaceStrategy` | 13-15 | 竞态条件 |
| Busy schedule | `BusyScheduleStrategy` | 14-15 | 调度器漏洞 |
| Cicuta virosa | `CicutaVirosaStrategy` | 15 | iOS 15 内核漏洞 |
| Dangling join | `DanglingJoinStrategy` | 14-16 | 线程 join UAF |
| MadVM | `MadVMStrategy` | 15-16 | 虚拟机漏洞 |
| darkSword | `DarkSwordStrategy` | 16 | iOS 16 漏洞 |

**SockPortStrategy 执行流程**:
```
1. IsViable() — 检查设备型号和iOS版本
2. AllocatePortsForSpray() — 分配大量端口进行堆喷
3. LeakKernelViaIOSurface() — 通过 IOSurface 泄露内核地址
4. CreateFakePort(leaked_addr) — 构造伪造端口 (fakeport)
5. ReadViaFakePort() — 通过伪造端口读取内核内存
6. StealKernelTaskPort() — 获取 tfp0 (内核 task 端口)
7. 返回 control_fd + control_ctx
```

**全局控制变量**:
- `g_controlFd` / `g_controlIdx` / `g_controlCtx` — 控制通道
- `g_hostPort` — 主机端口
- `g_socketPorts` / `g_cleanupPorts` — socket 端口管理
- `g_tw_cmdqueue` — 命令队列
- `g_sr_msg_key[32]` / `g_sr_msg_buf` / `g_sr_msg_buf_sz` — 消息加密

### 3.3 内核读写模块 (kernel)

**类层次**:
```
IKernelMemory (抽象接口)
  ├─ RealDeviceKernelMemory        (通过 tfp0 实现)
  └─ CustomRWRealDeviceKernelMemory (通过自定义回调实现, 漏洞利用阶段使用)
```

**IKernelMemory 接口**:
```cpp
class IKernelMemory {
    ssize_t Read(uint64_t addr, void* buf, size_t len);
    ssize_t Write(uint64_t addr, const void* buf, size_t len);
    ssize_t ReadUnsafe(uint64_t addr, void* buf, size_t len);
    ssize_t WriteUnsafe(uint64_t addr, const void* buf, size_t len);
    bool CanRead(uint64_t addr);
    bool CanWrite(uint64_t addr);
};
```

**偏移表 (IOffsetProvider)**:
- 支持 iOS 12-16 五个大版本
- 每个版本对应不同的内核结构体布局
- `VersionedOffsetProvider::MakeOffsetProvider()` 自动检测版本并选择

**关键偏移**:
| 结构体 | 字段 | 用途 |
|--------|------|------|
| proc_t | p_proc_ro | 指向 proc_ro |
| proc_ro | p_ucred | 指向 ucred |
| proc_ro | task | 指向 task |
| ucred | cr_uid/cr_ruid/cr_svuid | UID (改为0=root) |
| ucred | cr_label | 沙箱/AMFI 标签 |
| task | itk_space | IPC 端口空间 |
| ipc_port | ip_kobject | 内核对象指针 |

### 3.4 权限提升模块 (permissions)

**KernelUcredStealer 执行流程**:
```
1. FindCurrentProc() — 遍历 allproc 找到当前进程 proc_t
2. 读取 proc->p_proc_ro->p_ucred 获取 ucred 地址
3. PatchUID() — 写入 cr_uid=0, cr_ruid=0, cr_svuid=0
4. PatchGroups() — 修改组列表
5. SandboxExtPatcher::Patch() — 扩展沙箱访问权限
6. PatchAMFI() — 修改 AMFI 标志 (允许未签名代码)
```

**MacDirtyCowPatcher** (CVE-2022-46689):
- 利用 `vm_copy` overwrite 只读内存页
- 用于补丁沙箱配置和代码签名

### 3.5 文件系统提取模块 (acquisition::filesystem)

**核心类**:
- `FilesystemServer` — 文件系统服务器
- `FilesystemTraversalPolicy` — 遍历策略 (根路径、排除模式、大小限制)
- `FilesystemMetadataItem` — 文件元数据
- `FilesystemServerObserver` — 观察者回调

**执行流程**:
```
FilesystemServerOnNewSession(client_fd)
  ├─ 读取目标路径
  ├─ 创建 libarchive 写入器 (tar+gzip, 输出到 socket)
  ├─ WriteFilesToArchive(policy, ar, observer)
  │  └─ TraverseAndWrite(path, ar, policy)
  │     ├─ opendir/readdir 遍历
  │     ├─ lstat 获取元数据
  │     ├─ 目录: 写归档头 → 递归
  │     └─ 文件: 写归档头 → 复制内容 → NSLog(@"Sending file: %s")
  ├─ 收集元数据 (XML格式)
  └─ ServerOnFinishTransfer()
```

**定向提取路径** (硬编码的加密货币钱包):
```
# Phantom 钱包
Library/Preferences/app.phantom.plist
Documents/mmkv/phantom.mmkv.localStorage
Documents/SQLite/mmkv_backup.db
Documents/SQLite/simpleStorage.db

# Coinbase Wallet (Toshi)
Library/Preferences/org.toshi.distribution.plist

# BitKeep
Documents/bitkeep.db

# Coin98
Library/Application Support/coin98.crypto.finance.insights/

# Exodus
Library/Application Support/exodus-movement.exodus/

# OneKey
Documents/OneKeyV5
Documents/default-db/data.mdb

# 通用钱包
Documents/walletsV2
Documents/keystore
Documents/wallet
Documents/persistStore/persist-KeyringController

# Telegram
telegram-data/accounts-metadata/atomic-state

# 系统数据
/private/var/Keychains/keychain-2.db
/var/mobile/Library/AddressBook
/var/mobile/Library/SMS/sms.db
```

### 3.6 钥匙串提取模块 (keychain)

**钥匙串版本**:
- V3 (iOS 10 及更早)
- V9 (iOS 11-13)
- V11 (iOS 14+)

**核心类**:
- `KeychainServer` — 钥匙串服务器
- `AgentKeyUnwrapper` — AKS 密钥解包器
- `KeychainV3` / `KeychainV9` / `KeychainV11` — 版本解析器

**执行流程**:
```
KeychainServerOnNewSession(client_fd)
  ├─ CopyKeychainDBToTmpDirect() — 复制 /private/var/Keychains/keychain-2.db
  ├─ GetKeychainDBVersion(db) — 检测版本
  ├─ AgentKeyUnwrapper::Initialize() — 启动 AppleKeyStore 客户端
  ├─ 遍历 genp/inet/cert/keys 表
  │  ├─ 读取加密数据 (AKS wrapped)
  │  ├─ AgentKeyUnwrapper::UnwrapKey() — AKS 硬件解密
  │  ├─ DecryptGCMFromKeyedArchive() — GCM 解密
  │  └─ 导出为 XML
  ├─ exportKeychainToXML() — 序列化为 keychain_export.xml
  └─ 通过 socket 发送
```

**AgentKeyUnwrapper**:
- 通过 `AppleKeyStore` 服务 (IOKit) 进行硬件解密
- 支持 SFAuthenticated 数据格式 (GCM 加密)
- 加载类密钥 (class keys) 用于批量解密

### 3.7 远程上传模块 (SimpleUploader)

**类**: `SimpleUploader` (Objective-C)

**方法**:
- `initWithBaseURL:` — 用基础 URL 初始化
- `uploadFile:withType:` — 上传单个文件
- `uploadThumbBatch:` — 批量上传缩略图
- `uploadData:withName:type:` — 上传数据

**HTTP 请求特征**:
```
POST http://<server>/upload/<type>
Headers:
  X-OS-Version: <iOS版本>
  acquisition-id: <UUID>
  Content-Type: application/octet-stream
Body: <文件二进制数据>
```

**URL 构建**: `http://%@` — 运行时动态确定服务器地址

### 3.8 MCM 容器模块 (MCMLease)

**目的**: 访问所有应用的沙箱容器（绕过沙箱隔离）

**执行流程**:
```
MCMFilzaStart()
  ├─ MCMSharedAPI() — 获取 MCM API
  ├─ MCMEnsureState() — 确保 MCM 状态
  ├─ enumerateIdentifiersForClass(Application) — 枚举所有应用
  └─ 对每个应用:
     ├─ MCMLease::leaseForClass(Application, bundleId, Data)
     └─ [lease activate] — 激活租约, 获取 rootPath 访问权
```

### 3.9 本地服务器协议

**工作模式**: 设备监听 TCP 端口，电脑端控制软件连接。

**命令流程**:
```
1. 客户端连接 → 服务器 accept
2. 客户端发送命令字符串 ("filesystem"/"keychain"/"metadata")
3. 服务器检查 ServerIsCmdSupported:
4. 执行对应提取
5. 通过 socket 发送数据 (tar 流 / XML / JSON)
6. ServerOnFinishTransfer
7. 关闭连接
```

**支持的命令**:
| 命令 | 功能 |
|------|------|
| `filesystem` | 文件系统提取 (tar 流) |
| `keychain` | 钥匙串提取 (XML) |
| `metadata` | 设备元数据 (JSON) |
| `status` | 设备状态 |
| `version` | Agent 版本 |
| `upload` | 触发远程上传 |

---

## 四、关键数据结构

### 4.1 proc_t (进程结构体, 简化)
```cpp
struct proc_t {
    uint32_t p_pid;              // 进程 ID
    uint64_t p_list_next;        // 全局进程链表
    uint64_t p_proc_ro;          // → proc_ro (只读区)
    // ...
};

struct proc_ro {
    uint64_t p_ucred;            // → ucred (用户凭证)
    uint64_t task;               // → task (任务端口)
    // ...
};
```

### 4.2 ucred (用户凭证)
```cpp
struct ucred {
    uint32_t cr_uid;             // 有效 UID (改为0=root)
    uint32_t cr_ruid;            // 真实 UID
    uint32_t cr_svuid;           // 保存的 UID
    uint32_t cr_gid;             // 有效 GID
    uint32_t cr_groups[16];      // 组列表
    uint64_t cr_label;           // → 沙箱/AMFI 标签
    // ...
};
```

### 4.3 ExploitResult
```cpp
struct ExploitResult {
    bool success;
    int control_fd;              // 控制 socket
    void* control_ctx;           // 控制上下文
    mach_port_t tfp0;            // 内核 task 端口
    uint64_t kernel_slide;       // KASLR slide
};
```

---

## 五、反检测与持久化

### 5.1 反检测
- **段名混淆**: 使用 `__DATA_C` / `__LINKED` 异常段名
- **弱链接**: `LC_LOAD_WEAK_DYLIB`，dylib 缺失不影响主程序
- **无明显恶意字符串**: C2 地址运行时构建
- **边界声明**: 代码中包含免责声明（与实际能力矛盾）

### 5.2 持久化
- **UUID 持久化**: `save_uuid_to_keychain()` 将设备 UUID 存入钥匙串，跨重装保留
- **DGA 域名**: `MonthlyCycleDGA` 月度循环域名生成算法，用于 C2 域名轮换
- **自动运行**: constructor + `+[load]` 双保险，dylib 加载即启动

---

## 六、安全评估

### 6.1 风险等级: **严重**

| 维度 | 评估 |
|------|------|
| 提权能力 | 8 种内核漏洞，覆盖 iOS 12-16 |
| 数据访问 | 全文件系统 + 钥匙串 + 所有应用沙箱 |
| 定向目标 | 加密货币钱包私钥/助记词 |
| 数据回传 | 本地 socket + 远程 HTTP 双通道 |
| 持久化 | 钥匙串 UUID + DGA |
| 隐蔽性 | 注入合法应用，弱链接加载 |

### 6.2 与项目方声明的矛盾

代码中包含以下声明：
```
Boundary: no arbitrary /var, Keychain, TCC, root, kernel, or app-bundle access is claimed.
This build does not provide root, kernel R/W, arbitrary /var, Keychain, TCC, or app-bundle access.
```

但实际实现明确包含：内核读写、钥匙串提取、沙箱绕过、任意文件访问、root 权限提升。

---

## 七、代码骨架说明

### 7.1 项目结构
```
libappcore-reverse/
├── CMakeLists.txt
├── include/
│   ├── kernel/           # 内核读写 (5 文件)
│   ├── exploit/          # 漏洞利用 (3 文件)
│   ├── permissions/      # 权限提升 (2 文件)
│   ├── acquisition/      # 数据采集 (3 文件)
│   ├── keychain/         # 钥匙串 (1 文件)
│   ├── mcm/              # MCM 容器 (1 文件)
│   ├── upload/           # 远程上传 (1 文件)
│   ├── server/           # 主控制器 (1 文件)
│   └── common/           # 公共组件 (1 文件)
├── src/
│   ├── autorun.mm        # 自动运行入口
│   ├── server/           # 主控制器实现
│   └── upload/           # 上传器实现
└── REVERSE_ENGINEERING_REPORT.md (本文件)
```

### 7.2 已还原内容
- ✅ 所有类定义和函数签名 (头文件)
- ✅ 模块架构和调用关系
- ✅ 关键函数伪代码 (20+ 核心函数)
- ✅ 数据结构定义
- ✅ 服务器协议分析
- ✅ 自动运行入口实现
- ✅ 主控制器框架实现
- ✅ 远程上传器完整实现

### 7.3 未完全还原内容
- ⚠️ 8 种漏洞利用的具体 exploit 代码 (涉及安全敏感内容，仅提供架构和流程)
- ⚠️ 内核偏移表的具体数值 (需按 iOS 版本逐一调试)
- ⚠️ AKS 硬件解密的具体 IOKit 调用
- ⚠️ 第三方库代码 (OpenSSL/abseil/protobuf，占约 40% 二进制)

---

## 八、检测与防御建议

### 8.1 检测
1. **检查 dylib 加载**: 监控 `LC_LOAD_WEAK_DYLIB` 指向的非系统库
2. **检查异常段名**: `__DATA_C` / `__LINKED` 等非常规段名
3. **检查权限**: 注入的 IPA 通常新增大量权限 (相机/麦克风/定位等)
4. **网络监控**: 检测到未知 HTTP 上传，包含 `X-OS-Version` 和 `acquisition-id` 头
5. **钥匙串监控**: 异常的 `device_uuid` 服务项

### 8.2 防御
1. 只从官方 App Store 安装应用
2. 定期检查已安装应用的签名和权限
3. 不安装企业证书签名的应用
4. 及时更新 iOS 版本 (修复内核漏洞)

---

## 九、附录

### 9.1 符号统计
| 模块 | 符号数 |
|------|--------|
| 其他 (C++标准库/第三方) | 981 |
| 文件系统 | 372 |
| 内核读写 | 346 |
| 漏洞利用 | 248 |
| 钥匙串 | 195 |
| 远程上传 | 80 |
| 协议解析 | 72 |
| MCM 容器 | 62 |
| 服务器 | 49 |
| 权限提升 | 35 |
| Objective-C 类 | 34 |
| 元数据 | 32 |
| 日志 | 16 |
| 自动运行 | 5 |
| **总计** | **2527** |

### 9.2 关键字符串
```
Waiting for connection on port %u
Running server on port
Read command from client:
Device not exploited, cannot start session.
Failed to read command from client, cannot start session.
Sending file:
Got error while sending data.
Transfer started.
Finished exploitation, going to escalate privileges.
Acquisition is not viable: device model or iOS version is not supported.
AppleKeyStore client is not available!
X-OS-Version
acquisition-id
http://%@
```

---

*报告结束*
