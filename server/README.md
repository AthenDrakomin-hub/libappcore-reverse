# libappcore 远程接收服务器

基于 SimpleUploader HTTP 接口逆向重建的远程数据接收服务器。

## 功能

- 接收设备端 SimpleUploader 的 HTTP POST 上传
- 按 `acquisition-id` 和 `X-Bundle-ID` 分类存储
- 自动记录设备信息 (iOS 版本、Bundle ID、IP)
- 文件 SHA256 校验
- 提供 REST API 查询和下载
- 支持大文件上传 (最大 500MB)

## 安装

```bash
pip install -r requirements.txt
```

## 使用方法

### 启动服务器

```bash
# 默认监听 0.0.0.0:8080
python appcore_server.py

# 指定端口和上传目录
python appcore_server.py -H 0.0.0.0 -p 8080 -o /data/uploads

# 调试模式
python appcore_server.py -d
```

### 环境变量

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `UPLOAD_DIR` | 上传存储目录 | uploads |
| `MAX_CONTENT_LENGTH` | 最大文件大小 (字节) | 524288000 (500MB) |
| `LOG_FILE` | 日志文件 | appcore_server.log |

## API 接口

### 1. 上传文件

```
POST /upload/<type>
```

**请求头:**
```
X-OS-Version: 15.4.1
X-Bundle-ID: org.cocos2d.demo
acquisition-id: <UUID>
Content-Type: application/octet-stream
```

**请求体:** 二进制文件数据

**支持的 type:**
- `filesystem` - 文件系统归档 (tar.gz)
- `keychain` - 钥匙串导出 (XML)
- `metadata` - 设备元数据 (JSON)
- `thumbnail` - 缩略图 (JPG)
- `file` - 通用文件

**响应:**
```json
{
  "status": "ok",
  "filename": "filesystem_20261011_120000_abc12345.tar.gz",
  "size": 1048576,
  "sha256": "abc123...",
  "stored_at": "uploads/<acquisition-id>/<bundle-id>/filesystem_..."
}
```

### 2. 列出所有设备

```
GET /api/devices
```

**响应:**
```json
{
  "devices": [
    {
      "acquisition_id": "uuid-1234",
      "bundle_id": "org.cocos2d.demo",
      "os_version": "15.4.1",
      "file_count": 5,
      "total_size": 10485760,
      "last_upload": "2026-10-11T12:00:00"
    }
  ],
  "count": 1
}
```

### 3. 列出设备文件

```
GET /api/devices/<acquisition_id>/<bundle_id>/files
```

### 4. 下载文件

```
GET /api/download/<acquisition_id>/<bundle_id>/<filename>
```

### 5. 服务器统计

```
GET /api/stats
```

**响应:**
```json
{
  "total_devices": 3,
  "total_files": 15,
  "total_size": 52428800,
  "total_size_human": "50.00 MB",
  "upload_dir": "uploads"
}
```

### 6. 服务器状态

```
GET /
```

## 存储结构

```
uploads/
├── <acquisition-id>/
│   └── <bundle-id>/
│       ├── filesystem_20261011_120000_abc12345.tar.gz
│       ├── keychain_20261011_120001_def67890.xml
│       ├── metadata_20261011_120002_12345678.json
│       └── upload_metadata.json    # 上传历史记录
└── <another-acquisition-id>/
    └── ...
```

## upload_metadata.json 格式

```json
[
  {
    "timestamp": "2026-10-11T12:00:00",
    "type": "filesystem",
    "filename": "filesystem_20261011_120000_abc12345.tar.gz",
    "size": 1048576,
    "sha256": "abc123...",
    "headers": {
      "X-OS-Version": "15.4.1",
      "X-Bundle-ID": "org.cocos2d.demo",
      "acquisition-id": "uuid-1234",
      "Content-Type": "application/octet-stream"
    },
    "remote_ip": "192.168.1.100"
  }
]
```

## 与 SimpleUploader 的对应关系

| SimpleUploader 方法 | 服务器接口 |
|---------------------|-----------|
| `initWithBaseURL:` | 服务器基础 URL |
| `uploadFile:withType:` | `POST /upload/<type>` |
| `uploadThumbBatch:` | 多次 `POST /upload/thumbnail` |
| `uploadData:withName:type:` | `POST /upload/<type>` |
| `X-OS-Version` 头 | 记录到元数据 |
| `X-Bundle-ID` 头 | 用于目录分类 |
| `acquisition-id` 头 | 用于目录分类 |

## 安全建议

1. 生产环境建议使用 HTTPS (反向代理 Nginx/Caddy)
2. 添加认证 (API Key / Token)
3. 限制上传 IP 范围
4. 定期清理旧数据
5. 监控磁盘空间
