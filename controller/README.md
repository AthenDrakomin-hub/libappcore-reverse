# libappcore 电脑端控制软件

基于 libappcore.dylib 逆向协议重建的电脑端控制程序。

## 功能

- 连接设备上的 libappcore 本地服务器 (TCP)
- 发送命令: `filesystem` / `keychain` / `metadata` / `status` / `version` / `upload`
- 接收并保存提取的数据
- 文件系统: tar.gz 归档 (可解压)
- 钥匙串: XML 导出
- 元数据: JSON 格式
- 支持进度显示和速度统计

## 使用方法

### 安装

无需额外依赖，使用 Python 标准库。

```bash
python appcore_controller.py --help
```

### 基本用法

```bash
# 获取 Agent 版本
python appcore_controller.py -H 192.168.1.100 version

# 获取设备状态
python appcore_controller.py -H 192.168.1.100 status

# 获取设备元数据
python appcore_controller.py -H 192.168.1.100 metadata

# 提取钥匙串
python appcore_controller.py -H 192.168.1.100 keychain

# 提取文件系统 (指定路径)
python appcore_controller.py -H 192.168.1.100 filesystem -path /var/mobile

# 提取整个文件系统
python appcore_controller.py -H 192.168.1.100 filesystem -path /

# 完整采集 (所有数据)
python appcore_controller.py -H 192.168.1.100 full

# 触发设备远程上传
python appcore_controller.py -H 192.168.1.100 upload
```

### 参数说明

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `-H, --host` | 设备 IP 地址 (必填) | - |
| `-p, --port` | 设备端口 | 1337 |
| `-o, --output` | 输出目录 | acquisition_output |
| `-t, --timeout` | 超时时间 (秒) | 60 |

## 通信协议

```
电脑端 → 设备:  TCP 连接
电脑端 → 设备:  "command\n"
电脑端 → 设备:  "args\n" (可选)
设备 → 电脑端:  二进制数据流 (直到连接关闭)
设备 → 电脑端:  关闭连接
```

详细协议见 `../PROTOCOL.md`

## 输出文件

```
acquisition_output/
├── version_20261011_120000.txt      # Agent 版本
├── status_20261011_120000.json      # 设备状态
├── metadata_20261011_120000.json    # 设备元数据
├── keychain_20261011_120000.xml     # 钥匙串导出
└── filesystem_root_20261011_120000.tar.gz  # 文件系统归档
```

## 作为库使用

```python
from appcore_controller import AppcoreController

controller = AppcoreController("192.168.1.100", port=1337)
controller.get_version()
controller.get_keychain()
controller.get_filesystem("/var/mobile")
```

## 注意事项

1. 设备和电脑需在同一网络 (或通过 USB 端口转发)
2. 设备需已完成漏洞利用 (提权) 才能提取数据
3. 文件系统提取可能较大，建议指定具体路径
4. 大文件提取需要较长超时时间
