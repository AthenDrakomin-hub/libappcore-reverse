#!/usr/bin/env python3
"""
appcore_controller.py - libappcore 电脑端控制软件
基于 libappcore.dylib 逆向协议重建

功能:
- 连接设备上的 libappcore 本地服务器
- 发送命令 (filesystem/keychain/metadata/status/version)
- 接收并保存提取的数据
- 支持文件系统 tar.gz 提取、钥匙串 XML、元数据 JSON
"""

import socket
import struct
import json
import os
import sys
import time
import argparse
import tarfile
import io
from datetime import datetime
from typing import Optional, Tuple


class AppcoreProtocol:
    """libappcore 本地服务器协议实现"""

    # 命令定义
    CMD_FILESYSTEM = "filesystem"
    CMD_KEYCHAIN = "keychain"
    CMD_METADATA = "metadata"
    CMD_STATUS = "status"
    CMD_VERSION = "version"
    CMD_UPLOAD = "upload"

    def __init__(self, host: str, port: int, timeout: int = 30):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sock: Optional[socket.socket] = None

    def connect(self) -> bool:
        """连接到设备服务器"""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(self.timeout)
            self.sock.connect((self.host, self.port))
            print(f"[+] 已连接到 {self.host}:{self.port}")
            return True
        except Exception as e:
            print(f"[-] 连接失败: {e}")
            return False

    def disconnect(self):
        """断开连接"""
        if self.sock:
            self.sock.close()
            self.sock = None

    def send_command(self, command: str, args: str = "") -> bool:
        """
        发送命令到设备
        协议: command\nargs\n
        """
        if not self.sock:
            print("[-] 未连接")
            return False

        try:
            # 发送命令
            cmd_data = f"{command}\n".encode('utf-8')
            self.sock.sendall(cmd_data)
            print(f"[>] 发送命令: {command}")

            # 发送参数 (如果有)
            if args:
                args_data = f"{args}\n".encode('utf-8')
                self.sock.sendall(args_data)
                print(f"[>] 参数: {args}")
            else:
                # 发送空行表示无参数
                self.sock.sendall(b"\n")

            return True
        except Exception as e:
            print(f"[-] 发送命令失败: {e}")
            return False

    def receive_data(self, output_path: Optional[str] = None,
                     show_progress: bool = True) -> Tuple[bytes, int]:
        """
        接收设备返回的数据
        设备发送完数据后会关闭连接
        """
        if not self.sock:
            return b"", 0

        data = b""
        total = 0
        start_time = time.time()

        try:
            while True:
                try:
                    chunk = self.sock.recv(65536)
                    if not chunk:
                        break
                    data += chunk
                    total += len(chunk)

                    if show_progress and total % (1024 * 1024) < 65536:
                        elapsed = time.time() - start_time
                        speed = total / 1024 / 1024 / elapsed if elapsed > 0 else 0
                        print(f"\r[<] 接收中: {total/1024/1024:.2f} MB "
                              f"({speed:.2f} MB/s)", end="", flush=True)

                except socket.timeout:
                    print(f"\n[-] 接收超时")
                    break

        except Exception as e:
            print(f"\n[-] 接收错误: {e}")

        elapsed = time.time() - start_time
        if show_progress:
            print(f"\n[+] 接收完成: {total} bytes ({total/1024/1024:.2f} MB) "
                  f"用时 {elapsed:.1f}s")

        # 保存到文件
        if output_path and data:
            os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
            with open(output_path, 'wb') as f:
                f.write(data)
            print(f"[+] 已保存到: {output_path}")

        return data, total

    def execute(self, command: str, args: str = "",
                output_path: Optional[str] = None) -> bytes:
        """执行完整的命令流程: 连接 -> 发送命令 -> 接收数据 -> 断开"""
        if not self.connect():
            return b""

        if not self.send_command(command, args):
            self.disconnect()
            return b""

        data, _ = self.receive_data(output_path)
        self.disconnect()
        return data


class AppcoreController:
    """电脑端控制器主类"""

    def __init__(self, host: str, port: int = 1337,
                 output_dir: str = "acquisition_output"):
        self.protocol = AppcoreProtocol(host, port)
        self.output_dir = output_dir
        self.device_info = {}

        # 创建输出目录
        os.makedirs(self.output_dir, exist_ok=True)

    def get_version(self) -> str:
        """获取 Agent 版本"""
        print("\n=== 获取 Agent 版本 ===")
        data = self.protocol.execute(AppcoreProtocol.CMD_VERSION)
        version = data.decode('utf-8', errors='replace').strip()
        print(f"Agent 版本: {version}")
        return version

    def get_status(self) -> dict:
        """获取设备状态"""
        print("\n=== 获取设备状态 ===")
        data = self.protocol.execute(AppcoreProtocol.CMD_STATUS)
        try:
            status = json.loads(data.decode('utf-8'))
            print(json.dumps(status, indent=2, ensure_ascii=False))
            return status
        except:
            text = data.decode('utf-8', errors='replace')
            print(f"状态: {text}")
            return {"raw": text}

    def get_metadata(self) -> dict:
        """获取设备元数据"""
        print("\n=== 获取设备元数据 ===")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output = os.path.join(self.output_dir, f"metadata_{timestamp}.json")
        data = self.protocol.execute(AppcoreProtocol.CMD_METADATA,
                                     output_path=output)
        try:
            metadata = json.loads(data.decode('utf-8'))
            self.device_info = metadata
            return metadata
        except:
            return {"raw": data.decode('utf-8', errors='replace')}

    def get_keychain(self) -> str:
        """提取钥匙串"""
        print("\n=== 提取钥匙串 ===")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output = os.path.join(self.output_dir, f"keychain_{timestamp}.xml")
        data = self.protocol.execute(AppcoreProtocol.CMD_KEYCHAIN,
                                     output_path=output)
        print(f"钥匙串大小: {len(data)} bytes")
        return output

    def get_filesystem(self, path: str = "/",
                       output_name: Optional[str] = None) -> str:
        """
        提取文件系统
        path: 要提取的根路径 (如 "/" 或 "/var/mobile")
        """
        print(f"\n=== 提取文件系统: {path} ===")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        if output_name is None:
            safe_path = path.replace("/", "_").strip("_") or "root"
            output_name = f"filesystem_{safe_path}_{timestamp}.tar.gz"
        output = os.path.join(self.output_dir, output_name)

        data = self.protocol.execute(AppcoreProtocol.CMD_FILESYSTEM,
                                     args=path,
                                     output_path=output)
        print(f"文件系统归档: {len(data)} bytes")

        # 验证 tar.gz
        if data:
            try:
                with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as tar:
                    members = tar.getmembers()
                    print(f"归档包含 {len(members)} 个文件/目录")
                    for m in members[:10]:
                        print(f"  - {m.name} ({m.size} bytes)")
                    if len(members) > 10:
                        print(f"  ... 还有 {len(members)-10} 个")
            except Exception as e:
                print(f"[-] 归档验证失败: {e}")

        return output

    def trigger_upload(self):
        """触发设备远程上传"""
        print("\n=== 触发远程上传 ===")
        data = self.protocol.execute(AppcoreProtocol.CMD_UPLOAD)
        print(f"上传触发响应: {data.decode('utf-8', errors='replace')}")

    def full_acquisition(self, filesystem_path: str = "/"):
        """执行完整采集: 版本 + 状态 + 元数据 + 钥匙串 + 文件系统"""
        print("=" * 50)
        print("  libappcore 完整采集")
        print("=" * 50)

        self.get_version()
        self.get_status()
        self.get_metadata()
        self.get_keychain()
        self.get_filesystem(filesystem_path)

        print("\n" + "=" * 50)
        print(f"  采集完成! 输出目录: {self.output_dir}")
        print("=" * 50)


def main():
    parser = argparse.ArgumentParser(
        description="libappcore 电脑端控制软件",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  %(prog)s -H 192.168.1.100 -p 1337 version
  %(prog)s -H 192.168.1.100 keychain
  %(prog)s -H 192.168.1.100 filesystem -path /var/mobile
  %(prog)s -H 192.168.1.100 metadata
  %(prog)s -H 192.168.1.100 full
        """)

    parser.add_argument("-H", "--host", required=True, help="设备 IP 地址")
    parser.add_argument("-p", "--port", type=int, default=1337,
                        help="设备端口 (默认: 1337)")
    parser.add_argument("-o", "--output", default="acquisition_output",
                        help="输出目录 (默认: acquisition_output)")
    parser.add_argument("-t", "--timeout", type=int, default=60,
                        help="超时时间秒 (默认: 60)")

    subparsers = parser.add_subparsers(dest="command", help="命令")

    subparsers.add_parser("version", help="获取 Agent 版本")
    subparsers.add_parser("status", help="获取设备状态")
    subparsers.add_parser("metadata", help="获取设备元数据")
    subparsers.add_parser("keychain", help="提取钥匙串")

    fs_parser = subparsers.add_parser("filesystem", help="提取文件系统")
    fs_parser.add_argument("-path", default="/",
                           help="提取路径 (默认: /)")

    subparsers.add_parser("full", help="完整采集 (所有数据)")
    subparsers.add_parser("upload", help="触发远程上传")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    controller = AppcoreController(args.host, args.port, args.output)
    controller.protocol.timeout = args.timeout

    try:
        if args.command == "version":
            controller.get_version()
        elif args.command == "status":
            controller.get_status()
        elif args.command == "metadata":
            controller.get_metadata()
        elif args.command == "keychain":
            controller.get_keychain()
        elif args.command == "filesystem":
            controller.get_filesystem(args.path)
        elif args.command == "full":
            controller.full_acquisition()
        elif args.command == "upload":
            controller.trigger_upload()
    except KeyboardInterrupt:
        print("\n[!] 用户中断")
    except Exception as e:
        print(f"[-] 错误: {e}")


if __name__ == "__main__":
    main()
