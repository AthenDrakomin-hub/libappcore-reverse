#!/usr/bin/env python3
"""
example_server_usage.py - 服务器 API 使用示例
演示如何通过 REST API 与多租户服务器交互
"""
import requests
import json

BASE_URL = "http://localhost:8080"


def example_login():
    """登录获取 JWT token"""
    resp = requests.post(f"{BASE_URL}/api/auth/login", json={
        "username": "admin",
        "password": "admin123"
    })
    data = resp.json()
    print(f"登录: {resp.status_code}")
    print(f"Token: {data.get('token', '')[:50]}...")
    return data.get("token")


def example_get_devices(token):
    """获取设备列表"""
    headers = {"Authorization": f"Bearer {token}"}
    resp = requests.get(f"{BASE_URL}/api/devices", headers=headers)
    devices = resp.json()
    print(f"\n设备列表: {len(devices)} 台")
    for d in devices[:5]:
        print(f"  - {d.get('device_uid', '?')} iOS {d.get('ios_version', '?')}")


def example_get_stats(token):
    """获取统计信息"""
    headers = {"Authorization": f"Bearer {token}"}
    resp = requests.get(f"{BASE_URL}/api/stats", headers=headers)
    stats = resp.json()
    print(f"\n统计: {json.dumps(stats, indent=2)}")


def example_upload_file():
    """模拟设备上传文件"""
    files = {"file": ("metadata.json", b'{"device":"iPhone12,1","ios":"15.4.1"}', "application/json")}
    headers = {
        "X-OS-Version": "15.4.1",
        "X-Bundle-ID": "com.example.app",
        "acquisition-id": "test-uuid-001",
    }
    resp = requests.post(f"{BASE_URL}/upload/metadata", files=files, headers=headers)
    print(f"\n上传: {resp.status_code} {resp.json()}")


def example_crack_queue(token):
    """查看破解队列"""
    headers = {"Authorization": f"Bearer {token}"}
    resp = requests.get(f"{BASE_URL}/api/crack-queue", headers=headers)
    queue = resp.json()
    print(f"\n破解队列: {len(queue)} 项")


if __name__ == "__main__":
    print("=== libappcore 服务器 API 示例 ===\n")

    # 1. 登录
    token = example_login()
    if not token:
        print("登录失败, 请确保服务器已启动")
        exit(1)

    # 2. 获取设备列表
    example_get_devices(token)

    # 3. 获取统计
    example_get_stats(token)

    # 4. 模拟上传
    example_upload_file()

    # 5. 破解队列
    example_crack_queue(token)

    print("\n完成!")
