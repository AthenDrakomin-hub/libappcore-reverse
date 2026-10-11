#!/usr/bin/env python3
"""
auth.py - JWT 认证与权限控制
支持管理员(admin)和代理(agent)两种角色
代理只能访问自己渠道的数据
"""

import os
import time
import json
import hmac
import hashlib
import base64
from functools import wraps
from flask import request, jsonify, g

import database

# JWT 密钥（生产环境应从环境变量读取）
JWT_SECRET = os.environ.get("JWT_SECRET", "appcore_jwt_secret_2026_change_me")
JWT_EXPIRE = int(os.environ.get("JWT_EXPIRE", "86400"))  # 24小时

# 内存 Token 存储（生产可用 Redis）
_tokens = {}


def _b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64decode(data: str) -> bytes:
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data)


def create_token(user_id: int, username: str, role: str, channel_id=None) -> str:
    """创建 JWT Token"""
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "user_id": user_id,
        "username": username,
        "role": role,
        "channel_id": channel_id,
        "iat": int(time.time()),
        "exp": int(time.time()) + JWT_EXPIRE,
    }

    header_b64 = _b64encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = _b64encode(json.dumps(payload, separators=(",", ":")).encode())

    signature = hmac.new(
        JWT_SECRET.encode(),
        f"{header_b64}.{payload_b64}".encode(),
        hashlib.sha256
    ).digest()
    signature_b64 = _b64encode(signature)

    token = f"{header_b64}.{payload_b64}.{signature_b64}"
    _tokens[token] = payload
    return token


def verify_token(token: str) -> dict:
    """验证 JWT Token，返回 payload 或 None"""
    if token in _tokens:
        payload = _tokens[token]
        if payload.get("exp", 0) > time.time():
            return payload
        else:
            del _tokens[token]
            return None

    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None

        header_b64, payload_b64, signature_b64 = parts
        expected_sig = hmac.new(
            JWT_SECRET.encode(),
            f"{header_b64}.{payload_b64}".encode(),
            hashlib.sha256
        ).digest()

        if _b64decode(signature_b64) != expected_sig:
            return None

        payload = json.loads(_b64decode(payload_b64))
        if payload.get("exp", 0) < time.time():
            return None

        _tokens[token] = payload
        return payload
    except Exception:
        return None


def get_current_user():
    """从请求中获取当前用户"""
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
        return verify_token(token)
    return None


def login_required(f):
    """登录验证装饰器"""
    @wraps(f)
    def decorated(*args, **kwargs):
        user = get_current_user()
        if not user:
            return jsonify({"error": "未登录或Token已过期"}), 401
        g.current_user = user
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    """管理员权限装饰器"""
    @wraps(f)
    def decorated(*args, **kwargs):
        user = get_current_user()
        if not user:
            return jsonify({"error": "未登录"}), 401
        if user.get("role") != "admin":
            return jsonify({"error": "需要管理员权限"}), 403
        g.current_user = user
        return f(*args, **kwargs)
    return decorated


def get_accessible_channel_id(user: dict):
    """
    获取用户可访问的渠道ID
    admin 返回 None（表示全部）
    agent 返回自己的 channel_id
    """
    if user.get("role") == "admin":
        return None
    return user.get("channel_id")


def authenticate(username: str, password: str):
    """用户认证，返回 (token, user_info) 或 (None, error_msg)"""
    user = database.get_user_by_username(username)
    if not user:
        return None, "用户不存在"

    if user.get("status") != "active":
        return None, "账号已被禁用"

    if not database.verify_password(password, user["password_hash"]):
        return None, "密码错误"

    # 更新登录时间
    database.update_user_login(user["id"])

    # 记录日志
    database.add_audit_log(user["id"], "login", "", f"用户 {username} 登录",
                           request.remote_addr if request else "")

    # 生成 Token
    token = create_token(user["id"], user["username"], user["role"],
                         user.get("channel_id"))

    user_info = {
        "id": user["id"],
        "username": user["username"],
        "role": user["role"],
        "display_name": user.get("display_name", ""),
        "channel_id": user.get("channel_id"),
    }
    return token, user_info


def logout(token: str):
    """登出（使 Token 失效）"""
    if token in _tokens:
        del _tokens[token]
        return True
    return False
