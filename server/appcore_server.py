#!/usr/bin/env python3
"""
appcore_server.py - libappcore 远程接收服务器
基于 SimpleUploader HTTP 接口逆向重建

功能:
- 接收设备端 SimpleUploader 的 HTTP POST 上传
- 按 acquisition-id 和 type 分类存储
- 记录设备信息 (X-OS-Version, X-Bundle-ID)
- 提供查询和下载接口
"""

import os
import json
import uuid
import time
import hashlib
import logging
from datetime import datetime
from flask import Flask, request, jsonify, send_from_directory, abort
from werkzeug.utils import secure_filename

# 配置
UPLOAD_DIR = os.environ.get("UPLOAD_DIR", "uploads")
MAX_CONTENT_LENGTH = int(os.environ.get("MAX_CONTENT_LENGTH", 500 * 1024 * 1024))  # 500MB
LOG_FILE = os.environ.get("LOG_FILE", "appcore_server.log")

# 创建上传目录
os.makedirs(UPLOAD_DIR, exist_ok=True)

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("appcore_server")

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH


def get_device_dir(acquisition_id: str, bundle_id: str) -> str:
    """获取设备存储目录"""
    # 使用 acquisition-id 作为主目录
    safe_id = secure_filename(acquisition_id) if acquisition_id else "unknown"
    safe_bundle = secure_filename(bundle_id) if bundle_id else "unknown"
    device_dir = os.path.join(UPLOAD_DIR, safe_id, safe_bundle)
    os.makedirs(device_dir, exist_ok=True)
    return device_dir


def save_metadata(device_dir: str, headers: dict, file_info: dict):
    """保存上传元数据"""
    meta_path = os.path.join(device_dir, "upload_metadata.json")

    # 读取已有元数据
    metadata = []
    if os.path.exists(meta_path):
        try:
            with open(meta_path, 'r') as f:
                metadata = json.load(f)
        except:
            metadata = []

    # 添加新记录
    record = {
        "timestamp": datetime.now().isoformat(),
        "type": file_info.get("type", "unknown"),
        "filename": file_info.get("filename", ""),
        "size": file_info.get("size", 0),
        "sha256": file_info.get("sha256", ""),
        "headers": {
            "X-OS-Version": headers.get("X-OS-Version", ""),
            "X-Bundle-ID": headers.get("X-Bundle-ID", ""),
            "acquisition-id": headers.get("acquisition-id", ""),
            "Content-Type": headers.get("Content-Type", ""),
            "User-Agent": headers.get("User-Agent", ""),
        },
        "remote_ip": request.remote_addr,
    }
    metadata.append(record)

    with open(meta_path, 'w') as f:
        json.dump(metadata, f, indent=2, ensure_ascii=False)

    return record


@app.route("/upload/<upload_type>", methods=["POST"])
def upload_file(upload_type):
    """
    接收文件上传
    对应 SimpleUploader 的 uploadFile:withType: / uploadData:withName:type:

    HTTP 头:
      X-OS-Version: iOS版本
      X-Bundle-ID: 宿主App Bundle ID
      acquisition-id: 采集ID
      Content-Type: application/octet-stream
    """
    # 获取头信息
    os_version = request.headers.get("X-OS-Version", "unknown")
    bundle_id = request.headers.get("X-Bundle-ID", "unknown")
    acquisition_id = request.headers.get("acquisition-id", str(uuid.uuid4()))
    content_type = request.headers.get("Content-Type", "application/octet-stream")

    logger.info(f"上传请求: type={upload_type}, "
                f"os={os_version}, bundle={bundle_id}, "
                f"acquisition={acquisition_id}, ip={request.remote_addr}")

    # 获取上传数据
    data = request.get_data()
    if not data:
        logger.warning("空上传数据")
        return jsonify({"error": "empty data"}), 400

    # 计算文件哈希
    sha256 = hashlib.sha256(data).hexdigest()

    # 生成文件名
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    ext = get_extension_by_type(upload_type)
    filename = f"{upload_type}_{timestamp}_{sha256[:8]}{ext}"

    # 保存文件
    device_dir = get_device_dir(acquisition_id, bundle_id)
    filepath = os.path.join(device_dir, filename)

    with open(filepath, 'wb') as f:
        f.write(data)

    # 保存元数据
    file_info = {
        "type": upload_type,
        "filename": filename,
        "size": len(data),
        "sha256": sha256,
    }
    record = save_metadata(device_dir, request.headers, file_info)

    logger.info(f"文件已保存: {filepath} ({len(data)} bytes, sha256={sha256[:16]}...)")

    return jsonify({
        "status": "ok",
        "filename": filename,
        "size": len(data),
        "sha256": sha256,
        "stored_at": filepath,
    }), 200


def get_extension_by_type(upload_type: str) -> str:
    """根据上传类型获取文件扩展名"""
    extensions = {
        "filesystem": ".tar.gz",
        "keychain": ".xml",
        "metadata": ".json",
        "thumbnail": ".jpg",
        "file": ".bin",
        "plist": ".plist",
        "database": ".db",
    }
    return extensions.get(upload_type, ".bin")


@app.route("/api/devices", methods=["GET"])
def list_devices():
    """列出所有已上传的设备"""
    devices = []
    if not os.path.exists(UPLOAD_DIR):
        return jsonify({"devices": []})

    for acq_id in os.listdir(UPLOAD_DIR):
        acq_path = os.path.join(UPLOAD_DIR, acq_id)
        if not os.path.isdir(acq_path):
            continue
        for bundle_id in os.listdir(acq_path):
            bundle_path = os.path.join(acq_path, bundle_id)
            if not os.path.isdir(bundle_path):
                continue

            # 统计文件
            files = [f for f in os.listdir(bundle_path)
                     if not f.endswith("_metadata.json")]
            total_size = sum(os.path.getsize(os.path.join(bundle_path, f))
                             for f in files)

            # 读取元数据
            meta_path = os.path.join(bundle_path, "upload_metadata.json")
            last_upload = None
            os_version = "unknown"
            if os.path.exists(meta_path):
                try:
                    with open(meta_path, 'r') as f:
                        meta = json.load(f)
                    if meta:
                        last_upload = meta[-1].get("timestamp")
                        os_version = meta[-1].get("headers", {}).get("X-OS-Version", "unknown")
                except:
                    pass

            devices.append({
                "acquisition_id": acq_id,
                "bundle_id": bundle_id,
                "os_version": os_version,
                "file_count": len(files),
                "total_size": total_size,
                "last_upload": last_upload,
            })

    return jsonify({"devices": devices, "count": len(devices)})


@app.route("/api/devices/<acquisition_id>/<bundle_id>/files", methods=["GET"])
def list_device_files(acquisition_id, bundle_id):
    """列出设备的所有上传文件"""
    device_dir = get_device_dir(acquisition_id, bundle_id)
    if not os.path.exists(device_dir):
        return jsonify({"error": "device not found"}), 404

    files = []
    for f in os.listdir(device_dir):
        if f.endswith("_metadata.json"):
            continue
        fpath = os.path.join(device_dir, f)
        if os.path.isfile(fpath):
            stat = os.stat(fpath)
            files.append({
                "filename": f,
                "size": stat.st_size,
                "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            })

    # 读取元数据
    meta_path = os.path.join(device_dir, "upload_metadata.json")
    metadata = []
    if os.path.exists(meta_path):
        with open(meta_path, 'r') as f:
            metadata = json.load(f)

    return jsonify({
        "acquisition_id": acquisition_id,
        "bundle_id": bundle_id,
        "files": files,
        "upload_history": metadata,
    })


@app.route("/api/download/<acquisition_id>/<bundle_id>/<filename>", methods=["GET"])
def download_file(acquisition_id, bundle_id, filename):
    """下载设备上传的文件"""
    device_dir = get_device_dir(acquisition_id, bundle_id)
    safe_name = secure_filename(filename)
    filepath = os.path.join(device_dir, safe_name)

    if not os.path.exists(filepath):
        abort(404)

    return send_from_directory(device_dir, safe_name, as_attachment=True)


@app.route("/api/stats", methods=["GET"])
def get_stats():
    """获取服务器统计信息"""
    total_files = 0
    total_size = 0
    device_count = 0

    if os.path.exists(UPLOAD_DIR):
        for acq_id in os.listdir(UPLOAD_DIR):
            acq_path = os.path.join(UPLOAD_DIR, acq_id)
            if not os.path.isdir(acq_path):
                continue
            for bundle_id in os.listdir(acq_path):
                bundle_path = os.path.join(acq_path, bundle_id)
                if not os.path.isdir(bundle_path):
                    continue
                device_count += 1
                for f in os.listdir(bundle_path):
                    if f.endswith("_metadata.json"):
                        continue
                    fpath = os.path.join(bundle_path, f)
                    if os.path.isfile(fpath):
                        total_files += 1
                        total_size += os.path.getsize(fpath)

    return jsonify({
        "total_devices": device_count,
        "total_files": total_files,
        "total_size": total_size,
        "total_size_human": f"{total_size/1024/1024:.2f} MB",
        "upload_dir": UPLOAD_DIR,
    })


@app.route("/", methods=["GET"])
def index():
    """服务器状态页"""
    return jsonify({
        "name": "libappcore Remote Receiver",
        "version": "1.0.0",
        "status": "running",
        "endpoints": {
            "upload": "POST /upload/<type>",
            "devices": "GET /api/devices",
            "device_files": "GET /api/devices/<acquisition_id>/<bundle_id>/files",
            "download": "GET /api/download/<acquisition_id>/<bundle_id>/<filename>",
            "stats": "GET /api/stats",
        },
        "supported_types": ["filesystem", "keychain", "metadata", "thumbnail", "file"],
    })


@app.errorhandler(413)
def too_large(e):
    return jsonify({"error": "file too large",
                    "max_size": MAX_CONTENT_LENGTH}), 413


@app.errorhandler(500)
def server_error(e):
    logger.error(f"服务器错误: {e}")
    return jsonify({"error": "internal server error"}), 500


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="libappcore 远程接收服务器")
    parser.add_argument("-H", "--host", default="0.0.0.0", help="监听地址 (默认: 0.0.0.0)")
    parser.add_argument("-p", "--port", type=int, default=8080, help="监听端口 (默认: 8080)")
    parser.add_argument("-d", "--debug", action="store_true", help="调试模式")
    parser.add_argument("-o", "--output-dir", default=UPLOAD_DIR, help="上传目录")

    args = parser.parse_args()
    UPLOAD_DIR = args.output_dir
    os.makedirs(UPLOAD_DIR, exist_ok=True)

    logger.info(f"libappcore 远程接收服务器启动")
    logger.info(f"监听: {args.host}:{args.port}")
    logger.info(f"上传目录: {UPLOAD_DIR}")
    logger.info(f"最大文件大小: {MAX_CONTENT_LENGTH/1024/1024:.0f} MB")

    app.run(host=args.host, port=args.port, debug=args.debug)
