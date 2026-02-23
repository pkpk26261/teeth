# -*- coding: utf-8 -*-
"""
Idensol Chroma — 會員登入後台
啟動方式：python server.py
預設位址：http://localhost:5000
"""

import os
import json
import hashlib
import secrets
import random
import string
import base64
from datetime import datetime, timedelta
from functools import wraps

import pymysql
from flask import (
    Flask, request, jsonify, send_from_directory,
    session, redirect, url_for
)

app = Flask(__name__, static_folder='.', static_url_path='')

# ---------- 持久化 secret key（避免重啟後 session 全部失效）----------
_SECRET_KEY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.flask_secret_key')
def _load_or_create_secret_key():
    """從檔案載入 secret key；若檔案不存在則自動建立。
    這樣伺服器重啟後 session 仍然有效，admin 不會被維護模式擋住。"""
    if os.path.exists(_SECRET_KEY_FILE):
        with open(_SECRET_KEY_FILE, 'r') as f:
            key = f.read().strip()
            if key:
                return key
    key = secrets.token_hex(32)
    with open(_SECRET_KEY_FILE, 'w') as f:
        f.write(key)
    return key

app.secret_key = _load_or_create_secret_key()
app.permanent_session_lifetime = timedelta(days=7)
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100 MB

# ---------- MySQL 設定 ----------
DB_CONFIG = {
    'host': 'ls-27a90146fb5a0f44e33335ee47f091c3f0022092.cvaaw6mi0nhc.ap-northeast-1.rds.amazonaws.com',
    'port': 3306,
    'user': 'dbmasteruser',
    'password': r'o7YhR_}r,64Nhev4k*Q%OC^F>Xu228kV',
    'database': 'Database',
    'charset': 'utf8mb4',
    'cursorclass': pymysql.cursors.DictCursor,
    'max_allowed_packet': 128 * 1024 * 1024,  # 128 MB
    'init_command': "SET time_zone = '+08:00'",
}


def _get_db():
    """取得 MySQL 連線"""
    return pymysql.connect(**DB_CONFIG)


def _init_db():
    """初始化資料表（首次啟動時）"""
    # 先建立資料庫（若不存在）
    cfg_no_db = {k: v for k, v in DB_CONFIG.items() if k != 'database'}
    tmp = pymysql.connect(**cfg_no_db)
    try:
        with tmp.cursor() as cur:
            cur.execute("CREATE DATABASE IF NOT EXISTS `%s` DEFAULT CHARACTER SET utf8mb4" % DB_CONFIG['database'])
        tmp.commit()
    finally:
        tmp.close()

    conn = _get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id            INT AUTO_INCREMENT PRIMARY KEY,
                    username      VARCHAR(100) NOT NULL UNIQUE,
                    password_hash VARCHAR(64) NOT NULL,
                    salt          VARCHAR(32) NOT NULL,
                    display_name  VARCHAR(100) DEFAULT '',
                    email         VARCHAR(200) DEFAULT '',
                    phone         VARCHAR(30) DEFAULT '',
                    role          VARCHAR(30) DEFAULT '',
                    clinic_name   VARCHAR(200) DEFAULT '',
                    license_number VARCHAR(100) DEFAULT '',
                    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """)
            # 動態新增舊表缺少的欄位
            for col, typedef in [
                ('email',          "VARCHAR(200) DEFAULT ''"),
                ('phone',          "VARCHAR(30) DEFAULT ''"),
                ('role',           "VARCHAR(30) DEFAULT ''"),
                ('clinic_name',    "VARCHAR(200) DEFAULT ''"),
                ('license_number', "VARCHAR(100) DEFAULT ''"),
                ('avatar',         "LONGTEXT DEFAULT NULL"),
                ('is_admin',       "TINYINT(1) DEFAULT 0"),
            ]:
                try:
                    cur.execute(f"ALTER TABLE users ADD COLUMN {col} {typedef}")
                except Exception:
                    pass  # 欄位已存在則忽略
            # 確保 admin 帳號有管理員權限
            try:
                cur.execute("UPDATE users SET is_admin = 1 WHERE username = 'admin'")
            except Exception:
                pass
            cur.execute("""
                CREATE TABLE IF NOT EXISTS projects (
                    id            BIGINT PRIMARY KEY,
                    owner_username VARCHAR(100) NOT NULL,
                    name          VARCHAR(255) NOT NULL DEFAULT '',
                    status        VARCHAR(20) DEFAULT 'active',
                    dentist       VARCHAR(255) DEFAULT NULL,
                    description   TEXT DEFAULT NULL,
                    shared_with   JSON DEFAULT NULL,
                    thumbnail     LONGTEXT DEFAULT NULL,
                    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
                    modified_at   DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    deleted_at    DATETIME DEFAULT NULL,
                    INDEX idx_owner (owner_username),
                    INDEX idx_deleted (deleted_at)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS project_images (
                    id          BIGINT PRIMARY KEY,
                    project_id  BIGINT NOT NULL,
                    filename    VARCHAR(255) DEFAULT '',
                    thumbnail   LONGTEXT DEFAULT NULL,
                    uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_project (project_id)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS cd_markers (
                    project_id  BIGINT PRIMARY KEY,
                    data        JSON DEFAULT NULL
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS cs_sessions (
                    project_id  BIGINT PRIMARY KEY,
                    data        JSON DEFAULT NULL
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """)
            # ── 系統設定表 ──
            cur.execute("""
                CREATE TABLE IF NOT EXISTS system_settings (
                    setting_key   VARCHAR(100) PRIMARY KEY,
                    setting_value TEXT DEFAULT '',
                    category      VARCHAR(50) DEFAULT 'general',
                    label         VARCHAR(200) DEFAULT '',
                    field_type    VARCHAR(20) DEFAULT 'text',
                    sort_order    INT DEFAULT 0,
                    updated_at    DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """)
            # ── 色卡品牌表 ──
            cur.execute("""
                CREATE TABLE IF NOT EXISTS shade_brands (
                    id         INT AUTO_INCREMENT PRIMARY KEY,
                    brand_key  VARCHAR(100) NOT NULL UNIQUE,
                    brand_name VARCHAR(200) NOT NULL,
                    sort_order INT DEFAULT 0,
                    is_active  TINYINT(1) DEFAULT 1,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """)
            # ── 色卡群組表 ──
            cur.execute("""
                CREATE TABLE IF NOT EXISTS shade_groups (
                    id         INT AUTO_INCREMENT PRIMARY KEY,
                    brand_id   INT NOT NULL,
                    title      VARCHAR(200) NOT NULL,
                    sort_order INT DEFAULT 0,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_brand (brand_id),
                    FOREIGN KEY (brand_id) REFERENCES shade_brands(id) ON DELETE CASCADE
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """)
            # ── 色卡色階表 ──
            cur.execute("""
                CREATE TABLE IF NOT EXISTS shades (
                    id         INT AUTO_INCREMENT PRIMARY KEY,
                    group_id   INT NOT NULL,
                    code       VARCHAR(50) NOT NULL,
                    name       VARCHAR(200) DEFAULT '',
                    hex_color  VARCHAR(7) DEFAULT '#FFFFFF',
                    lab_l      DECIMAL(6,2) DEFAULT 0,
                    lab_a      DECIMAL(6,2) DEFAULT 0,
                    lab_b      DECIMAL(6,2) DEFAULT 0,
                    sort_order INT DEFAULT 0,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_group (group_id),
                    FOREIGN KEY (group_id) REFERENCES shade_groups(id) ON DELETE CASCADE
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """)
            # ── AI色階指南 色階系統表 ──
            cur.execute("""
                CREATE TABLE IF NOT EXISTS shade_systems (
                    id          INT AUTO_INCREMENT PRIMARY KEY,
                    system_key  VARCHAR(100) NOT NULL UNIQUE,
                    system_name VARCHAR(200) NOT NULL,
                    sort_order  INT DEFAULT 0,
                    is_active   TINYINT(1) DEFAULT 1,
                    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """)
            # ── AI色階指南 色階代碼表 ──
            cur.execute("""
                CREATE TABLE IF NOT EXISTS shade_system_codes (
                    id          INT AUTO_INCREMENT PRIMARY KEY,
                    system_id   INT NOT NULL,
                    code        VARCHAR(50) NOT NULL,
                    sort_order  INT DEFAULT 0,
                    INDEX idx_system (system_id),
                    FOREIGN KEY (system_id) REFERENCES shade_systems(id) ON DELETE CASCADE
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """)
            # ── 登入紀錄表 ──
            cur.execute("""
                CREATE TABLE IF NOT EXISTS login_history (
                    id         INT AUTO_INCREMENT PRIMARY KEY,
                    user_id    INT NOT NULL,
                    username   VARCHAR(100) NOT NULL,
                    display_name VARCHAR(100) DEFAULT '',
                    ip_address VARCHAR(45) DEFAULT '',
                    user_agent TEXT DEFAULT NULL,
                    login_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_user (user_id),
                    INDEX idx_login_at (login_at)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """)
            # ── 密碼重設 token 表 ──
            cur.execute("""
                CREATE TABLE IF NOT EXISTS password_reset_tokens (
                    id         INT AUTO_INCREMENT PRIMARY KEY,
                    user_id    INT NOT NULL,
                    token      VARCHAR(128) NOT NULL UNIQUE,
                    expires_at DATETIME NOT NULL,
                    used       TINYINT(1) DEFAULT 0,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_token (token),
                    INDEX idx_user (user_id)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """)
            # ── 插入預設系統設定 ──
            _default_settings = [
                ('site_name', 'Idensol Chroma', 'general', '網站名稱', 'text', 1),
                ('site_description', '牙科數位比色系統', 'general', '網站描述', 'text', 2),
                ('allow_registration', '1', 'general', '開放註冊', 'toggle', 3),
                ('max_upload_size_mb', '100', 'general', '最大上傳檔案大小 (MB)', 'number', 4),
                ('session_timeout_days', '7', 'security', '登入有效天數', 'number', 5),
                ('max_projects_per_user', '0', 'limits', '每人最大專案數 (0=不限)', 'number', 6),
                ('max_images_per_project', '0', 'limits', '每專案最大圖片數 (0=不限)', 'number', 7),
                ('maintenance_mode', '0', 'general', '維護模式', 'toggle', 8),
                ('smtp_host', 'smtp.gmail.com', 'email', 'SMTP 伺服器', 'text', 10),
                ('smtp_port', '587', 'email', 'SMTP 連接埠', 'number', 11),
                ('smtp_user', 'idensol2014@gmail.com', 'email', 'SMTP 帳號', 'text', 12),
                ('smtp_password', 'nbgg fkit fakp qvhr', 'email', 'SMTP 密碼', 'password', 13),
                ('smtp_sender_name', 'Idensol Chroma', 'email', '寄件者名稱', 'text', 14),
                ('smtp_use_tls', '1', 'email', '使用 TLS', 'toggle', 15),
                ('password_reset_expiry_minutes', '30', 'email', '重設連結有效分鐘數', 'number', 16),
            ]
            for s in _default_settings:
                cur.execute("""
                    INSERT IGNORE INTO system_settings (setting_key, setting_value, category, label, field_type, sort_order)
                    VALUES (%s, %s, %s, %s, %s, %s)
                """, s)
            # 移除舊的色彩設定（已改由程式碼管理）
            cur.execute("DELETE FROM system_settings WHERE category = 'color'")
            # 遷移：若 SMTP 設定為空，自動填入預設值
            _smtp_defaults = {
                'smtp_host': 'smtp.gmail.com',
                'smtp_user': 'idensol2014@gmail.com',
                'smtp_password': 'nbgg fkit fakp qvhr',
            }
            for _k, _v in _smtp_defaults.items():
                cur.execute(
                    "UPDATE system_settings SET setting_value = %s WHERE setting_key = %s AND (setting_value = '' OR setting_value IS NULL)",
                    (_v, _k)
                )
        conn.commit()
        print('[INFO] 資料庫初始化完成')
    finally:
        conn.close()


_settings_cache = {}
_settings_cache_ts = 0
_SETTINGS_CACHE_TTL = 5  # 秒


def _get_setting(key, default=None):
    """從資料庫讀取單一系統設定值（帶 5 秒快取）"""
    global _settings_cache, _settings_cache_ts
    import time
    now = time.time()
    if now - _settings_cache_ts > _SETTINGS_CACHE_TTL:
        conn = _get_db()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT setting_key, setting_value FROM system_settings")
                rows = cur.fetchall()
                _settings_cache = {r['setting_key']: r['setting_value'] for r in rows}
                _settings_cache_ts = now
        finally:
            conn.close()
    return _settings_cache.get(key, default)


def _hash_password(password, salt=None):
    """密碼雜湊 (SHA-256 + salt)"""
    if salt is None:
        salt = secrets.token_hex(16)
    hashed = hashlib.sha256((salt + password).encode()).hexdigest()
    return salt, hashed


def _init_default_admin():
    """初始化預設管理員帳號（首次啟動時）"""
    conn = _get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM users WHERE username = %s", ('admin',))
            if not cur.fetchone():
                salt, hashed = _hash_password('idensol2014')
                cur.execute(
                    "INSERT INTO users (username, password_hash, salt, display_name) VALUES (%s, %s, %s, %s)",
                    ('admin', hashed, salt, '管理員')
                )
                conn.commit()
                print('[INFO] 已建立預設管理員帳號')
    finally:
        conn.close()


# ---------- 驗證裝飾器 ----------

# 維護模式繞過 token（admin 登入時設定到 cookie，即使 session 失效也能辨識）
_MAINTENANCE_BYPASS_TOKEN = hashlib.sha256(app.secret_key.encode()).hexdigest()[:32]

@app.before_request
def check_maintenance_mode():
    """維護模式檢查 —— 擁有者帳號 / bypass token 可通行"""
    path = request.path
    # 允許的白名單：靜態資源、登入/登出、公開設定、驗證碼
    whitelist = ('/api/auth/login', '/api/auth/logout', '/api/auth/me', '/api/auth/register',
                 '/api/public/settings', '/api/auth/captcha',
                 '/api/auth/forgot-password', '/api/auth/reset-password', '/api/auth/verify-reset-token',
                 '/css/', '/js/', '/uploads/', '/login', '/forgot-password', '/reset-password')
    if any(path.startswith(w) for w in whitelist):
        return None
    # 靜態檔案 & HTML 頁面一律放行（真正的權限控管在 API 層）
    if path.endswith(('.html', '.css', '.js', '.png', '.jpg', '.ico', '.svg', '.woff2', '.woff', '.ttf')):
        return None
    # 根路徑 (/) 也放行，讓頁面載入
    if path == '/' or path == '':
        return None
    try:
        if _get_setting('maintenance_mode', '0') == '1':
            # 方法 1：session 中是管理員（擁有者或管理員帳號）
            if session.get('is_admin'):
                return None
            # 方法 2：帶有維護繞過 cookie（session 失效時的備用方案）
            if request.cookies.get('maintenance_bypass') == _MAINTENANCE_BYPASS_TOKEN:
                return None
            return jsonify({'ok': False, 'msg': '系統維護中，請稍後再試'}), 503
    except Exception:
        pass
    return None


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user' not in session:
            return jsonify({'ok': False, 'msg': '請先登入'}), 401
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user' not in session:
            return jsonify({'ok': False, 'msg': '請先登入'}), 401
        if not session.get('is_admin'):
            return jsonify({'ok': False, 'msg': '需要管理員權限'}), 403
        return f(*args, **kwargs)
    return decorated


# ---------- 認證 API ----------

@app.route('/api/auth/status')
def auth_status():
    """檢查目前登入狀態"""
    if 'user' in session:
        # 取得使用者頭像與管理員狀態
        avatar_url = None
        is_admin = False
        try:
            conn = _get_db()
            with conn.cursor() as cur:
                cur.execute("SELECT avatar, is_admin FROM users WHERE username = %s", (session['user'],))
                row = cur.fetchone()
                if row:
                    if row.get('avatar'):
                        avatar_url = row['avatar']
                    is_admin = bool(row.get('is_admin', 0))
            conn.close()
        except Exception:
            pass

        # 如果前端已有快取且大小一致，不回傳完整頭像資料
        avatar_size = len(avatar_url) if avatar_url else 0
        cached_size = request.args.get('avatar_cache_size', type=int)
        if cached_size and avatar_url and cached_size == avatar_size:
            avatar_url = '__cached__'
        session['is_admin'] = is_admin
        return jsonify({
            'logged_in': True,
            'username': session['user'],
            'display_name': session.get('display_name', session['user']),
            'avatar': avatar_url,
            'avatar_size': avatar_size,
            'is_admin': is_admin,
        })
    return jsonify({'logged_in': False})


# ---------- 驗證碼 (CAPTCHA) ----------

def _generate_captcha_svg(text):
    """產生帶有干擾線的 SVG 驗證碼圖片"""
    width, height = 160, 50
    lines = ''
    # 隨機干擾線
    for _ in range(5):
        x1, y1 = random.randint(0, width), random.randint(0, height)
        x2, y2 = random.randint(0, width), random.randint(0, height)
        r, g, b = random.randint(120, 200), random.randint(120, 200), random.randint(120, 200)
        lines += f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="rgb({r},{g},{b})" stroke-width="1.5"/>'

    chars = ''
    for i, ch in enumerate(text):
        x = 20 + i * 30
        y = random.randint(28, 38)
        rotate = random.randint(-20, 20)
        r, g, b = random.randint(30, 100), random.randint(30, 100), random.randint(30, 100)
        chars += (
            f'<text x="{x}" y="{y}" font-size="{random.randint(22, 30)}" '
            f'font-family="Arial,sans-serif" font-weight="bold" fill="rgb({r},{g},{b})" '
            f'transform="rotate({rotate},{x},{y})">{ch}</text>'
        )

    # 隨機圓點
    dots = ''
    for _ in range(20):
        cx, cy = random.randint(0, width), random.randint(0, height)
        r_c = random.randint(1, 3)
        r, g, b = random.randint(150, 220), random.randint(150, 220), random.randint(150, 220)
        dots += f'<circle cx="{cx}" cy="{cy}" r="{r_c}" fill="rgb({r},{g},{b})" opacity="0.5"/>'

    svg = (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}">'
        f'<rect width="100%" height="100%" fill="#f5f5f5"/>'
        f'{lines}{dots}{chars}</svg>'
    )
    return svg


@app.route('/api/auth/captcha')
def get_captcha():
    """取得驗證碼圖片"""
    # 產生隨機 4 位英數字驗證碼（排除易混淆字元）
    allowed = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
    code = ''.join(random.choices(allowed, k=4))
    session['captcha'] = code.upper()
    session['captcha_time'] = datetime.utcnow().isoformat()

    svg = _generate_captcha_svg(code)
    b64 = base64.b64encode(svg.encode('utf-8')).decode('utf-8')

    return jsonify({
        'ok': True,
        'image': f'data:image/svg+xml;base64,{b64}',
    })


@app.route('/api/auth/login', methods=['POST'])
def login():
    """會員登入"""
    data = request.get_json(silent=True) or {}
    username = data.get('username', '').strip()
    password = data.get('password', '')

    if not username or not password:
        return jsonify({'ok': False, 'msg': '請輸入帳號和密碼'}), 400

    conn = _get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM users WHERE username = %s", (username,))
            user = cur.fetchone()
    finally:
        conn.close()

    if not user:
        return jsonify({'ok': False, 'msg': '帳號或密碼錯誤'}), 401

    # 維護模式：僅允許管理員帳號登入
    if _get_setting('maintenance_mode', '0') == '1' and not user.get('is_admin'):
        return jsonify({'ok': False, 'msg': '系統維護中，目前僅開放管理員帳號登入'}), 503

    _, hashed = _hash_password(password, user['salt'])
    if hashed != user['password_hash']:
        return jsonify({'ok': False, 'msg': '帳號或密碼錯誤'}), 401

    session.permanent = True
    # 動態讀取 session 有效天數
    try:
        timeout_days = int(_get_setting('session_timeout_days', '7'))
    except (TypeError, ValueError):
        timeout_days = 7
    app.permanent_session_lifetime = timedelta(days=timeout_days)
    session['user'] = username
    session['display_name'] = user.get('display_name', username)
    session['is_admin'] = bool(user.get('is_admin', 0))

    # 記錄登入紀錄
    try:
        ip = request.headers.get('X-Forwarded-For', request.remote_addr) or ''
        if ',' in ip:
            ip = ip.split(',')[0].strip()
        ua = request.headers.get('User-Agent', '')[:500]
        conn2 = _get_db()
        try:
            with conn2.cursor() as cur2:
                cur2.execute(
                    "INSERT INTO login_history (user_id, username, display_name, ip_address, user_agent) VALUES (%s,%s,%s,%s,%s)",
                    (user['id'], username, user.get('display_name', username), ip, ua)
                )
            conn2.commit()
        finally:
            conn2.close()
    except Exception:
        pass  # 登入紀錄寫入失敗不影響登入

    resp = jsonify({
        'ok': True,
        'username': username,
        'display_name': user.get('display_name', username),
        'is_admin': bool(user.get('is_admin', 0)),
    })
    # admin 登入時設定維護繞過 cookie，即使 session 失效也能通過維護模式
    if username == 'admin':
        resp.set_cookie('maintenance_bypass', _MAINTENANCE_BYPASS_TOKEN,
                        max_age=60*60*24*30, httponly=True, samesite='Lax')
    return resp


@app.route('/api/auth/register', methods=['POST'])
def register():
    """會員註冊"""
    # 維護模式禁止註冊
    if _get_setting('maintenance_mode', '0') == '1':
        return jsonify({'ok': False, 'msg': '系統維護中，暫停註冊新帳號'}), 503
    # 檢查是否開放註冊
    if _get_setting('allow_registration', '1') != '1':
        return jsonify({'ok': False, 'msg': '目前系統未開放註冊'}), 403
    data = request.get_json(silent=True) or {}
    username = data.get('username', '').strip()
    password = data.get('password', '')
    display_name = data.get('display_name', '').strip() or username
    email = data.get('email', '').strip()
    phone = data.get('phone', '').strip()
    role = data.get('role', '').strip()
    clinic_name = data.get('clinic_name', '').strip()
    license_number = data.get('license_number', '').strip()
    captcha_input = data.get('captcha', '').strip().upper()

    # --- 驗證碼檢查 ---
    captcha_answer = session.get('captcha', '')
    captcha_time = session.get('captcha_time', '')
    # 清除已使用的驗證碼
    session.pop('captcha', None)
    session.pop('captcha_time', None)

    if not captcha_input or captcha_input != captcha_answer:
        return jsonify({'ok': False, 'msg': '驗證碼錯誤，請重新輸入'}), 400

    # 檢查驗證碼是否超時（5 分鐘）
    if captcha_time:
        try:
            ct = datetime.fromisoformat(captcha_time)
            if (datetime.utcnow() - ct).total_seconds() > 300:
                return jsonify({'ok': False, 'msg': '驗證碼已過期，請重新取得'}), 400
        except Exception:
            pass

    # --- 基本欄位驗證 ---
    if not username or not password:
        return jsonify({'ok': False, 'msg': '請輸入帳號和密碼'}), 400

    if len(username) < 3:
        return jsonify({'ok': False, 'msg': '帳號至少需要 3 個字元'}), 400

    if len(password) < 8:
        return jsonify({'ok': False, 'msg': '密碼至少需要 8 個字元'}), 400

    import re
    if not re.search(r'[a-zA-Z]', password):
        return jsonify({'ok': False, 'msg': '密碼必須包含至少一個英文字母'}), 400
    if not re.search(r'[0-9]', password):
        return jsonify({'ok': False, 'msg': '密碼必須包含至少一個數字'}), 400

    if not email:
        return jsonify({'ok': False, 'msg': '請輸入電子郵件'}), 400

    if not role:
        return jsonify({'ok': False, 'msg': '請選擇您的職業身份'}), 400

    conn = _get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM users WHERE username = %s", (username,))
            if cur.fetchone():
                return jsonify({'ok': False, 'msg': '此帳號已被使用'}), 409

            if email:
                cur.execute("SELECT id FROM users WHERE email = %s AND email != ''", (email,))
                if cur.fetchone():
                    return jsonify({'ok': False, 'msg': '此電子郵件已被使用'}), 409

            salt, hashed = _hash_password(password)
            cur.execute(
                """INSERT INTO users
                   (username, password_hash, salt, display_name, email, phone, role, clinic_name, license_number)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                (username, hashed, salt, display_name, email, phone, role, clinic_name, license_number)
            )
        conn.commit()
    finally:
        conn.close()

    # 註冊後自動登入
    session.permanent = True
    session['user'] = username
    session['display_name'] = display_name

    return jsonify({
        'ok': True,
        'username': username,
        'display_name': display_name,
    })


@app.route('/api/auth/logout', methods=['POST'])
def logout():
    """會員登出"""
    session.clear()
    return jsonify({'ok': True})


# ---------- 帳號管理 API ----------

@app.route('/api/auth/profile')
@login_required
def get_profile():
    """取得目前登入使用者的完整資料"""
    conn = _get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT username, display_name, email, phone, role, clinic_name, license_number, avatar, created_at FROM users WHERE username = %s", (session['user'],))
            user = cur.fetchone()
    finally:
        conn.close()

    if not user:
        return jsonify({'ok': False, 'msg': '使用者不存在'}), 404

    avatar_data = user.get('avatar', None)
    avatar_size = len(avatar_data) if avatar_data else 0

    # 如果前端已有快取且大小一致，不回傳完整頭像
    cached_size = request.args.get('avatar_cache_size', type=int)
    if cached_size and avatar_data and cached_size == avatar_size:
        avatar_data = '__cached__'

    return jsonify({
        'ok': True,
        'profile': {
            'username': user['username'],
            'display_name': user['display_name'] or '',
            'email': user.get('email', ''),
            'phone': user.get('phone', ''),
            'role': user.get('role', ''),
            'clinic_name': user.get('clinic_name', ''),
            'license_number': user.get('license_number', ''),
            'avatar': avatar_data,
            'avatar_size': avatar_size,
            'created_at': user['created_at'].isoformat() if user['created_at'] else None,
        }
    })


@app.route('/api/auth/profile', methods=['PUT'])
@login_required
def update_profile():
    """更新使用者個人資料"""
    data = request.get_json(silent=True) or {}
    display_name = data.get('display_name', '').strip()
    email = data.get('email', '').strip()
    phone = data.get('phone', '').strip()
    role = data.get('role', '').strip()
    clinic_name = data.get('clinic_name', '').strip()
    license_number = data.get('license_number', '').strip()

    if not display_name:
        return jsonify({'ok': False, 'msg': '姓名不可為空'}), 400
    if not email:
        return jsonify({'ok': False, 'msg': '電子郵件不可為空'}), 400

    conn = _get_db()
    try:
        with conn.cursor() as cur:
            # 檢查 email 是否被其他人使用
            cur.execute("SELECT id FROM users WHERE email = %s AND email != '' AND username != %s", (email, session['user']))
            if cur.fetchone():
                return jsonify({'ok': False, 'msg': '此電子郵件已被其他帳號使用'}), 409

            cur.execute("""
                UPDATE users SET display_name=%s, email=%s, phone=%s, role=%s, clinic_name=%s, license_number=%s
                WHERE username=%s
            """, (display_name, email, phone, role, clinic_name, license_number, session['user']))
        conn.commit()
    finally:
        conn.close()

    session['display_name'] = display_name

    return jsonify({'ok': True, 'msg': '資料更新成功'})


@app.route('/api/users/<username>/avatar')
@login_required
def get_user_avatar(username):
    """取得指定使用者的頭像（回傳圖片）"""
    import base64 as _b64
    conn = _get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT avatar FROM users WHERE username = %s", (username,))
            row = cur.fetchone()
    finally:
        conn.close()
    if not row or not row.get('avatar'):
        # 回傳 404
        return '', 404
    data_uri = row['avatar']
    # 解析 data:image/png;base64,xxxxx
    if data_uri.startswith('data:'):
        header, encoded = data_uri.split(',', 1)
        mime = header.split(':')[1].split(';')[0]
        img_bytes = _b64.b64decode(encoded)
        resp = app.response_class(img_bytes, mimetype=mime)
        resp.headers['Cache-Control'] = 'public, max-age=300'
        return resp
    # 若不是 data URI 格式，嘗試當純 base64
    try:
        img_bytes = _b64.b64decode(data_uri)
        resp = app.response_class(img_bytes, mimetype='image/png')
        resp.headers['Cache-Control'] = 'public, max-age=300'
        return resp
    except Exception:
        return '', 404


@app.route('/api/auth/avatar', methods=['POST'])
@login_required
def upload_avatar():
    """上傳使用者頭像（接收 base64 圖片資料）"""
    data = request.get_json(silent=True) or {}
    avatar_data = data.get('avatar', '')

    if not avatar_data:
        return jsonify({'ok': False, 'msg': '未提供頭像資料'}), 400

    # 限制大小：base64 字串最大約 2MB (原始約 1.5MB)
    if len(avatar_data) > 2 * 1024 * 1024:
        return jsonify({'ok': False, 'msg': '頭像檔案過大，請選擇較小的圖片（最大 1.5MB）'}), 400

    conn = _get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("UPDATE users SET avatar = %s WHERE username = %s",
                        (avatar_data, session['user']))
        conn.commit()
    finally:
        conn.close()

    return jsonify({'ok': True, 'msg': '頭像已更新', 'avatar': avatar_data})


@app.route('/api/auth/avatar', methods=['DELETE'])
@login_required
def delete_avatar():
    """刪除使用者頭像"""
    conn = _get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("UPDATE users SET avatar = NULL WHERE username = %s", (session['user'],))
        conn.commit()
    finally:
        conn.close()

    return jsonify({'ok': True, 'msg': '頭像已移除'})


# ---------- 管理員 API ----------

@app.route('/api/admin/stats')
@admin_required
def admin_stats():
    """取得管理後台統計資料"""
    conn = _get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) as cnt FROM users")
            total_users = cur.fetchone()['cnt']
            cur.execute("SELECT COUNT(*) as cnt FROM projects WHERE deleted_at IS NULL")
            total_projects = cur.fetchone()['cnt']
            cur.execute("SELECT COUNT(*) as cnt FROM project_images pi JOIN projects p ON pi.project_id = p.id WHERE p.deleted_at IS NULL")
            total_images = cur.fetchone()['cnt']
            # 今日新增使用者
            cur.execute("SELECT COUNT(*) as cnt FROM users WHERE DATE(created_at) = CURDATE()")
            today_users = cur.fetchone()['cnt']
            # 本週新增使用者
            cur.execute("SELECT COUNT(*) as cnt FROM users WHERE created_at >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)")
            week_users = cur.fetchone()['cnt']
    finally:
        conn.close()
    return jsonify({
        'ok': True,
        'stats': {
            'total_users': total_users,
            'total_projects': total_projects,
            'total_images': total_images,
            'today_users': today_users,
            'week_users': week_users,
        }
    })


@app.route('/api/admin/login-history')
@admin_required
def admin_login_history():
    """取得所有使用者的登入紀錄"""
    limit = request.args.get('limit', 200, type=int)
    conn = _get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT lh.id, lh.username, lh.display_name, lh.ip_address,
                       lh.user_agent, lh.login_at,
                       u.is_admin
                FROM login_history lh
                LEFT JOIN users u ON u.id = lh.user_id
                ORDER BY lh.login_at DESC
                LIMIT %s
            """, (limit,))
            rows = cur.fetchall()
            for r in rows:
                if r.get('login_at'):
                    r['login_at'] = r['login_at'].isoformat()
                r['is_admin'] = bool(r.get('is_admin', 0))
    finally:
        conn.close()
    return jsonify({'ok': True, 'records': rows})


@app.route('/api/admin/users')
@admin_required
def admin_list_users():
    """列出所有使用者（含密碼 salt/hash 供管理員查看）"""
    search = request.args.get('search', '').strip()
    conn = _get_db()
    try:
        with conn.cursor() as cur:
            if search:
                like = f'%{search}%'
                cur.execute("""
                    SELECT id, username, display_name, email, phone, role, clinic_name,
                           license_number, is_admin, created_at, password_hash, salt,
                           (avatar IS NOT NULL AND avatar != '') AS has_avatar
                    FROM users
                    WHERE username LIKE %s OR display_name LIKE %s OR email LIKE %s
                    ORDER BY created_at DESC
                """, (like, like, like))
            else:
                cur.execute("""
                    SELECT id, username, display_name, email, phone, role, clinic_name,
                           license_number, is_admin, created_at, password_hash, salt,
                           (avatar IS NOT NULL AND avatar != '') AS has_avatar
                    FROM users ORDER BY created_at DESC
                """)
            users = cur.fetchall()
            # 統計每位使用者的專案數
            for u in users:
                cur.execute("SELECT COUNT(*) as cnt FROM projects WHERE owner_username = %s AND deleted_at IS NULL",
                            (u['username'],))
                u['project_count'] = cur.fetchone()['cnt']
                u['created_at'] = u['created_at'].isoformat() if u['created_at'] else None
                u['is_admin'] = bool(u.get('is_admin', 0))
                u['has_avatar'] = bool(u.get('has_avatar', 0))
    finally:
        conn.close()
    return jsonify({'ok': True, 'users': users})


@app.route('/api/admin/users/<int:user_id>', methods=['PUT'])
@admin_required
def admin_update_user(user_id):
    """管理員更新使用者資料"""
    data = request.get_json(silent=True) or {}
    conn = _get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
            user = cur.fetchone()
            if not user:
                return jsonify({'ok': False, 'msg': '使用者不存在'}), 404

            # 可更新的欄位
            fields = []
            values = []
            for field in ['display_name', 'email', 'phone', 'role', 'clinic_name', 'license_number']:
                if field in data:
                    fields.append(f"{field} = %s")
                    values.append(data[field])

            # 管理員權限（擁有者帳號的角色不可被其他管理員變更）
            if 'is_admin' in data:
                if user['username'] == 'admin':
                    # 只有擁有者自己可以修改自己的管理員權限（但仍不可降級）
                    if session.get('user') != 'admin':
                        return jsonify({'ok': False, 'msg': '管理員無法變更擁有者帳號的角色'}), 403
                    if not data['is_admin']:
                        return jsonify({'ok': False, 'msg': '擁有者帳號的管理員權限無法移除'}), 403
                fields.append("is_admin = %s")
                values.append(1 if data['is_admin'] else 0)

            # 重設密碼
            if data.get('new_password'):
                new_salt, new_hash = _hash_password(data['new_password'])
                fields.append("password_hash = %s")
                values.append(new_hash)
                fields.append("salt = %s")
                values.append(new_salt)

            if fields:
                values.append(user_id)
                cur.execute(f"UPDATE users SET {', '.join(fields)} WHERE id = %s", values)
                conn.commit()
    finally:
        conn.close()
    return jsonify({'ok': True, 'msg': '使用者資料已更新'})


@app.route('/api/admin/users', methods=['POST'])
@admin_required
def admin_create_user():
    """管理員手動新增使用者帳號"""
    import re as _re
    data = request.get_json(silent=True) or {}
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    display_name = data.get('display_name', '').strip() or username
    email = data.get('email', '').strip()
    phone = data.get('phone', '').strip()
    role = data.get('role', '').strip()
    clinic_name = data.get('clinic_name', '').strip()
    license_number = data.get('license_number', '').strip()
    is_admin = bool(data.get('is_admin', False))

    # 基本驗證
    if not username or not password:
        return jsonify({'ok': False, 'msg': '請輸入帳號和密碼'}), 400
    if len(username) < 3:
        return jsonify({'ok': False, 'msg': '帳號至少需要 3 個字元'}), 400
    if len(password) < 6:
        return jsonify({'ok': False, 'msg': '密碼至少需要 6 個字元'}), 400

    conn = _get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM users WHERE username = %s", (username,))
            if cur.fetchone():
                return jsonify({'ok': False, 'msg': '此帳號已被使用'}), 409
            if email:
                cur.execute("SELECT id FROM users WHERE email = %s AND email != ''", (email,))
                if cur.fetchone():
                    return jsonify({'ok': False, 'msg': '此電子郵件已被使用'}), 409

            salt, hashed = _hash_password(password)
            cur.execute(
                """INSERT INTO users
                   (username, password_hash, salt, display_name, email, phone, role, clinic_name, license_number, is_admin)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                (username, hashed, salt, display_name, email, phone, role, clinic_name, license_number, 1 if is_admin else 0)
            )
        conn.commit()
    finally:
        conn.close()
    return jsonify({'ok': True, 'msg': f'使用者 {username} 已建立'})


@app.route('/api/admin/users/<int:user_id>', methods=['DELETE'])
@admin_required
def admin_delete_user(user_id):
    """管理員刪除使用者"""
    conn = _get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT username FROM users WHERE id = %s", (user_id,))
            user = cur.fetchone()
            if not user:
                return jsonify({'ok': False, 'msg': '使用者不存在'}), 404
            if user['username'] == 'admin':
                return jsonify({'ok': False, 'msg': '擁有者帳號無法刪除'}), 403
            if user['username'] == session.get('user'):
                return jsonify({'ok': False, 'msg': '無法刪除自己的帳號'}), 403
            # 刪除該使用者的專案和圖片
            cur.execute("SELECT id FROM projects WHERE owner_username = %s", (user['username'],))
            proj_ids = [r['id'] for r in cur.fetchall()]
            if proj_ids:
                fmt = ','.join(['%s'] * len(proj_ids))
                cur.execute(f"DELETE FROM project_images WHERE project_id IN ({fmt})", proj_ids)
                cur.execute(f"DELETE FROM cd_markers WHERE project_id IN ({fmt})", proj_ids)
                cur.execute(f"DELETE FROM cs_sessions WHERE project_id IN ({fmt})", proj_ids)
                cur.execute(f"DELETE FROM projects WHERE owner_username = %s", (user['username'],))
            cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
            conn.commit()
    finally:
        conn.close()
    return jsonify({'ok': True, 'msg': '使用者已刪除'})


@app.route('/api/admin/projects')
@admin_required
def admin_list_projects():
    """管理員查看所有專案"""
    conn = _get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT p.id, p.name, p.owner_username, p.status, p.created_at, p.modified_at, p.deleted_at,
                       u.display_name as owner_display_name,
                       (SELECT COUNT(*) FROM project_images WHERE project_id = p.id) as image_count
                FROM projects p
                LEFT JOIN users u ON p.owner_username = u.username
                ORDER BY p.modified_at DESC
            """)
            projects = cur.fetchall()
            for p in projects:
                p['created_at'] = p['created_at'].isoformat() if p['created_at'] else None
                p['modified_at'] = p['modified_at'].isoformat() if p['modified_at'] else None
                p['deleted_at'] = p['deleted_at'].isoformat() if p.get('deleted_at') else None
    finally:
        conn.close()
    return jsonify({'ok': True, 'projects': projects})


@app.route('/api/admin/projects/<int:project_id>', methods=['DELETE'])
@admin_required
def admin_delete_project(project_id):
    """管理員永久刪除專案（含所有圖片與相關資料）"""
    conn = _get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM projects WHERE id = %s", (project_id,))
            if not cur.fetchone():
                return jsonify({'ok': False, 'msg': '專案不存在'}), 404
            cur.execute("DELETE FROM project_images WHERE project_id = %s", (project_id,))
            cur.execute("DELETE FROM cd_markers WHERE project_id = %s", (project_id,))
            cur.execute("DELETE FROM cs_sessions WHERE project_id = %s", (project_id,))
            cur.execute("DELETE FROM projects WHERE id = %s", (project_id,))
            conn.commit()
    finally:
        conn.close()
    return jsonify({'ok': True, 'msg': '專案已永久刪除'})


# ---------- 系統設定 API ----------

@app.route('/api/admin/settings')
@admin_required
def admin_get_settings():
    """取得所有系統設定"""
    conn = _get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM system_settings ORDER BY sort_order")
            settings = cur.fetchall()
            for s in settings:
                if s.get('updated_at'):
                    s['updated_at'] = s['updated_at'].isoformat()
    finally:
        conn.close()
    return jsonify({'ok': True, 'settings': settings})


@app.route('/api/admin/settings', methods=['PUT'])
@admin_required
def admin_update_settings():
    """批次更新系統設定"""
    data = request.get_json(silent=True) or {}
    items = data.get('settings', {})
    if not items:
        return jsonify({'ok': False, 'msg': '沒有要更新的項目'}), 400
    conn = _get_db()
    try:
        with conn.cursor() as cur:
            for key, val in items.items():
                cur.execute("UPDATE system_settings SET setting_value=%s WHERE setting_key=%s", (str(val), key))
        conn.commit()
    finally:
        conn.close()
    # 清除快取，讓設定立即生效
    global _settings_cache_ts
    _settings_cache_ts = 0
    # 即時生效：更新 Flask 執行時期設定
    if 'max_upload_size_mb' in items:
        try:
            app.config['MAX_CONTENT_LENGTH'] = int(items['max_upload_size_mb']) * 1024 * 1024
        except (ValueError, TypeError):
            pass
    if 'session_timeout_days' in items:
        try:
            app.permanent_session_lifetime = timedelta(days=int(items['session_timeout_days']))
        except (ValueError, TypeError):
            pass
    return jsonify({'ok': True, 'msg': '設定已更新'})


@app.route('/api/public/settings')
def public_settings():
    """公開 API：回傳前端需要的系統設定（不含安全類別）"""
    EXPOSED_KEYS = [
        'site_name', 'site_description', 'allow_registration',
        'maintenance_mode', 'max_upload_size_mb',
    ]
    conn = _get_db()
    try:
        with conn.cursor() as cur:
            placeholders = ','.join(['%s'] * len(EXPOSED_KEYS))
            cur.execute(f"SELECT setting_key, setting_value FROM system_settings WHERE setting_key IN ({placeholders})", EXPOSED_KEYS)
            rows = cur.fetchall()
    finally:
        conn.close()
    result = {r['setting_key']: r['setting_value'] for r in rows}
    return jsonify({'ok': True, 'settings': result})


# ---------- 色卡管理 API ----------

@app.route('/api/admin/shade-brands')
@admin_required
def admin_list_shade_brands():
    """列出所有色卡品牌（含群組與色階數量）"""
    conn = _get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT b.*,
                       (SELECT COUNT(*) FROM shade_groups WHERE brand_id=b.id) as group_count,
                       (SELECT COUNT(*) FROM shades s JOIN shade_groups g ON s.group_id=g.id WHERE g.brand_id=b.id) as shade_count
                FROM shade_brands b ORDER BY b.sort_order, b.id
            """)
            brands = cur.fetchall()
            for b in brands:
                b['is_active'] = bool(b.get('is_active', 1))
                if b.get('created_at'):
                    b['created_at'] = b['created_at'].isoformat()
    finally:
        conn.close()
    return jsonify({'ok': True, 'brands': brands})


@app.route('/api/admin/shade-brands', methods=['POST'])
@admin_required
def admin_add_shade_brand():
    """新增色卡品牌"""
    data = request.get_json(silent=True) or {}
    brand_key = data.get('brand_key', '').strip()
    brand_name = data.get('brand_name', '').strip()
    if not brand_key or not brand_name:
        return jsonify({'ok': False, 'msg': '品牌代碼與名稱不可為空'}), 400
    conn = _get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM shade_brands WHERE brand_key=%s", (brand_key,))
            if cur.fetchone():
                return jsonify({'ok': False, 'msg': '品牌代碼已存在'}), 409
            cur.execute("SELECT COALESCE(MAX(sort_order),0)+1 as n FROM shade_brands")
            sort_order = cur.fetchone()['n']
            cur.execute("INSERT INTO shade_brands (brand_key, brand_name, sort_order) VALUES (%s,%s,%s)",
                        (brand_key, brand_name, sort_order))
            brand_id = cur.lastrowid
        conn.commit()
    finally:
        conn.close()
    return jsonify({'ok': True, 'msg': '品牌已新增', 'id': brand_id})


@app.route('/api/admin/shade-brands/<int:brand_id>', methods=['PUT'])
@admin_required
def admin_update_shade_brand(brand_id):
    """更新色卡品牌"""
    data = request.get_json(silent=True) or {}
    conn = _get_db()
    try:
        with conn.cursor() as cur:
            fields, vals = [], []
            for f in ['brand_name', 'brand_key', 'sort_order']:
                if f in data:
                    fields.append(f"{f}=%s")
                    vals.append(data[f])
            if 'is_active' in data:
                fields.append("is_active=%s")
                vals.append(1 if data['is_active'] else 0)
            if fields:
                vals.append(brand_id)
                cur.execute(f"UPDATE shade_brands SET {','.join(fields)} WHERE id=%s", vals)
        conn.commit()
    finally:
        conn.close()
    return jsonify({'ok': True, 'msg': '品牌已更新'})


@app.route('/api/admin/shade-brands/<int:brand_id>', methods=['DELETE'])
@admin_required
def admin_delete_shade_brand(brand_id):
    """刪除色卡品牌（連帶刪除群組與色階）"""
    conn = _get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM shade_brands WHERE id=%s", (brand_id,))
        conn.commit()
    finally:
        conn.close()
    return jsonify({'ok': True, 'msg': '品牌及其所有色卡資料已刪除'})


@app.route('/api/admin/shade-brands/<int:brand_id>/groups')
@admin_required
def admin_list_shade_groups(brand_id):
    """列出品牌下所有群組（含色階數量）"""
    conn = _get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT g.*, (SELECT COUNT(*) FROM shades WHERE group_id=g.id) as shade_count
                FROM shade_groups g WHERE g.brand_id=%s ORDER BY g.sort_order, g.id
            """, (brand_id,))
            groups = cur.fetchall()
            for g in groups:
                if g.get('created_at'):
                    g['created_at'] = g['created_at'].isoformat()
    finally:
        conn.close()
    return jsonify({'ok': True, 'groups': groups})


@app.route('/api/admin/shade-groups', methods=['POST'])
@admin_required
def admin_add_shade_group():
    """新增色卡群組"""
    data = request.get_json(silent=True) or {}
    brand_id = data.get('brand_id')
    title = data.get('title', '').strip()
    if not brand_id or not title:
        return jsonify({'ok': False, 'msg': '品牌 ID 與群組名稱不可為空'}), 400
    conn = _get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT COALESCE(MAX(sort_order),0)+1 as n FROM shade_groups WHERE brand_id=%s", (brand_id,))
            sort_order = cur.fetchone()['n']
            cur.execute("INSERT INTO shade_groups (brand_id, title, sort_order) VALUES (%s,%s,%s)",
                        (brand_id, title, sort_order))
            group_id = cur.lastrowid
        conn.commit()
    finally:
        conn.close()
    return jsonify({'ok': True, 'msg': '群組已新增', 'id': group_id})


@app.route('/api/admin/shade-groups/<int:group_id>', methods=['PUT'])
@admin_required
def admin_update_shade_group(group_id):
    """更新群組"""
    data = request.get_json(silent=True) or {}
    conn = _get_db()
    try:
        with conn.cursor() as cur:
            fields, vals = [], []
            for f in ['title', 'sort_order']:
                if f in data:
                    fields.append(f"{f}=%s")
                    vals.append(data[f])
            if fields:
                vals.append(group_id)
                cur.execute(f"UPDATE shade_groups SET {','.join(fields)} WHERE id=%s", vals)
        conn.commit()
    finally:
        conn.close()
    return jsonify({'ok': True, 'msg': '群組已更新'})


@app.route('/api/admin/shade-groups/<int:group_id>', methods=['DELETE'])
@admin_required
def admin_delete_shade_group(group_id):
    """刪除群組（連帶刪除色階）"""
    conn = _get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM shade_groups WHERE id=%s", (group_id,))
        conn.commit()
    finally:
        conn.close()
    return jsonify({'ok': True, 'msg': '群組及其色階已刪除'})


@app.route('/api/admin/shade-groups/<int:group_id>/shades')
@admin_required
def admin_list_shades(group_id):
    """列出群組下所有色階"""
    conn = _get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM shades WHERE group_id=%s ORDER BY sort_order, id", (group_id,))
            shades = cur.fetchall()
            for s in shades:
                s['lab_l'] = float(s['lab_l']) if s['lab_l'] else 0
                s['lab_a'] = float(s['lab_a']) if s['lab_a'] else 0
                s['lab_b'] = float(s['lab_b']) if s['lab_b'] else 0
                if s.get('created_at'):
                    s['created_at'] = s['created_at'].isoformat()
    finally:
        conn.close()
    return jsonify({'ok': True, 'shades': shades})


@app.route('/api/admin/shades', methods=['POST'])
@admin_required
def admin_add_shade():
    """新增色階"""
    data = request.get_json(silent=True) or {}
    group_id = data.get('group_id')
    code = data.get('code', '').strip()
    name = data.get('name', '').strip()
    hex_color = data.get('hex_color', '#FFFFFF').strip()
    lab_l = data.get('lab_l', 0)
    lab_a = data.get('lab_a', 0)
    lab_b = data.get('lab_b', 0)
    if not group_id or not code:
        return jsonify({'ok': False, 'msg': '群組 ID 與色階代碼不可為空'}), 400
    conn = _get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT COALESCE(MAX(sort_order),0)+1 as n FROM shades WHERE group_id=%s", (group_id,))
            sort_order = cur.fetchone()['n']
            cur.execute("""
                INSERT INTO shades (group_id, code, name, hex_color, lab_l, lab_a, lab_b, sort_order)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
            """, (group_id, code, name, hex_color, lab_l, lab_a, lab_b, sort_order))
            shade_id = cur.lastrowid
        conn.commit()
    finally:
        conn.close()
    return jsonify({'ok': True, 'msg': '色階已新增', 'id': shade_id})


@app.route('/api/admin/shades/<int:shade_id>', methods=['PUT'])
@admin_required
def admin_update_shade(shade_id):
    """更新色階"""
    data = request.get_json(silent=True) or {}
    conn = _get_db()
    try:
        with conn.cursor() as cur:
            fields, vals = [], []
            for f in ['code', 'name', 'hex_color', 'lab_l', 'lab_a', 'lab_b', 'sort_order']:
                if f in data:
                    fields.append(f"{f}=%s")
                    vals.append(data[f])
            if fields:
                vals.append(shade_id)
                cur.execute(f"UPDATE shades SET {','.join(fields)} WHERE id=%s", vals)
        conn.commit()
    finally:
        conn.close()
    return jsonify({'ok': True, 'msg': '色階已更新'})


@app.route('/api/admin/shades/<int:shade_id>', methods=['DELETE'])
@admin_required
def admin_delete_shade(shade_id):
    """刪除色階"""
    conn = _get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM shades WHERE id=%s", (shade_id,))
        conn.commit()
    finally:
        conn.close()
    return jsonify({'ok': True, 'msg': '色階已刪除'})


# ---------- 色卡資料匯入/匯出 ----------

@app.route('/api/admin/shade-brands/<int:brand_id>/export')
@admin_required
def admin_export_shade_brand(brand_id):
    """匯出單一品牌完整資料（含群組與色階）為 JSON"""
    conn = _get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM shade_brands WHERE id=%s", (brand_id,))
            brand = cur.fetchone()
            if not brand:
                return jsonify({'ok': False, 'msg': '品牌不存在'}), 404
            cur.execute("SELECT * FROM shade_groups WHERE brand_id=%s ORDER BY sort_order, id", (brand_id,))
            groups = cur.fetchall()
            export_groups = []
            for g in groups:
                cur.execute("SELECT * FROM shades WHERE group_id=%s ORDER BY sort_order, id", (g['id'],))
                shades = cur.fetchall()
                export_groups.append({
                    'title': g['title'],
                    'sort_order': g.get('sort_order', 0),
                    'shades': [{
                        'code': s['code'],
                        'name': s['name'],
                        'hex': s['hex_color'],
                        'L': float(s['lab_l']) if s['lab_l'] else 0,
                        'a': float(s['lab_a']) if s['lab_a'] else 0,
                        'b': float(s['lab_b']) if s['lab_b'] else 0,
                        'sort_order': s.get('sort_order', 0),
                    } for s in shades]
                })
            export_data = {
                'brand_key': brand['brand_key'],
                'brand_name': brand['brand_name'],
                'groups': export_groups,
                'exported_at': datetime.now().isoformat(),
                'version': '1.0'
            }
    finally:
        conn.close()
    return jsonify({'ok': True, 'data': export_data})


@app.route('/api/admin/shade-brands/import', methods=['POST'])
@admin_required
def admin_import_shade_brand():
    """匯入品牌完整資料（含群組與色階）從 JSON"""
    data = request.get_json(silent=True) or {}
    brand_key = data.get('brand_key', '').strip()
    brand_name = data.get('brand_name', '').strip()
    groups = data.get('groups', [])
    if not brand_key or not brand_name:
        return jsonify({'ok': False, 'msg': '匯入資料格式錯誤：缺少 brand_key 或 brand_name'}), 400
    conn = _get_db()
    try:
        with conn.cursor() as cur:
            # 檢查是否已存在同 brand_key
            cur.execute("SELECT id FROM shade_brands WHERE brand_key=%s", (brand_key,))
            existing = cur.fetchone()
            if existing:
                # 刪除舊的再重建
                cur.execute("DELETE FROM shade_brands WHERE id=%s", (existing['id'],))
            cur.execute("SELECT COALESCE(MAX(sort_order),0)+1 as n FROM shade_brands")
            sort_order = cur.fetchone()['n']
            cur.execute("INSERT INTO shade_brands (brand_key, brand_name, sort_order) VALUES (%s,%s,%s)",
                        (brand_key, brand_name, sort_order))
            brand_id = cur.lastrowid
            shade_count = 0
            for gidx, group in enumerate(groups):
                g_title = group.get('title', f'群組{gidx+1}')
                g_sort = group.get('sort_order', gidx)
                cur.execute("INSERT INTO shade_groups (brand_id, title, sort_order) VALUES (%s,%s,%s)",
                            (brand_id, g_title, g_sort))
                group_id = cur.lastrowid
                for sidx, shade in enumerate(group.get('shades', [])):
                    s_sort = shade.get('sort_order', sidx)
                    cur.execute("""
                        INSERT INTO shades (group_id, code, name, hex_color, lab_l, lab_a, lab_b, sort_order)
                        VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
                    """, (group_id, shade.get('code',''), shade.get('name',''),
                          shade.get('hex','#FFFFFF'), shade.get('L',0), shade.get('a',0), shade.get('b',0), s_sort))
                    shade_count += 1
        conn.commit()
    finally:
        conn.close()
    return jsonify({'ok': True, 'msg': f'已成功匯入品牌「{brand_name}」（{len(groups)} 個群組、{shade_count} 個色階）', 'id': brand_id})


@app.route('/api/admin/shade-brands/import-defaults', methods=['POST'])
@admin_required
def admin_import_default_shades():
    """匯入預設色卡資料（從硬編碼的 JS 資料）"""
    DEFAULT_BRANDS = [
        {
            'brand_key': 'vita-classical', 'brand_name': 'VITA Classical',
            'groups': [
                {'title': 'BL 系列（漂白色調）', 'shades': [
                    {'code':'BL1','name':'漂白1','hex':'#EDE8DC','L':91.8,'a':-1.0,'b':7.5},
                    {'code':'BL2','name':'漂白2','hex':'#EBE4D6','L':90.5,'a':-0.5,'b':8.5},
                    {'code':'BL3','name':'漂白3','hex':'#E8E0D0','L':89.0,'a':0.0,'b':9.5},
                    {'code':'BL4','name':'漂白4','hex':'#E4DACB','L':87.5,'a':0.5,'b':10.5},
                ]},
                {'title': 'A 系列（紅棕色調）', 'shades': [
                    {'code':'A1','name':'淺紅棕','hex':'#E8D8C4','L':87.5,'a':2.0,'b':14.5},
                    {'code':'A2','name':'淡紅棕','hex':'#DCC9A8','L':82.0,'a':3.5,'b':19.0},
                    {'code':'A3','name':'中紅棕','hex':'#CEBC97','L':77.0,'a':4.5,'b':22.0},
                    {'code':'A3.5','name':'深中紅棕','hex':'#C4AD84','L':72.0,'a':6.0,'b':25.0},
                    {'code':'A4','name':'深紅棕','hex':'#B89D72','L':66.0,'a':7.5,'b':28.0},
                ]},
                {'title': 'B 系列（黃色調）', 'shades': [
                    {'code':'B1','name':'淺黃','hex':'#E6DCCA','L':88.0,'a':0.5,'b':12.0},
                    {'code':'B2','name':'淡黃','hex':'#DDD0B0','L':84.0,'a':1.5,'b':18.0},
                    {'code':'B3','name':'中黃','hex':'#D0C19A','L':79.0,'a':3.0,'b':22.5},
                    {'code':'B4','name':'深黃','hex':'#C4B286','L':74.0,'a':5.0,'b':26.0},
                ]},
                {'title': 'C 系列（灰色調）', 'shades': [
                    {'code':'C1','name':'淺灰','hex':'#D8D0C2','L':84.0,'a':0.0,'b':10.0},
                    {'code':'C2','name':'淡灰','hex':'#CEC3AC','L':79.5,'a':1.5,'b':15.5},
                    {'code':'C3','name':'中灰','hex':'#C0B496','L':74.0,'a':3.0,'b':19.0},
                    {'code':'C4','name':'深灰','hex':'#B0A284','L':67.5,'a':4.5,'b':22.0},
                ]},
                {'title': 'D 系列（紅灰色調）', 'shades': [
                    {'code':'D2','name':'淡紅灰','hex':'#D6CCBC','L':83.0,'a':2.0,'b':11.5},
                    {'code':'D3','name':'中紅灰','hex':'#C8BCA4','L':77.0,'a':3.5,'b':16.0},
                    {'code':'D4','name':'深紅灰','hex':'#BAAC90','L':71.0,'a':5.0,'b':20.0},
                ]},
            ]
        },
        {
            'brand_key': 'vita-3d-master', 'brand_name': 'VITA 3D-Master',
            'groups': [
                {'title': '1M（明度 1）', 'shades': [
                    {'code':'1M1','name':'明度1 彩度1','hex':'#EBE0D2','L':89.0,'a':1.0,'b':10.0},
                    {'code':'1M2','name':'明度1 彩度2','hex':'#E4D6C0','L':86.0,'a':2.0,'b':14.0},
                ]},
                {'title': '2L / 2M / 2R（明度 2）', 'shades': [
                    {'code':'2L1.5','name':'明度2 偏亮 彩度1.5','hex':'#E2D8C6','L':87.0,'a':0.5,'b':12.0},
                    {'code':'2L2.5','name':'明度2 偏亮 彩度2.5','hex':'#D8CCAE','L':83.0,'a':2.0,'b':18.0},
                    {'code':'2M1','name':'明度2 中等 彩度1','hex':'#E0D4C2','L':85.5,'a':1.5,'b':13.0},
                    {'code':'2M2','name':'明度2 中等 彩度2','hex':'#D6C8AE','L':82.0,'a':3.0,'b':17.0},
                    {'code':'2M3','name':'明度2 中等 彩度3','hex':'#CCBC9A','L':77.0,'a':4.5,'b':21.5},
                    {'code':'2R1.5','name':'明度2 偏紅 彩度1.5','hex':'#DED0BA','L':84.5,'a':3.0,'b':14.5},
                    {'code':'2R2.5','name':'明度2 偏紅 彩度2.5','hex':'#D4C4A4','L':80.0,'a':5.0,'b':19.0},
                ]},
                {'title': '3L / 3M / 3R（明度 3）', 'shades': [
                    {'code':'3L1.5','name':'明度3 偏亮 彩度1.5','hex':'#D8CEBC','L':83.5,'a':1.0,'b':12.5},
                    {'code':'3L2.5','name':'明度3 偏亮 彩度2.5','hex':'#CCC0A2','L':78.5,'a':2.5,'b':18.5},
                    {'code':'3M1','name':'明度3 中等 彩度1','hex':'#D4C8B4','L':81.5,'a':2.0,'b':14.0},
                    {'code':'3M2','name':'明度3 中等 彩度2','hex':'#C8BA9C','L':76.5,'a':4.0,'b':19.0},
                    {'code':'3M3','name':'明度3 中等 彩度3','hex':'#BCA88A','L':70.5,'a':6.5,'b':24.0},
                    {'code':'3R1.5','name':'明度3 偏紅 彩度1.5','hex':'#D2C2AA','L':79.5,'a':4.5,'b':16.0},
                    {'code':'3R2.5','name':'明度3 偏紅 彩度2.5','hex':'#C6B494','L':74.5,'a':6.5,'b':21.0},
                ]},
                {'title': '4L / 4M / 4R（明度 4）', 'shades': [
                    {'code':'4L1.5','name':'明度4 偏亮 彩度1.5','hex':'#CCC2AE','L':79.0,'a':1.5,'b':13.0},
                    {'code':'4L2.5','name':'明度4 偏亮 彩度2.5','hex':'#C0B496','L':74.0,'a':3.5,'b':19.0},
                    {'code':'4M1','name':'明度4 中等 彩度1','hex':'#C8BAA4','L':76.5,'a':3.0,'b':15.5},
                    {'code':'4M2','name':'明度4 中等 彩度2','hex':'#BAAC8E','L':71.0,'a':5.0,'b':21.0},
                    {'code':'4M3','name':'明度4 中等 彩度3','hex':'#AA9876','L':64.0,'a':7.5,'b':26.0},
                    {'code':'4R1.5','name':'明度4 偏紅 彩度1.5','hex':'#C4B498','L':74.5,'a':5.5,'b':17.5},
                    {'code':'4R2.5','name':'明度4 偏紅 彩度2.5','hex':'#B8A482','L':69.0,'a':7.5,'b':23.0},
                ]},
                {'title': '5M（明度 5）', 'shades': [
                    {'code':'5M1','name':'明度5 彩度1','hex':'#C0B49E','L':74.0,'a':3.5,'b':15.0},
                    {'code':'5M2','name':'明度5 彩度2','hex':'#B0A286','L':67.5,'a':5.5,'b':21.0},
                    {'code':'5M3','name':'明度5 彩度3','hex':'#9E8E6E','L':60.0,'a':8.0,'b':27.0},
                ]},
            ]
        },
        {
            'brand_key': 'ivoclar-ips-emax', 'brand_name': 'Ivoclar IPS e.max',
            'groups': [
                {'title': 'HT（高透）', 'shades': [
                    {'code':'HT A1','name':'高透 A1','hex':'#E6D8C6','L':87.0,'a':1.5,'b':13.0},
                    {'code':'HT A2','name':'高透 A2','hex':'#DACAA8','L':82.5,'a':3.0,'b':18.0},
                    {'code':'HT A3','name':'高透 A3','hex':'#CCBC96','L':77.0,'a':4.0,'b':21.5},
                    {'code':'HT B1','name':'高透 B1','hex':'#E4DACA','L':87.5,'a':0.5,'b':11.0},
                    {'code':'HT B2','name':'高透 B2','hex':'#DBCEAE','L':83.5,'a':1.5,'b':17.0},
                    {'code':'HT BL1','name':'高透 BL1','hex':'#EDE6DA','L':91.5,'a':-0.5,'b':8.0},
                    {'code':'HT BL2','name':'高透 BL2','hex':'#EAE2D4','L':90.0,'a':0.0,'b':9.5},
                    {'code':'HT BL3','name':'高透 BL3','hex':'#E6DDD0','L':89.0,'a':0.5,'b':10.5},
                    {'code':'HT BL4','name':'高透 BL4','hex':'#E2D8C8','L':87.5,'a':1.0,'b':11.5},
                ]},
                {'title': 'LT（低透）', 'shades': [
                    {'code':'LT A1','name':'低透 A1','hex':'#E4D4C0','L':86.0,'a':2.0,'b':14.0},
                    {'code':'LT A2','name':'低透 A2','hex':'#D8C6A4','L':81.0,'a':3.5,'b':19.0},
                    {'code':'LT A3','name':'低透 A3','hex':'#CAB892','L':76.0,'a':5.0,'b':22.5},
                    {'code':'LT A3.5','name':'低透 A3.5','hex':'#C0AA80','L':71.0,'a':6.5,'b':25.5},
                    {'code':'LT B1','name':'低透 B1','hex':'#E2D8C6','L':87.0,'a':0.5,'b':12.0},
                    {'code':'LT B2','name':'低透 B2','hex':'#D8CAAA','L':82.5,'a':2.0,'b':17.5},
                    {'code':'LT C2','name':'低透 C2','hex':'#CCC0A8','L':79.0,'a':1.5,'b':15.0},
                    {'code':'LT D3','name':'低透 D3','hex':'#C6B89E','L':76.0,'a':3.5,'b':16.5},
                ]},
                {'title': 'MO（中等不透明）', 'shades': [
                    {'code':'MO 0','name':'不透明 0','hex':'#EDE4D6','L':91.0,'a':0.0,'b':9.0},
                    {'code':'MO 1','name':'不透明 1','hex':'#E6DACA','L':88.0,'a':1.0,'b':12.0},
                    {'code':'MO 2','name':'不透明 2','hex':'#DED0B8','L':84.5,'a':2.0,'b':15.0},
                    {'code':'MO 3','name':'不透明 3','hex':'#D4C4A4','L':80.0,'a':3.5,'b':18.5},
                    {'code':'MO 4','name':'不透明 4','hex':'#C8B692','L':75.0,'a':5.0,'b':22.0},
                ]},
            ]
        },
        {
            'brand_key': 'gc-initial', 'brand_name': 'GC Initial',
            'groups': [
                {'title': 'LiSi（二矽酸鋰）', 'shades': [
                    {'code':'A1','name':'LiSi A1','hex':'#E6D6C2','L':86.5,'a':2.0,'b':14.0},
                    {'code':'A2','name':'LiSi A2','hex':'#DAC8A6','L':81.5,'a':3.5,'b':18.5},
                    {'code':'A3','name':'LiSi A3','hex':'#CCBA94','L':76.5,'a':5.0,'b':22.0},
                    {'code':'A3.5','name':'LiSi A3.5','hex':'#C2AA82','L':71.0,'a':6.5,'b':25.0},
                    {'code':'B1','name':'LiSi B1','hex':'#E4DAC8','L':87.5,'a':0.5,'b':11.5},
                    {'code':'B2','name':'LiSi B2','hex':'#D9CCAD','L':83.0,'a':1.5,'b':16.5},
                    {'code':'B3','name':'LiSi B3','hex':'#CEC0A0','L':78.5,'a':2.5,'b':20.0},
                    {'code':'C2','name':'LiSi C2','hex':'#CCC2AB','L':79.5,'a':1.0,'b':14.5},
                    {'code':'D2','name':'LiSi D2','hex':'#D4CCB8','L':82.5,'a':2.0,'b':12.0},
                    {'code':'D3','name':'LiSi D3','hex':'#C8BCA2','L':77.0,'a':3.0,'b':16.0},
                ]},
            ]
        },
        {
            'brand_key': 'noritake-ex3', 'brand_name': 'Noritake EX-3',
            'groups': [
                {'title': 'Body', 'shades': [
                    {'code':'A1','name':'Body A1','hex':'#E5D7C3','L':87.0,'a':1.5,'b':13.5},
                    {'code':'A2','name':'Body A2','hex':'#D9C9A7','L':82.0,'a':3.0,'b':18.0},
                    {'code':'A3','name':'Body A3','hex':'#CBB995','L':76.5,'a':4.5,'b':21.5},
                    {'code':'A3.5','name':'Body A3.5','hex':'#C1A983','L':71.0,'a':6.0,'b':24.5},
                    {'code':'A4','name':'Body A4','hex':'#B59A72','L':65.0,'a':7.5,'b':27.5},
                    {'code':'B1','name':'Body B1','hex':'#E3D9C7','L':87.5,'a':0.5,'b':11.0},
                    {'code':'B2','name':'Body B2','hex':'#D8CBAC','L':82.5,'a':1.5,'b':16.5},
                    {'code':'B3','name':'Body B3','hex':'#CDBF9E','L':78.0,'a':2.5,'b':19.5},
                    {'code':'B4','name':'Body B4','hex':'#C2B18A','L':73.0,'a':4.0,'b':24.0},
                    {'code':'C1','name':'Body C1','hex':'#D7CFC0','L':84.0,'a':0.0,'b':10.5},
                    {'code':'C2','name':'Body C2','hex':'#CBC1AA','L':79.0,'a':1.5,'b':15.0},
                    {'code':'C3','name':'Body C3','hex':'#BEB394','L':74.0,'a':2.5,'b':18.5},
                    {'code':'D2','name':'Body D2','hex':'#D5CBBA','L':83.0,'a':1.5,'b':12.0},
                    {'code':'D3','name':'Body D3','hex':'#C7BBA2','L':77.0,'a':3.0,'b':16.0},
                    {'code':'D4','name':'Body D4','hex':'#B9AA8E','L':71.0,'a':4.5,'b':20.0},
                ]},
            ]
        },
        {
            'brand_key': 'ivoclar-ips-dsign', 'brand_name': 'Ivoclar IPS d.SIGN',
            'groups': [
                {'title': 'Body A 系列', 'shades': [
                    {'code':'A1','name':'d.SIGN A1','hex':'#E7D9C5','L':87.2,'a':1.8,'b':14.0},
                    {'code':'A2','name':'d.SIGN A2','hex':'#DBCBA9','L':82.3,'a':3.2,'b':18.5},
                    {'code':'A3','name':'d.SIGN A3','hex':'#CDBD98','L':77.2,'a':4.3,'b':21.8},
                    {'code':'A3.5','name':'d.SIGN A3.5','hex':'#C3AE85','L':72.2,'a':5.8,'b':24.8},
                    {'code':'A4','name':'d.SIGN A4','hex':'#B79E73','L':66.2,'a':7.2,'b':27.8},
                ]},
                {'title': 'Body B 系列', 'shades': [
                    {'code':'B1','name':'d.SIGN B1','hex':'#E5DDCB','L':88.2,'a':0.3,'b':11.5},
                    {'code':'B2','name':'d.SIGN B2','hex':'#DCD1B1','L':84.2,'a':1.3,'b':17.5},
                    {'code':'B3','name':'d.SIGN B3','hex':'#CFC29B','L':79.2,'a':2.8,'b':22.0},
                    {'code':'B4','name':'d.SIGN B4','hex':'#C3B387','L':74.2,'a':4.8,'b':25.5},
                ]},
                {'title': 'Body C 系列', 'shades': [
                    {'code':'C1','name':'d.SIGN C1','hex':'#D7D1C3','L':84.2,'a':-0.2,'b':9.5},
                    {'code':'C2','name':'d.SIGN C2','hex':'#CDC4AD','L':79.7,'a':1.3,'b':15.0},
                    {'code':'C3','name':'d.SIGN C3','hex':'#BFB597','L':74.2,'a':2.8,'b':18.5},
                    {'code':'C4','name':'d.SIGN C4','hex':'#AFA385','L':67.7,'a':4.3,'b':21.5},
                ]},
                {'title': 'Body D 系列', 'shades': [
                    {'code':'D2','name':'d.SIGN D2','hex':'#D5CDBD','L':83.2,'a':1.8,'b':11.0},
                    {'code':'D3','name':'d.SIGN D3','hex':'#C7BDA5','L':77.2,'a':3.3,'b':15.5},
                    {'code':'D4','name':'d.SIGN D4','hex':'#B9AD91','L':71.2,'a':4.8,'b':19.5},
                ]},
            ]
        },
        {
            'brand_key': 'shofu-vintage-halo', 'brand_name': 'Shofu Vintage Halo',
            'groups': [
                {'title': 'Body A 系列', 'shades': [
                    {'code':'A1','name':'Halo A1','hex':'#E9D9C3','L':87.8,'a':2.2,'b':15.0},
                    {'code':'A2','name':'Halo A2','hex':'#DDCAA7','L':82.5,'a':3.8,'b':19.5},
                    {'code':'A3','name':'Halo A3','hex':'#CFBC96','L':77.5,'a':5.0,'b':22.5},
                    {'code':'A3.5','name':'Halo A3.5','hex':'#C5AD83','L':72.5,'a':6.5,'b':25.5},
                    {'code':'A4','name':'Halo A4','hex':'#B99D71','L':66.5,'a':8.0,'b':28.5},
                ]},
                {'title': 'Body B 系列', 'shades': [
                    {'code':'B1','name':'Halo B1','hex':'#E7DDC9','L':88.5,'a':0.8,'b':12.5},
                    {'code':'B2','name':'Halo B2','hex':'#DED1AF','L':84.5,'a':1.8,'b':18.5},
                    {'code':'B3','name':'Halo B3','hex':'#D1C29A','L':79.5,'a':3.5,'b':23.0},
                    {'code':'B4','name':'Halo B4','hex':'#C5B385','L':74.5,'a':5.5,'b':26.5},
                ]},
                {'title': 'Body C 系列', 'shades': [
                    {'code':'C1','name':'Halo C1','hex':'#D9D1C1','L':84.5,'a':0.2,'b':10.5},
                    {'code':'C2','name':'Halo C2','hex':'#CFC4AB','L':80.0,'a':1.8,'b':16.0},
                    {'code':'C3','name':'Halo C3','hex':'#C1B595','L':74.5,'a':3.5,'b':19.5},
                    {'code':'C4','name':'Halo C4','hex':'#B1A383','L':68.0,'a':5.0,'b':22.5},
                ]},
                {'title': 'Body D 系列', 'shades': [
                    {'code':'D2','name':'Halo D2','hex':'#D7CDBB','L':83.5,'a':2.2,'b':12.0},
                    {'code':'D3','name':'Halo D3','hex':'#C9BDA3','L':77.5,'a':3.8,'b':16.5},
                    {'code':'D4','name':'Halo D4','hex':'#BBAD8F','L':71.5,'a':5.2,'b':20.5},
                ]},
            ]
        },
        {
            'brand_key': '3m-lava-esthetic', 'brand_name': '3M Lava Esthetic',
            'groups': [
                {'title': 'Fluorescent Zirconia', 'shades': [
                    {'code':'BL1','name':'Lava BL1','hex':'#ECE7DB','L':91.5,'a':-0.8,'b':7.8},
                    {'code':'BL2','name':'Lava BL2','hex':'#E9E3D5','L':90.2,'a':-0.3,'b':9.0},
                    {'code':'A1','name':'Lava A1','hex':'#E6D7C3','L':86.8,'a':2.0,'b':14.2},
                    {'code':'A2','name':'Lava A2','hex':'#DAC9A6','L':81.8,'a':3.5,'b':19.2},
                    {'code':'A3','name':'Lava A3','hex':'#CCBB95','L':76.8,'a':4.8,'b':22.2},
                    {'code':'A3.5','name':'Lava A3.5','hex':'#C2AC83','L':71.8,'a':6.2,'b':25.2},
                    {'code':'B1','name':'Lava B1','hex':'#E5DBC9','L':88.0,'a':0.5,'b':11.8},
                    {'code':'B2','name':'Lava B2','hex':'#DCCFAD','L':83.8,'a':1.5,'b':17.2},
                    {'code':'C1','name':'Lava C1','hex':'#D6CFC1','L':83.8,'a':0.0,'b':10.2},
                    {'code':'C2','name':'Lava C2','hex':'#CCC2AA','L':79.2,'a':1.5,'b':15.2},
                    {'code':'D2','name':'Lava D2','hex':'#D4CBB9','L':82.8,'a':2.0,'b':11.8},
                    {'code':'D3','name':'Lava D3','hex':'#C6BBA1','L':76.8,'a':3.5,'b':16.2},
                ]},
            ]
        },
        {
            'brand_key': 'dentsply-celtra-duo', 'brand_name': 'Dentsply Celtra Duo',
            'groups': [
                {'title': 'HT（高透明）', 'shades': [
                    {'code':'HT A1','name':'Celtra HT A1','hex':'#E7D9C4','L':87.3,'a':1.7,'b':13.5},
                    {'code':'HT A2','name':'Celtra HT A2','hex':'#DBCBA7','L':82.8,'a':3.2,'b':18.2},
                    {'code':'HT A3','name':'Celtra HT A3','hex':'#CDBD95','L':77.3,'a':4.2,'b':21.8},
                    {'code':'HT A3.5','name':'Celtra HT A3.5','hex':'#C3AE84','L':72.3,'a':5.8,'b':24.5},
                    {'code':'HT B1','name':'Celtra HT B1','hex':'#E5DBCA','L':88.0,'a':0.3,'b':11.3},
                    {'code':'HT C2','name':'Celtra HT C2','hex':'#CFC3AB','L':79.8,'a':1.2,'b':14.8},
                    {'code':'HT BL1','name':'Celtra HT BL1','hex':'#EEE7DA','L':92.0,'a':-0.7,'b':7.5},
                    {'code':'HT BL2','name':'Celtra HT BL2','hex':'#EBE3D4','L':90.3,'a':-0.2,'b':9.0},
                ]},
                {'title': 'LT（低透明）', 'shades': [
                    {'code':'LT A1','name':'Celtra LT A1','hex':'#E5D5BF','L':86.3,'a':2.2,'b':14.5},
                    {'code':'LT A2','name':'Celtra LT A2','hex':'#D9C7A3','L':81.3,'a':3.7,'b':19.5},
                    {'code':'LT A3','name':'Celtra LT A3','hex':'#CBB991','L':76.3,'a':5.2,'b':22.8},
                    {'code':'LT A3.5','name':'Celtra LT A3.5','hex':'#C1AB7F','L':71.3,'a':6.7,'b':25.8},
                    {'code':'LT B1','name':'Celtra LT B1','hex':'#E3D9C5','L':87.3,'a':0.7,'b':12.2},
                    {'code':'LT B2','name':'Celtra LT B2','hex':'#DACEAD','L':83.5,'a':1.7,'b':17.0},
                    {'code':'LT C2','name':'Celtra LT C2','hex':'#CDC1A7','L':79.3,'a':1.7,'b':15.5},
                    {'code':'LT D3','name':'Celtra LT D3','hex':'#C5B99D','L':76.3,'a':3.7,'b':16.8},
                ]},
            ]
        },
        {
            'brand_key': 'kuraray-katana-zirconia', 'brand_name': 'Kuraray Katana Zirconia',
            'groups': [
                {'title': 'STML（超高透多層）', 'shades': [
                    {'code':'A1','name':'STML A1','hex':'#E8DAC5','L':87.5,'a':1.8,'b':13.8},
                    {'code':'A2','name':'STML A2','hex':'#DCCCA9','L':82.5,'a':3.3,'b':18.3},
                    {'code':'A3','name':'STML A3','hex':'#CEBE98','L':77.5,'a':4.5,'b':21.5},
                    {'code':'A3.5','name':'STML A3.5','hex':'#C4AF86','L':72.5,'a':5.8,'b':24.5},
                    {'code':'A4','name':'STML A4','hex':'#B8A074','L':66.5,'a':7.2,'b':27.3},
                    {'code':'B1','name':'STML B1','hex':'#E6DCCB','L':88.3,'a':0.3,'b':11.3},
                    {'code':'B2','name':'STML B2','hex':'#DDD0B0','L':84.0,'a':1.3,'b':17.3},
                    {'code':'B3','name':'STML B3','hex':'#D0C29C','L':79.3,'a':2.8,'b':22.0},
                    {'code':'C1','name':'STML C1','hex':'#D8D0C2','L':84.3,'a':-0.2,'b':9.8},
                    {'code':'C2','name':'STML C2','hex':'#CEC3AD','L':79.8,'a':1.3,'b':14.8},
                    {'code':'D2','name':'STML D2','hex':'#D6CCBC','L':83.3,'a':1.8,'b':11.3},
                    {'code':'D3','name':'STML D3','hex':'#C8BCA5','L':77.3,'a':3.3,'b':15.8},
                ]},
                {'title': 'UTML（超高透單層）', 'shades': [
                    {'code':'A1','name':'UTML A1','hex':'#E7D8C4','L':87.0,'a':2.0,'b':14.2},
                    {'code':'A2','name':'UTML A2','hex':'#DBCAA8','L':82.0,'a':3.5,'b':18.8},
                    {'code':'A3','name':'UTML A3','hex':'#CDBC96','L':77.0,'a':4.8,'b':22.0},
                    {'code':'B1','name':'UTML B1','hex':'#E5DBCA','L':88.0,'a':0.5,'b':11.5},
                    {'code':'C1','name':'UTML C1','hex':'#D7CFC1','L':84.0,'a':0.0,'b':10.0},
                    {'code':'D2','name':'UTML D2','hex':'#D5CABB','L':83.0,'a':2.0,'b':11.5},
                ]},
            ]
        },
    ]
    # AI色階指南預設色階系統
    DEFAULT_SHADE_SYSTEMS = [
        {'system_key': 'vita-3d-master', 'system_name': 'VITA 3D-Master', 'codes': [
            '0M1','0M2','0M3','1M1','1M2',
            '2L1.5','2L2.5','2M1','2M2','2M3','2R1.5','2R2.5',
            '3L1.5','3L2.5','3M1','3M2','3M3','3R1.5','3R2.5',
            '4L1.5','4L2.5','4M1','4M2','4M3','4R1.5','4R2.5',
            '5M1','5M2','5M3'
        ]},
        {'system_key': 'vita-classical', 'system_name': 'VITA Classical', 'codes': [
            'BL1','BL2','BL3','BL4',
            'A1','A2','A3','A3.5','A4',
            'B1','B2','B3','B4',
            'C1','C2','C3','C4',
            'D2','D3','D4'
        ]},
        {'system_key': 'natural-die', 'system_name': 'Natural Die Material', 'codes': [
            'ND1','ND2','ND3','ND4','ND5','ND6','ND7','ND8','ND9'
        ]},
    ]

    conn = _get_db()
    try:
        with conn.cursor() as cur:
            # 取得已存在的品牌代碼，支援增量匯入
            cur.execute("SELECT brand_key FROM shade_brands")
            existing_keys = {r['brand_key'] for r in cur.fetchall()}
            new_brands = [b for b in DEFAULT_BRANDS if b['brand_key'] not in existing_keys]
            if not new_brands:
                return jsonify({'ok': False, 'msg': '所有預設色卡品牌皆已存在，無需匯入'}), 409
            # 取得目前最大排序值
            cur.execute("SELECT COALESCE(MAX(sort_order), -1) as max_sort FROM shade_brands")
            base_sort = cur.fetchone()['max_sort'] + 1
            # 匯入品牌
            for idx, brand in enumerate(new_brands):
                cur.execute("INSERT INTO shade_brands (brand_key, brand_name, sort_order) VALUES (%s,%s,%s)",
                            (brand['brand_key'], brand['brand_name'], base_sort + idx))
                brand_id = cur.lastrowid
                for gidx, group in enumerate(brand['groups']):
                    cur.execute("INSERT INTO shade_groups (brand_id, title, sort_order) VALUES (%s,%s,%s)",
                                (brand_id, group['title'], gidx))
                    group_id = cur.lastrowid
                    for sidx, shade in enumerate(group['shades']):
                        cur.execute("""
                            INSERT INTO shades (group_id, code, name, hex_color, lab_l, lab_a, lab_b, sort_order)
                            VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
                        """, (group_id, shade['code'], shade['name'], shade['hex'],
                              shade['L'], shade['a'], shade['b'], sidx))
            # 匯入AI色階系統
            cur.execute("SELECT COUNT(*) as cnt FROM shade_systems")
            if cur.fetchone()['cnt'] == 0:
                for idx, sys in enumerate(DEFAULT_SHADE_SYSTEMS):
                    cur.execute("INSERT INTO shade_systems (system_key, system_name, sort_order) VALUES (%s,%s,%s)",
                                (sys['system_key'], sys['system_name'], idx))
                    sys_id = cur.lastrowid
                    for cidx, code in enumerate(sys['codes']):
                        cur.execute("INSERT INTO shade_system_codes (system_id, code, sort_order) VALUES (%s,%s,%s)",
                                    (sys_id, code, cidx))
        conn.commit()
    finally:
        conn.close()
    return jsonify({'ok': True, 'msg': f'已成功匯入 {len(new_brands)} 個預設色卡品牌'})


# ---------- AI色階系統 管理 API ----------

@app.route('/api/admin/shade-systems')
@admin_required
def admin_list_shade_systems():
    """列出所有色階系統"""
    conn = _get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT s.*, (SELECT COUNT(*) FROM shade_system_codes WHERE system_id=s.id) as code_count
                FROM shade_systems s ORDER BY s.sort_order, s.id
            """)
            systems = cur.fetchall()
            for s in systems:
                s['is_active'] = bool(s.get('is_active', 1))
                if s.get('created_at'):
                    s['created_at'] = s['created_at'].isoformat()
    finally:
        conn.close()
    return jsonify({'ok': True, 'systems': systems})


@app.route('/api/admin/shade-systems', methods=['POST'])
@admin_required
def admin_add_shade_system():
    """新增色階系統"""
    data = request.get_json(silent=True) or {}
    system_key = data.get('system_key', '').strip()
    system_name = data.get('system_name', '').strip()
    codes = data.get('codes', [])
    if not system_key or not system_name:
        return jsonify({'ok': False, 'msg': '系統代碼與名稱不可為空'}), 400
    conn = _get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM shade_systems WHERE system_key=%s", (system_key,))
            if cur.fetchone():
                return jsonify({'ok': False, 'msg': '系統代碼已存在'}), 409
            cur.execute("SELECT COALESCE(MAX(sort_order),0)+1 as n FROM shade_systems")
            sort_order = cur.fetchone()['n']
            cur.execute("INSERT INTO shade_systems (system_key, system_name, sort_order) VALUES (%s,%s,%s)",
                        (system_key, system_name, sort_order))
            sys_id = cur.lastrowid
            for cidx, code in enumerate(codes):
                cur.execute("INSERT INTO shade_system_codes (system_id, code, sort_order) VALUES (%s,%s,%s)",
                            (sys_id, code.strip(), cidx))
        conn.commit()
    finally:
        conn.close()
    return jsonify({'ok': True, 'msg': '色階系統已新增', 'id': sys_id})


@app.route('/api/admin/shade-systems/<int:system_id>', methods=['PUT'])
@admin_required
def admin_update_shade_system(system_id):
    """更新色階系統"""
    data = request.get_json(silent=True) or {}
    conn = _get_db()
    try:
        with conn.cursor() as cur:
            fields, vals = [], []
            for f in ['system_name', 'system_key', 'sort_order']:
                if f in data:
                    fields.append(f"{f}=%s")
                    vals.append(data[f])
            if 'is_active' in data:
                fields.append("is_active=%s")
                vals.append(1 if data['is_active'] else 0)
            if fields:
                vals.append(system_id)
                cur.execute(f"UPDATE shade_systems SET {','.join(fields)} WHERE id=%s", vals)
            # 更新代碼清單（若提供）
            if 'codes' in data:
                cur.execute("DELETE FROM shade_system_codes WHERE system_id=%s", (system_id,))
                for cidx, code in enumerate(data['codes']):
                    cur.execute("INSERT INTO shade_system_codes (system_id, code, sort_order) VALUES (%s,%s,%s)",
                                (system_id, code.strip(), cidx))
        conn.commit()
    finally:
        conn.close()
    return jsonify({'ok': True, 'msg': '色階系統已更新'})


@app.route('/api/admin/shade-systems/<int:system_id>', methods=['DELETE'])
@admin_required
def admin_delete_shade_system(system_id):
    """刪除色階系統"""
    conn = _get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM shade_systems WHERE id=%s", (system_id,))
        conn.commit()
    finally:
        conn.close()
    return jsonify({'ok': True, 'msg': '色階系統已刪除'})


# ---------- 公開 API：前端取色卡資料 ----------

@app.route('/api/shade-brands')
def public_shade_brands():
    """前端取得所有啟用的色卡品牌資料（含完整群組/色階）"""
    conn = _get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id, brand_key, brand_name FROM shade_brands WHERE is_active=1 ORDER BY sort_order, id")
            brands = cur.fetchall()
            result = []
            for b in brands:
                cur.execute("SELECT id, title FROM shade_groups WHERE brand_id=%s ORDER BY sort_order, id", (b['id'],))
                groups = cur.fetchall()
                brand_data = {'id': b['brand_key'], 'name': b['brand_name'], 'groups': []}
                for g in groups:
                    cur.execute("SELECT code, name, hex_color as hex, lab_l as L, lab_a as a, lab_b as b FROM shades WHERE group_id=%s ORDER BY sort_order, id", (g['id'],))
                    shades = cur.fetchall()
                    for s in shades:
                        s['L'] = float(s['L'])
                        s['a'] = float(s['a'])
                        s['b'] = float(s['b'])
                    brand_data['groups'].append({'title': g['title'], 'shades': shades})
                result.append(brand_data)
    finally:
        conn.close()
    return jsonify({'ok': True, 'brands': result})


@app.route('/api/shade-systems')
def public_shade_systems():
    """前端取得所有啟用的色階系統（用於 AI 色階指南）"""
    conn = _get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id, system_key, system_name FROM shade_systems WHERE is_active=1 ORDER BY sort_order, id")
            systems = cur.fetchall()
            result = {}
            for s in systems:
                cur.execute("SELECT code FROM shade_system_codes WHERE system_id=%s ORDER BY sort_order, id", (s['id'],))
                codes = [r['code'] for r in cur.fetchall()]
                result[s['system_key']] = {'name': s['system_name'], 'codes': codes}
    finally:
        conn.close()
    return jsonify({'ok': True, 'systems': result})


@app.route('/api/auth/password', methods=['PUT'])
@login_required
def change_password():
    """變更密碼"""
    data = request.get_json(silent=True) or {}
    current_password = data.get('current_password', '')
    new_password = data.get('new_password', '')

    if not current_password or not new_password:
        return jsonify({'ok': False, 'msg': '請輸入目前密碼和新密碼'}), 400

    if len(new_password) < 8:
        return jsonify({'ok': False, 'msg': '新密碼至少需要 8 個字元'}), 400

    import re
    if not re.search(r'[a-zA-Z]', new_password):
        return jsonify({'ok': False, 'msg': '新密碼必須包含至少一個英文字母'}), 400
    if not re.search(r'[0-9]', new_password):
        return jsonify({'ok': False, 'msg': '新密碼必須包含至少一個數字'}), 400

    conn = _get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT salt, password_hash FROM users WHERE username = %s", (session['user'],))
            user = cur.fetchone()
            if not user:
                return jsonify({'ok': False, 'msg': '使用者不存在'}), 404

            _, current_hashed = _hash_password(current_password, user['salt'])
            if current_hashed != user['password_hash']:
                return jsonify({'ok': False, 'msg': '目前密碼錯誤'}), 401

            new_salt, new_hashed = _hash_password(new_password)
            cur.execute("UPDATE users SET password_hash=%s, salt=%s WHERE username=%s",
                        (new_hashed, new_salt, session['user']))
        conn.commit()
    finally:
        conn.close()

    return jsonify({'ok': True, 'msg': '密碼變更成功'})


# ---------- 忘記密碼 / 密碼重設 API ----------

def _send_reset_email(to_email, to_name, reset_link, token_code):
    """透過 SMTP 寄送密碼重設信件"""
    import smtplib
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart

    smtp_host = _get_setting('smtp_host', '')
    smtp_port = int(_get_setting('smtp_port', '587') or '587')
    smtp_user = _get_setting('smtp_user', '')
    smtp_password = _get_setting('smtp_password', '')
    sender_name = _get_setting('smtp_sender_name', 'Idensol Chroma')
    use_tls = _get_setting('smtp_use_tls', '1') == '1'

    if not smtp_host or not smtp_user:
        return False, 'SMTP 尚未設定，無法發送郵件'

    html_body = f"""
    <div style="max-width:520px;margin:0 auto;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;color:#1e293b;">
      <div style="text-align:center;padding:32px 0 16px;">
        <span style="font-size:48px;">🦷</span>
        <h2 style="margin:12px 0 4px;font-size:22px;font-weight:700;">{sender_name}</h2>
        <p style="color:#64748b;font-size:14px;margin:0;">密碼重設通知</p>
      </div>
      <div style="background:#ffffff;border:1px solid #e2e8f0;border-radius:12px;padding:28px 24px;margin:0 12px;">
        <p style="font-size:15px;line-height:1.6;">您好 <strong>{to_name}</strong>，</p>
        <p style="font-size:14px;line-height:1.6;color:#475569;">
          我們收到了您的密碼重設請求。請點擊下方按鈕來設定新密碼：
        </p>
        <div style="text-align:center;margin:28px 0;">
          <a href="{reset_link}" style="display:inline-block;padding:12px 36px;background:linear-gradient(135deg,#2563eb,#1d4ed8);color:#fff;font-size:15px;font-weight:600;text-decoration:none;border-radius:10px;">
            重設密碼
          </a>
        </div>
        <p style="font-size:13px;color:#64748b;text-align:center;">
          或者手動輸入驗證碼：<strong style="font-size:16px;letter-spacing:2px;color:#2563eb;">{token_code}</strong>
        </p>
        <hr style="border:none;border-top:1px solid #e2e8f0;margin:20px 0;">
        <p style="font-size:12px;color:#94a3b8;line-height:1.5;">
          ⏰ 此連結將在 {_get_setting('password_reset_expiry_minutes', '30')} 分鐘後失效。<br>
          如果您並未發出此請求，請忽略此封郵件，您的帳號不會受到任何影響。
        </p>
      </div>
      <p style="text-align:center;font-size:11px;color:#94a3b8;margin-top:20px;">
        {sender_name} © {datetime.now().year}
      </p>
    </div>
    """

    msg = MIMEMultipart('alternative')
    msg['Subject'] = f'【{sender_name}】密碼重設驗證'
    msg['From'] = f'{sender_name} <{smtp_user}>'
    msg['To'] = to_email
    msg.attach(MIMEText(html_body, 'html', 'utf-8'))

    try:
        if use_tls:
            server = smtplib.SMTP(smtp_host, smtp_port, timeout=15)
            server.ehlo()
            server.starttls()
        else:
            server = smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=15)
        server.login(smtp_user, smtp_password)
        server.sendmail(smtp_user, [to_email], msg.as_string())
        server.quit()
        return True, '郵件已發送'
    except Exception as e:
        print(f'[ERROR] SMTP 發送失敗: {e}')
        return False, f'郵件發送失敗：{str(e)}'


@app.route('/api/auth/forgot-password', methods=['POST'])
def forgot_password():
    """忘記密碼 — 產生重設 token 並寄送郵件"""
    data = request.get_json(silent=True) or {}
    identifier = data.get('identifier', '').strip()  # 帳號或 email
    captcha_input = data.get('captcha', '').strip().upper()

    if not identifier:
        return jsonify({'ok': False, 'msg': '請輸入帳號或電子郵件'}), 400

    # --- 驗證碼檢查 ---
    captcha_answer = session.get('captcha', '')
    captcha_time = session.get('captcha_time', '')
    session.pop('captcha', None)
    session.pop('captcha_time', None)

    if not captcha_input or captcha_input != captcha_answer:
        return jsonify({'ok': False, 'msg': '驗證碼錯誤，請重新輸入'}), 400
    if captcha_time:
        try:
            ct = datetime.fromisoformat(captcha_time)
            if (datetime.utcnow() - ct).total_seconds() > 300:
                return jsonify({'ok': False, 'msg': '驗證碼已過期，請重新取得'}), 400
        except Exception:
            pass

    # 查找使用者（支援帳號或 email）
    conn = _get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, username, display_name, email FROM users WHERE username = %s OR (email = %s AND email != '')",
                (identifier, identifier)
            )
            user = cur.fetchone()
    finally:
        conn.close()

    if not user or not user.get('email'):
        # 即使找不到也回傳成功，避免帳號列舉攻擊
        return jsonify({
            'ok': True,
            'msg': '若該帳號存在且有綁定電子郵件，重設信件已發送至您的信箱。',
            'email_sent': False,
        })

    # 產生重設 token（6 位數字驗證碼 + URL token）
    token_code = ''.join(random.choices('0123456789', k=6))
    url_token = secrets.token_urlsafe(48)
    try:
        expiry_minutes = int(_get_setting('password_reset_expiry_minutes', '30'))
    except (TypeError, ValueError):
        expiry_minutes = 30
    expires_at = datetime.utcnow() + timedelta(minutes=expiry_minutes)

    conn = _get_db()
    try:
        with conn.cursor() as cur:
            # 失效該使用者所有舊 token
            cur.execute("UPDATE password_reset_tokens SET used = 1 WHERE user_id = %s AND used = 0", (user['id'],))
            # 儲存新 token（存 url_token + token_code 的組合）
            combined_token = f"{url_token}:{token_code}"
            cur.execute(
                "INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES (%s, %s, %s)",
                (user['id'], combined_token, expires_at)
            )
        conn.commit()
    finally:
        conn.close()

    # 組合重設連結
    host = request.headers.get('X-Forwarded-Host') or request.headers.get('Host') or 'localhost:5000'
    scheme = request.headers.get('X-Forwarded-Proto') or request.scheme
    reset_link = f"{scheme}://{host}/reset-password?token={url_token}"

    # 嘗試寄送郵件
    masked_email = user['email']
    at_idx = masked_email.index('@')
    if at_idx > 2:
        masked_email = masked_email[0] + '*' * (at_idx - 2) + masked_email[at_idx - 1:]
    else:
        masked_email = masked_email[0] + '*' * (at_idx - 1) + masked_email[at_idx:]

    email_ok, email_msg = _send_reset_email(
        user['email'],
        user.get('display_name') or user['username'],
        reset_link,
        token_code,
    )

    if email_ok:
        return jsonify({
            'ok': True,
            'msg': f'密碼重設信件已發送至 {masked_email}，請查看信箱。',
            'email_sent': True,
        })
    else:
        # SMTP 未設定或發送失敗 — 直接回傳驗證碼（方便開發/無 SMTP 環境）
        return jsonify({
            'ok': True,
            'msg': f'郵件發送失敗（{email_msg}）。請聯繫管理員協助重設密碼。',
            'email_sent': False,
            'fallback_token': token_code,
            'fallback_url_token': url_token,
        })


@app.route('/api/auth/verify-reset-token', methods=['POST'])
def verify_reset_token():
    """驗證重設 token 是否有效"""
    data = request.get_json(silent=True) or {}
    url_token = data.get('token', '').strip()
    code = data.get('code', '').strip()

    if not url_token and not code:
        return jsonify({'ok': False, 'msg': '缺少驗證資訊'}), 400

    conn = _get_db()
    try:
        with conn.cursor() as cur:
            if url_token:
                cur.execute(
                    "SELECT * FROM password_reset_tokens WHERE token LIKE %s AND used = 0 AND expires_at > UTC_TIMESTAMP()",
                    (f"{url_token}:%",)
                )
            else:
                cur.execute(
                    "SELECT * FROM password_reset_tokens WHERE token LIKE %s AND used = 0 AND expires_at > UTC_TIMESTAMP()",
                    (f"%:{code}",)
                )
            row = cur.fetchone()
    finally:
        conn.close()

    if not row:
        return jsonify({'ok': False, 'msg': '驗證碼無效或已過期，請重新申請'}), 400

    # 回傳必要資訊
    stored_token = row['token']
    parts = stored_token.split(':', 1)
    return jsonify({
        'ok': True,
        'url_token': parts[0] if len(parts) == 2 else '',
        'msg': '驗證成功',
    })


@app.route('/api/auth/reset-password', methods=['POST'])
def reset_password():
    """使用 token 重設密碼"""
    data = request.get_json(silent=True) or {}
    url_token = data.get('token', '').strip()
    code = data.get('code', '').strip()
    new_password = data.get('new_password', '').strip()

    if not url_token and not code:
        return jsonify({'ok': False, 'msg': '缺少驗證資訊'}), 400
    if not new_password:
        return jsonify({'ok': False, 'msg': '請輸入新密碼'}), 400
    if len(new_password) < 8:
        return jsonify({'ok': False, 'msg': '新密碼至少需要 8 個字元'}), 400

    import re
    if not re.search(r'[a-zA-Z]', new_password):
        return jsonify({'ok': False, 'msg': '新密碼必須包含至少一個英文字母'}), 400
    if not re.search(r'[0-9]', new_password):
        return jsonify({'ok': False, 'msg': '新密碼必須包含至少一個數字'}), 400

    conn = _get_db()
    try:
        with conn.cursor() as cur:
            # 查找有效的 token
            if url_token and code:
                cur.execute(
                    "SELECT * FROM password_reset_tokens WHERE token = %s AND used = 0 AND expires_at > UTC_TIMESTAMP()",
                    (f"{url_token}:{code}",)
                )
            elif url_token:
                cur.execute(
                    "SELECT * FROM password_reset_tokens WHERE token LIKE %s AND used = 0 AND expires_at > UTC_TIMESTAMP()",
                    (f"{url_token}:%",)
                )
            else:
                cur.execute(
                    "SELECT * FROM password_reset_tokens WHERE token LIKE %s AND used = 0 AND expires_at > UTC_TIMESTAMP()",
                    (f"%:{code}",)
                )
            token_row = cur.fetchone()

            if not token_row:
                return jsonify({'ok': False, 'msg': '驗證碼無效或已過期，請重新申請'}), 400

            # 更新密碼
            new_salt, new_hashed = _hash_password(new_password)
            cur.execute(
                "UPDATE users SET password_hash = %s, salt = %s WHERE id = %s",
                (new_hashed, new_salt, token_row['user_id'])
            )
            # 標記 token 已使用
            cur.execute(
                "UPDATE password_reset_tokens SET used = 1 WHERE id = %s",
                (token_row['id'],)
            )
            # 同時失效該使用者所有其他 token
            cur.execute(
                "UPDATE password_reset_tokens SET used = 1 WHERE user_id = %s",
                (token_row['user_id'],)
            )
        conn.commit()
    finally:
        conn.close()

    return jsonify({'ok': True, 'msg': '密碼重設成功！請使用新密碼登入。'})


# ---------- 專案 API ----------

def _row_to_project(row):
    """將 DB row 轉為前端格式"""
    shared = row.get('shared_with')
    if isinstance(shared, str):
        try: shared = json.loads(shared)
        except: shared = []
    return {
        'id': row['id'],
        'name': row['name'],
        'status': row['status'] or 'active',
        'dentist': row['dentist'],
        'description': row['description'],
        'sharedWith': shared or [],
        'ownerUsername': row.get('owner_username', ''),
        'thumbnail': row['thumbnail'],
        'createdAt': row['created_at'].isoformat() if row['created_at'] else None,
        'modifiedAt': row['modified_at'].isoformat() if row['modified_at'] else None,
        'deletedAt': row['deleted_at'].isoformat() if row.get('deleted_at') else None,
        'images': [],
    }


def _check_project_access(cur, project_id, user):
    """檢查使用者對專案的存取權限。回傳 (row, permission)。
    permission: 'owner' | 'edit' | 'view' | None
    """
    cur.execute("SELECT * FROM projects WHERE id=%s AND owner_username=%s", (project_id, user))
    row = cur.fetchone()
    if row:
        return row, 'owner'
    # 嘗試被分享者
    cur.execute(
        """SELECT * FROM projects WHERE id=%s AND deleted_at IS NULL
           AND (JSON_CONTAINS(shared_with, JSON_OBJECT('username', %s))
                OR JSON_CONTAINS(shared_with, JSON_QUOTE(%s)))""",
        (project_id, user, user)
    )
    row = cur.fetchone()
    if not row:
        return None, None
    # 解析 shared_with 取得此使用者的權限
    shared = row.get('shared_with')
    if isinstance(shared, str):
        try: shared = json.loads(shared)
        except: shared = []
    permission = 'view'
    for s in (shared or []):
        if isinstance(s, dict) and s.get('username') == user:
            permission = s.get('permission', 'view')
            break
    return row, permission

def _row_to_image(row):
    return {
        'id': row['id'],
        'filename': row['filename'],
        'thumbnail': row['thumbnail'],
        'uploadedAt': row['uploaded_at'].isoformat() if row['uploaded_at'] else None,
    }

def _row_to_image_lite(row):
    """不含 thumbnail base64，用於列表"""
    return {
        'id': row['id'],
        'filename': row['filename'],
        'uploadedAt': row['uploaded_at'].isoformat() if row['uploaded_at'] else None,
    }


@app.route('/api/projects', methods=['GET'])
@login_required
def list_projects():
    """取得目前使用者的專案列表（不含已刪除）"""
    user = session['user']
    conn = _get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT * FROM projects WHERE owner_username=%s AND deleted_at IS NULL ORDER BY modified_at DESC",
                (user,)
            )
            rows = cur.fetchall()
            projects = []
            for r in rows:
                p = _row_to_project(r)
                cur.execute("SELECT id, project_id, filename, uploaded_at FROM project_images WHERE project_id=%s ORDER BY uploaded_at DESC", (r['id'],))
                p['images'] = [_row_to_image_lite(img) for img in cur.fetchall()]
                # 若專案沒有縮圖，自動用第一張圖片的 thumbnail
                if not p['thumbnail'] and p['images']:
                    cur.execute("SELECT thumbnail FROM project_images WHERE project_id=%s ORDER BY uploaded_at DESC LIMIT 1", (r['id'],))
                    first = cur.fetchone()
                    if first:
                        p['thumbnail'] = first['thumbnail']
                projects.append(p)
        return jsonify(projects)
    finally:
        conn.close()


@app.route('/api/projects/trash', methods=['GET'])
@login_required
def list_trash():
    """取得回收站專案"""
    user = session['user']
    conn = _get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT * FROM projects WHERE owner_username=%s AND deleted_at IS NOT NULL ORDER BY deleted_at DESC",
                (user,)
            )
            rows = cur.fetchall()
            projects = []
            for r in rows:
                p = _row_to_project(r)
                cur.execute("SELECT id, project_id, filename, uploaded_at FROM project_images WHERE project_id=%s", (r['id'],))
                p['images'] = [_row_to_image_lite(img) for img in cur.fetchall()]
                projects.append(p)
        return jsonify(projects)
    finally:
        conn.close()


@app.route('/api/projects/<int:project_id>', methods=['GET'])
@login_required
def get_project(project_id):
    """取得單一專案（擁有者或被分享者皆可存取）"""
    user = session['user']
    conn = _get_db()
    try:
        with conn.cursor() as cur:
            row, permission = _check_project_access(cur, project_id, user)
            if not row:
                return jsonify({'ok': False, 'msg': '專案不存在'}), 404
            p = _row_to_project(row)
            p['myPermission'] = permission
            cur.execute("SELECT * FROM project_images WHERE project_id=%s ORDER BY uploaded_at DESC", (project_id,))
            p['images'] = [_row_to_image(img) for img in cur.fetchall()]
        return jsonify(p)
    finally:
        conn.close()


@app.route('/api/projects', methods=['POST'])
@login_required
def create_project():
    """建立專案"""
    user = session['user']
    # 檢查每人最大專案數限制
    try:
        max_proj = int(_get_setting('max_projects_per_user', '0'))
    except (TypeError, ValueError):
        max_proj = 0
    if max_proj > 0:
        conn2 = _get_db()
        try:
            with conn2.cursor() as cur2:
                cur2.execute("SELECT COUNT(*) as cnt FROM projects WHERE owner_username=%s", (user,))
                if cur2.fetchone()['cnt'] >= max_proj:
                    return jsonify({'ok': False, 'msg': f'已達專案上限（{max_proj}）'}), 403
        finally:
            conn2.close()
    data = request.get_json(silent=True) or {}
    pid = data.get('id') or int(datetime.now().timestamp() * 1000)
    name = data.get('name', '未命名專案')
    conn = _get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO projects (id, owner_username, name, status, dentist, description, shared_with, thumbnail, created_at, modified_at)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                (pid, user, name,
                 data.get('status', 'active'),
                 data.get('dentist'),
                 data.get('description', ''),
                 json.dumps(data.get('sharedWith', [])),
                 data.get('thumbnail'),
                 data.get('createdAt', datetime.now().isoformat()),
                 data.get('modifiedAt', datetime.now().isoformat()))
            )
            # 如果帶有 images
            for img in data.get('images', []):
                img_id = img.get('id') or int(datetime.now().timestamp() * 1000)
                cur.execute(
                    "INSERT INTO project_images (id, project_id, filename, thumbnail, uploaded_at) VALUES (%s,%s,%s,%s,%s)",
                    (img_id, pid, img.get('filename', ''), img.get('thumbnail'), img.get('uploadedAt', datetime.now().isoformat()))
                )
        conn.commit()
        return jsonify({'ok': True, 'id': pid})
    finally:
        conn.close()


@app.route('/api/projects/<int:project_id>/duplicate', methods=['POST'])
@login_required
def duplicate_project(project_id):
    """複製專案（含圖片）"""
    user = session['user']
    # 檢查每人最大專案數限制
    try:
        max_proj = int(_get_setting('max_projects_per_user', '0'))
    except (TypeError, ValueError):
        max_proj = 0
    conn = _get_db()
    try:
        with conn.cursor() as cur:
            if max_proj > 0:
                cur.execute("SELECT COUNT(*) as cnt FROM projects WHERE owner_username=%s AND deleted_at IS NULL", (user,))
                if cur.fetchone()['cnt'] >= max_proj:
                    return jsonify({'ok': False, 'msg': f'已達專案上限（{max_proj}）'}), 403

            # 取得原專案
            row, permission = _check_project_access(cur, project_id, user)
            if not row:
                return jsonify({'ok': False, 'msg': '專案不存在'}), 404

            now = datetime.now()
            new_pid = int(now.timestamp() * 1000)
            new_name = (row['name'] or '未命名專案') + ' (副本)'

            # 複製專案
            cur.execute(
                """INSERT INTO projects (id, owner_username, name, status, dentist, description, shared_with, thumbnail, created_at, modified_at)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                (new_pid, user, new_name,
                 row['status'] or 'active',
                 row['dentist'],
                 row['description'] or '',
                 json.dumps([]),
                 row['thumbnail'],
                 now.isoformat(),
                 now.isoformat())
            )

            # 用 SQL 直接複製圖片，避免將大量 thumbnail base64 資料拉到應用層
            # 先取得原專案的圖片 id 列表（不含 thumbnail 資料）
            cur.execute("SELECT id FROM project_images WHERE project_id=%s ORDER BY id", (project_id,))
            img_rows = cur.fetchall()
            for i, img_row in enumerate(img_rows):
                new_img_id = new_pid * 100 + i + 1  # 確保不與其他 id 衝突
                cur.execute(
                    """INSERT INTO project_images (id, project_id, filename, thumbnail, uploaded_at)
                       SELECT %s, %s, filename, thumbnail, %s
                       FROM project_images WHERE id=%s""",
                    (new_img_id, new_pid, now.isoformat(), img_row['id'])
                )

        conn.commit()
        return jsonify({'ok': True, 'id': new_pid, 'name': new_name})
    except Exception as e:
        conn.rollback()
        app.logger.error(f'複製專案失敗: {e}')
        return jsonify({'ok': False, 'msg': '複製專案失敗'}), 500
    finally:
        conn.close()


@app.route('/api/projects/<int:project_id>', methods=['PUT'])
@login_required
def update_project(project_id):
    """更新專案（完整覆蓋）"""
    user = session['user']
    data = request.get_json(silent=True) or {}
    if not data:
        return jsonify({'ok': False, 'msg': '無效的請求資料'}), 400
    conn = _get_db()
    try:
        with conn.cursor() as cur:
            row, permission = _check_project_access(cur, project_id, user)
            if not row:
                return jsonify({'ok': False, 'msg': '專案不存在'}), 404
            if permission == 'view':
                return jsonify({'ok': False, 'msg': '您只有檢視權限，無法編輯此專案'}), 403

            # 非擁有者不可修改 shared_with
            shared_with_value = json.dumps(data.get('sharedWith', []))
            if permission != 'owner':
                shared_with_value = row.get('shared_with') if isinstance(row.get('shared_with'), str) else json.dumps(row.get('shared_with') or [])

            cur.execute(
                """UPDATE projects SET name=%s, status=%s, dentist=%s, description=%s,
                   shared_with=%s, thumbnail=%s, modified_at=%s WHERE id=%s""",
                (data.get('name', ''), data.get('status', 'active'), data.get('dentist'),
                 data.get('description', ''), shared_with_value,
                 data.get('thumbnail'), datetime.now().isoformat(), project_id)
            )

            # 同步 images：刪除舊的，插入新的
            if 'images' in data:
                cur.execute("DELETE FROM project_images WHERE project_id=%s", (project_id,))
                for img in data['images']:
                    img_id = img.get('id') or int(datetime.now().timestamp() * 1000)
                    cur.execute(
                        "INSERT INTO project_images (id, project_id, filename, thumbnail, uploaded_at) VALUES (%s,%s,%s,%s,%s)",
                        (img_id, project_id, img.get('filename', ''), img.get('thumbnail'),
                         img.get('uploadedAt', datetime.now().isoformat()))
                    )
        conn.commit()
        return jsonify({'ok': True})
    except Exception as e:
        conn.rollback()
        app.logger.error('update_project error: %s', e)
        return jsonify({'ok': False, 'msg': '儲存失敗，請稍後再試'}), 500
    finally:
        conn.close()


@app.route('/api/projects/<int:project_id>', methods=['DELETE'])
@login_required
def soft_delete_project(project_id):
    """軟刪除（移至回收站）"""
    user = session['user']
    conn = _get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE projects SET deleted_at=%s WHERE id=%s AND owner_username=%s",
                (datetime.now().isoformat(), project_id, user)
            )
        conn.commit()
        return jsonify({'ok': True})
    finally:
        conn.close()


@app.route('/api/projects/<int:project_id>/restore', methods=['POST'])
@login_required
def restore_project(project_id):
    """從回收站恢復"""
    user = session['user']
    conn = _get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE projects SET deleted_at=NULL, modified_at=%s WHERE id=%s AND owner_username=%s",
                (datetime.now().isoformat(), project_id, user)
            )
        conn.commit()
        return jsonify({'ok': True})
    finally:
        conn.close()


@app.route('/api/projects/<int:project_id>/permanent', methods=['DELETE'])
@login_required
def permanent_delete_project(project_id):
    """永久刪除"""
    user = session['user']
    conn = _get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM project_images WHERE project_id=%s", (project_id,))
            cur.execute("DELETE FROM cd_markers WHERE project_id=%s", (project_id,))
            cur.execute("DELETE FROM cs_sessions WHERE project_id=%s", (project_id,))
            cur.execute("DELETE FROM projects WHERE id=%s AND owner_username=%s", (project_id, user))
        conn.commit()
        return jsonify({'ok': True})
    finally:
        conn.close()


@app.route('/api/projects/trash', methods=['DELETE'])
@login_required
def empty_trash():
    """清空回收站"""
    user = session['user']
    conn = _get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id FROM projects WHERE owner_username=%s AND deleted_at IS NOT NULL", (user,)
            )
            ids = [r['id'] for r in cur.fetchall()]
            if ids:
                fmt = ','.join(['%s'] * len(ids))
                cur.execute(f"DELETE FROM project_images WHERE project_id IN ({fmt})", ids)
                cur.execute(f"DELETE FROM cd_markers WHERE project_id IN ({fmt})", ids)
                cur.execute(f"DELETE FROM cs_sessions WHERE project_id IN ({fmt})", ids)
                cur.execute(f"DELETE FROM projects WHERE id IN ({fmt})", ids)
        conn.commit()
        return jsonify({'ok': True})
    finally:
        conn.close()


# ---------- 圖片 API ----------

@app.route('/api/projects/<int:project_id>/images/<int:image_id>/move', methods=['POST'])
@login_required
def move_image(project_id, image_id):
    """將圖片移動到另一個專案"""
    user = session['user']
    data = request.get_json(silent=True) or {}
    target_id = data.get('targetProjectId')
    if not target_id:
        return jsonify({'ok': False, 'msg': '缺少目標專案 ID'}), 400
    conn = _get_db()
    try:
        with conn.cursor() as cur:
            # 確認兩個專案都屬於此使用者
            cur.execute("SELECT id FROM projects WHERE id=%s AND owner_username=%s", (project_id, user))
            if not cur.fetchone():
                return jsonify({'ok': False, 'msg': '來源專案不存在'}), 404
            cur.execute("SELECT id FROM projects WHERE id=%s AND owner_username=%s", (target_id, user))
            if not cur.fetchone():
                return jsonify({'ok': False, 'msg': '目標專案不存在'}), 404
            # 移動
            cur.execute("UPDATE project_images SET project_id=%s WHERE id=%s AND project_id=%s", (target_id, image_id, project_id))
            # 更新兩個專案的 modified_at
            now = datetime.now().isoformat()
            cur.execute("UPDATE projects SET modified_at=%s WHERE id=%s", (now, project_id))
            cur.execute("UPDATE projects SET modified_at=%s WHERE id=%s", (now, target_id))
        conn.commit()
        return jsonify({'ok': True})
    finally:
        conn.close()


# ---------- 標記 API ----------

@app.route('/api/projects/<int:project_id>/markers', methods=['GET'])
@login_required
def get_markers(project_id):
    user = session['user']
    conn = _get_db()
    try:
        with conn.cursor() as cur:
            row, permission = _check_project_access(cur, project_id, user)
            if not row:
                return jsonify({'ok': False, 'msg': '專案不存在'}), 404
            cur.execute("SELECT data FROM cd_markers WHERE project_id=%s", (project_id,))
            row = cur.fetchone()
            if row and row['data']:
                d = row['data']
                if isinstance(d, str):
                    d = json.loads(d)
                return jsonify(d)
        return jsonify(None)
    finally:
        conn.close()


@app.route('/api/projects/<int:project_id>/markers', methods=['PUT'])
@login_required
def save_markers(project_id):
    user = session['user']
    data = request.get_json(silent=True)
    conn = _get_db()
    try:
        with conn.cursor() as cur:
            row, permission = _check_project_access(cur, project_id, user)
            if not row:
                return jsonify({'ok': False, 'msg': '專案不存在'}), 404
            if permission == 'view':
                return jsonify({'ok': False, 'msg': '您只有檢視權限，無法編輯標記'}), 403
            cur.execute(
                "INSERT INTO cd_markers (project_id, data) VALUES (%s, %s) ON DUPLICATE KEY UPDATE data=%s",
                (project_id, json.dumps(data), json.dumps(data))
            )
        conn.commit()
        return jsonify({'ok': True})
    finally:
        conn.close()


# ---------- 陶瓷工作室工作階段 API ----------

@app.route('/api/projects/<int:project_id>/cs-session', methods=['GET'])
@login_required
def get_cs_session(project_id):
    user = session['user']
    conn = _get_db()
    try:
        with conn.cursor() as cur:
            row, permission = _check_project_access(cur, project_id, user)
            if not row:
                return jsonify({'ok': False, 'msg': '專案不存在'}), 404
            cur.execute("SELECT data FROM cs_sessions WHERE project_id=%s", (project_id,))
            row = cur.fetchone()
            if row and row['data']:
                d = row['data']
                if isinstance(d, str):
                    d = json.loads(d)
                return jsonify(d)
        return jsonify(None)
    finally:
        conn.close()


@app.route('/api/projects/<int:project_id>/cs-session', methods=['PUT'])
@login_required
def save_cs_session(project_id):
    user = session['user']
    data = request.get_json(silent=True)
    conn = _get_db()
    try:
        with conn.cursor() as cur:
            row, permission = _check_project_access(cur, project_id, user)
            if not row:
                return jsonify({'ok': False, 'msg': '專案不存在'}), 404
            if permission == 'view':
                return jsonify({'ok': False, 'msg': '您只有檢視權限，無法編輯工作階段'}), 403
            cur.execute(
                "INSERT INTO cs_sessions (project_id, data) VALUES (%s, %s) ON DUPLICATE KEY UPDATE data=%s",
                (project_id, json.dumps(data), json.dumps(data))
            )
        conn.commit()
        return jsonify({'ok': True})
    finally:
        conn.close()


# ---------- 分享 API ----------

@app.route('/api/users/search')
@login_required
def search_users():
    """搜尋使用者（用於分享功能）"""
    q = request.args.get('q', '').strip()
    if len(q) < 1:
        return jsonify([])

    current_user = session['user']
    conn = _get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """SELECT username, display_name, role, clinic_name
                   FROM users
                   WHERE (username LIKE %s OR display_name LIKE %s)
                     AND username != %s
                   LIMIT 10""",
                (f'%{q}%', f'%{q}%', current_user)
            )
            rows = cur.fetchall()
        return jsonify([{
            'username': r['username'],
            'display_name': r['display_name'] or r['username'],
            'role': r.get('role', ''),
            'clinic_name': r.get('clinic_name', ''),
        } for r in rows])
    finally:
        conn.close()


@app.route('/api/projects/<int:project_id>/share', methods=['GET'])
@login_required
def get_share_list(project_id):
    """取得專案的分享清單"""
    user = session['user']
    conn = _get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT shared_with FROM projects WHERE id=%s AND owner_username=%s", (project_id, user))
            row = cur.fetchone()
            if not row:
                return jsonify({'ok': False, 'msg': '專案不存在'}), 404
            shared = row.get('shared_with')
            if isinstance(shared, str):
                try:
                    shared = json.loads(shared)
                except Exception:
                    shared = []
        return jsonify({'ok': True, 'shared_with': shared or []})
    finally:
        conn.close()


@app.route('/api/projects/<int:project_id>/share', methods=['POST'])
@login_required
def share_project(project_id):
    """分享專案給指定使用者"""
    user = session['user']
    data = request.get_json(silent=True) or {}
    target_username = data.get('username', '').strip()
    permission = data.get('permission', 'view')  # view / edit

    if not target_username:
        return jsonify({'ok': False, 'msg': '請指定分享對象'}), 400

    if target_username == user:
        return jsonify({'ok': False, 'msg': '不能分享給自己'}), 400

    if permission not in ('view', 'edit'):
        return jsonify({'ok': False, 'msg': '無效的權限設定'}), 400

    conn = _get_db()
    try:
        with conn.cursor() as cur:
            # 確認專案存在且屬於當前使用者
            cur.execute("SELECT shared_with FROM projects WHERE id=%s AND owner_username=%s", (project_id, user))
            row = cur.fetchone()
            if not row:
                return jsonify({'ok': False, 'msg': '專案不存在'}), 404

            # 確認目標使用者存在
            cur.execute("SELECT username, display_name, role, clinic_name FROM users WHERE username=%s", (target_username,))
            target_user = cur.fetchone()
            if not target_user:
                return jsonify({'ok': False, 'msg': '找不到此使用者'}), 404

            # 解析原有分享清單
            shared = row.get('shared_with')
            if isinstance(shared, str):
                try:
                    shared = json.loads(shared)
                except Exception:
                    shared = []
            shared = shared or []

            # 檢查是否已分享
            existing_idx = None
            for i, s in enumerate(shared):
                if isinstance(s, dict) and s.get('username') == target_username:
                    existing_idx = i
                    break
                elif isinstance(s, str) and s == target_username:
                    existing_idx = i
                    break

            new_entry = {
                'username': target_username,
                'display_name': target_user['display_name'] or target_username,
                'role': target_user.get('role', ''),
                'permission': permission,
            }

            if existing_idx is not None:
                shared[existing_idx] = new_entry
            else:
                shared.append(new_entry)

            # 更新資料庫
            cur.execute("UPDATE projects SET shared_with=%s, modified_at=%s WHERE id=%s",
                        (json.dumps(shared), datetime.now().isoformat(), project_id))
        conn.commit()
        return jsonify({'ok': True, 'shared_with': shared, 'msg': f'已分享給 {target_user["display_name"] or target_username}'})
    finally:
        conn.close()


@app.route('/api/projects/<int:project_id>/share/<username>', methods=['DELETE'])
@login_required
def unshare_project(project_id, username):
    """取消分享"""
    user = session['user']
    conn = _get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT shared_with FROM projects WHERE id=%s AND owner_username=%s", (project_id, user))
            row = cur.fetchone()
            if not row:
                return jsonify({'ok': False, 'msg': '專案不存在'}), 404

            shared = row.get('shared_with')
            if isinstance(shared, str):
                try:
                    shared = json.loads(shared)
                except Exception:
                    shared = []
            shared = shared or []

            # 過濾掉指定使用者
            new_shared = []
            for s in shared:
                if isinstance(s, dict) and s.get('username') == username:
                    continue
                elif isinstance(s, str) and s == username:
                    continue
                new_shared.append(s)

            cur.execute("UPDATE projects SET shared_with=%s, modified_at=%s WHERE id=%s",
                        (json.dumps(new_shared), datetime.now().isoformat(), project_id))
        conn.commit()
        return jsonify({'ok': True, 'shared_with': new_shared, 'msg': '已取消分享'})
    finally:
        conn.close()


@app.route('/api/projects/shared', methods=['GET'])
@login_required
def list_shared_projects():
    """取得其他人分享給我的專案"""
    user = session['user']
    conn = _get_db()
    try:
        with conn.cursor() as cur:
            # 搜尋 shared_with JSON 中包含目前使用者的專案
            cur.execute(
                """SELECT p.*, u.display_name as owner_display_name
                   FROM projects p
                   LEFT JOIN users u ON u.username = p.owner_username
                   WHERE p.deleted_at IS NULL
                     AND p.owner_username != %s
                     AND (
                       JSON_CONTAINS(p.shared_with, JSON_OBJECT('username', %s))
                       OR JSON_CONTAINS(p.shared_with, JSON_QUOTE(%s))
                     )
                   ORDER BY p.modified_at DESC""",
                (user, user, user)
            )
            rows = cur.fetchall()
            projects = []
            for r in rows:
                p = _row_to_project(r)
                p['owner'] = r.get('owner_display_name') or r['owner_username']
                p['ownerUsername'] = r['owner_username']
                # 取得我的權限
                shared = p.get('sharedWith') or []
                my_permission = 'view'
                for s in shared:
                    if isinstance(s, dict) and s.get('username') == user:
                        my_permission = s.get('permission', 'view')
                        break
                p['myPermission'] = my_permission
                cur.execute("SELECT id, project_id, filename, uploaded_at FROM project_images WHERE project_id=%s ORDER BY uploaded_at DESC", (r['id'],))
                p['images'] = [_row_to_image_lite(img) for img in cur.fetchall()]
                if not p['thumbnail'] and p['images']:
                    cur.execute("SELECT thumbnail FROM project_images WHERE project_id=%s ORDER BY uploaded_at DESC LIMIT 1", (r['id'],))
                    first = cur.fetchone()
                    if first:
                        p['thumbnail'] = first['thumbnail']
                projects.append(p)
        return jsonify(projects)
    finally:
        conn.close()


# ---------- 靜態檔案服務 ----------

# 乾淨 URL：不帶 .html 副檔名
_PAGES = ['login', 'index', 'account', 'project-detail', 'color-detection', 'ceramic-studio', 'ai-color-guide', 'recipe-dentin', 'recipe-unified', 'admin', 'forgot-password', 'reset-password']

@app.route('/')
def serve_index():
    return send_from_directory('.', 'index.html')


@app.route('/<page>')
def serve_page(page):
    if page in _PAGES:
        return send_from_directory('.', page + '.html')
    # 其餘當作靜態檔案
    return send_from_directory('.', page)


@app.route('/<path:filename>')
def serve_static(filename):
    return send_from_directory('.', filename)


# ---------- 啟動 ----------

if __name__ == '__main__':
    _init_db()
    _init_default_admin()
    # 從資料庫載入設定套用到 Flask
    try:
        _upload_mb = _get_setting('max_upload_size_mb', '100')
        app.config['MAX_CONTENT_LENGTH'] = int(_upload_mb) * 1024 * 1024
        _session_days = _get_setting('session_timeout_days', '7')
        app.permanent_session_lifetime = timedelta(days=int(_session_days))
    except Exception:
        pass
    print('=' * 50)
    print('  Idensol Chroma 伺服器已啟動')
    print('  http://localhost:5000')
    print('=' * 50)
    app.run(host='0.0.0.0', port=5000, debug=True)
