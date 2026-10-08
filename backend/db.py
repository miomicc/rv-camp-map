"""
数据层：SQLite + 纯 SQL，零 ORM 依赖。

为什么不用 ORM：这类应用的表结构极简单，几十万条 POI 数据用 SQLite
加两个索引就够跑。引入 ORM 只会增加维护成本。

表清单：
  users         用户（等级、积分、会员到期时间、绑定手机号）
  spots         营地标记（核心表）
  ratings       营地评星/核实反馈
  point_logs    积分流水
  orders        会员赞助订单
  tokens        登录会话
  audit_log     审核日志（谁在什么时候改了哪条数据）
  notifications 站内信
  sms_codes     短信验证码
  rate_hits     限流计数
  uploads       上传文件登记（用于归属校验与孤儿回收）
"""

import json
import os
import hashlib
import secrets
import sqlite3
import time
from contextlib import contextmanager

import config

DB_PATH = os.environ.get("RVCAMP_DB") or str(config.DATA_DIR / "rvcamp.db")

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_no         TEXT    NOT NULL UNIQUE,     -- 8 位用户编号，对外展示用
    secret_key_hash TEXT    UNIQUE,              -- sha256(PEPPER+密钥)。绝不存明文
    key_preview     TEXT    NOT NULL DEFAULT '', -- 密钥末 4 位，供用户核对，不可用于登录
    username        TEXT    UNIQUE,              -- 可选：绑定的账号名（升级项）
    password_hash   TEXT    NOT NULL DEFAULT '',
    salt            TEXT    NOT NULL DEFAULT '',
    nickname        TEXT    NOT NULL DEFAULT '',
    level           INTEGER NOT NULL DEFAULT 0,   -- 0=免费会员 1=赞助会员
    points          INTEGER NOT NULL DEFAULT 0,
    expire_at       TEXT,                          -- 赞助会员到期时间 ISO8601
    is_admin        INTEGER NOT NULL DEFAULT 0,
    is_banned       INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);

CREATE TABLE IF NOT EXISTS spots (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT    NOT NULL,
    lng           REAL    NOT NULL,   -- GCJ-02 经度（与底图坐标系一致）
    lat           REAL    NOT NULL,   -- GCJ-02 纬度
    province      TEXT    NOT NULL DEFAULT '',
    city          TEXT    NOT NULL DEFAULT '',
    spot_type     TEXT    NOT NULL DEFAULT '营地',  -- 营地/服务区/野外驻车/营地酒店
    -- 以下为会员可见字段，免费用户看不到
    address       TEXT    NOT NULL DEFAULT '',
    phone         TEXT    NOT NULL DEFAULT '',
    price_range   TEXT    NOT NULL DEFAULT '',
    facilities    TEXT    NOT NULL DEFAULT '[]',    -- JSON 数组：水电、排污、淋浴…
    detail        TEXT    NOT NULL DEFAULT '',
    images        TEXT    NOT NULL DEFAULT '[]',    -- JSON 数组
    -- 审核与质量
    status        INTEGER NOT NULL DEFAULT 0,   -- 0=待审 1=通过 2=驳回 3=失效
    reject_reason TEXT    NOT NULL DEFAULT '',
    created_by    INTEGER,
    created_at    TEXT    NOT NULL,
    updated_at    TEXT    NOT NULL,
    -- 众包可信度
    verify_score  REAL    NOT NULL DEFAULT 0,   -- 0~5
    verify_count  INTEGER NOT NULL DEFAULT 0,
    report_count  INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (created_by) REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_spots_bbox     ON spots(lng, lat);
CREATE INDEX IF NOT EXISTS idx_spots_status   ON spots(status);
CREATE INDEX IF NOT EXISTS idx_spots_creator  ON spots(created_by);

CREATE TABLE IF NOT EXISTS ratings (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    spot_id    INTEGER NOT NULL,
    user_id    INTEGER NOT NULL,
    stars      INTEGER NOT NULL,   -- 1~5
    comment    TEXT    NOT NULL DEFAULT '',
    verdict    TEXT    NOT NULL DEFAULT 'ok',  -- ok=信息准确 stale=已失效
    created_at TEXT    NOT NULL,
    UNIQUE(spot_id, user_id),
    FOREIGN KEY (spot_id) REFERENCES spots(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS point_logs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL,
    delta      INTEGER NOT NULL,
    reason     TEXT    NOT NULL,
    ref_id     INTEGER,
    created_at TEXT    NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_pointlogs_user ON point_logs(user_id, created_at DESC);

CREATE TABLE IF NOT EXISTS orders (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    order_no   TEXT    NOT NULL UNIQUE,
    user_id    INTEGER NOT NULL,
    plan       TEXT    NOT NULL,   -- basic_3y / lifetime
    amount_fen INTEGER NOT NULL,   -- 单位：分，避免浮点
    status     INTEGER NOT NULL DEFAULT 0,  -- 0=待支付 1=已支付 2=已关闭
    channel    TEXT    NOT NULL DEFAULT '',
    created_at TEXT    NOT NULL,
    paid_at    TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_orders_user ON orders(user_id, created_at DESC);

CREATE TABLE IF NOT EXISTS tokens (
    token      TEXT PRIMARY KEY,
    user_id    INTEGER NOT NULL,
    expire_at  INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS audit_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    actor      INTEGER,
    action     TEXT NOT NULL,
    target     TEXT NOT NULL,
    detail     TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS login_fails (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ip         TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_loginfails_ip ON login_fails(ip, created_at);

-- 站内信。外部通道（邮件/短信）可能发不出去，站内信是唯一保证送达的
CREATE TABLE IF NOT EXISTS notifications (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL,
    type       TEXT    NOT NULL,
    title      TEXT    NOT NULL,
    body       TEXT    NOT NULL DEFAULT '',
    ref        TEXT    NOT NULL DEFAULT '',
    is_read    INTEGER NOT NULL DEFAULT 0,
    created_at TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_notify_user ON notifications(user_id, is_read, created_at DESC);

-- 短信验证码。只存哈希，明文不落库
CREATE TABLE IF NOT EXISTS sms_codes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    phone      TEXT    NOT NULL,
    code_hash  TEXT    NOT NULL,
    purpose    TEXT    NOT NULL DEFAULT 'bind',
    expire_at  INTEGER NOT NULL,
    tries      INTEGER NOT NULL DEFAULT 0,
    created_at TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sms_phone ON sms_codes(phone, created_at DESC);

-- 限流计数。放库里而不是内存：多 worker 时内存计数会各算一份
CREATE TABLE IF NOT EXISTS rate_hits (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    scope      TEXT    NOT NULL,
    identity   TEXT    NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_rate ON rate_hits(scope, identity, created_at);

-- 免费用户详情浏览记录。按 (用户, 营地, 日期) 去重，
-- 反复刷新同一个营地不会重复扣额度——否则用户会觉得系统在刁难他
CREATE TABLE IF NOT EXISTS detail_views (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_key   TEXT    NOT NULL,
    spot_id    INTEGER NOT NULL,
    day        TEXT    NOT NULL,
    created_at TEXT    NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_dv ON detail_views(user_key, spot_id, day);

-- 上传文件登记。没有这张表就无法判断"哪些文件没人引用"
CREATE TABLE IF NOT EXISTS uploads (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    path       TEXT    NOT NULL UNIQUE,
    thumb      TEXT    NOT NULL DEFAULT '',
    uploader   INTEGER,
    spot_id    INTEGER,
    bytes      INTEGER NOT NULL DEFAULT 0,
    created_at TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_uploads_spot ON uploads(spot_id);
CREATE INDEX IF NOT EXISTS idx_uploads_user ON uploads(uploader);

-- 图形验证码。领密钥这种"白送东西"的接口必须挡一道，
-- 否则一个 while True 就能刷出几万个账号。一次性、5 分钟过期。
CREATE TABLE IF NOT EXISTS captchas (
    id         TEXT    PRIMARY KEY,
    code       TEXT    NOT NULL,
    expire_at  INTEGER NOT NULL,
    used       INTEGER NOT NULL DEFAULT 0,
    tries      INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
);
"""


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime())


def hash_password(password: str, salt: str) -> str:
    """PBKDF2-SHA256，20 万轮。生产环境建议换 bcrypt/argon2。"""
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 200_000).hex()


def make_salt() -> str:
    return secrets.token_hex(16)


# ---------------------------------------------------------------- 用户密钥（匿名令牌登录）

# 字符集：字母 + 数字，剔除 0/O、1/l/I 这些抄写时容易看错的字符。
# 剩 58 个字符，32 位密钥的空间是 58^32 ≈ 2^187，
# 暴力枚举在物理上不可行（对比：地球上的原子总数约 2^166）。
KEY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
KEY_LENGTH = 32

# 管理员密钥前缀。
# 为什么不干脆用同一套格式：管理员密钥是最高权限凭证，一眼能认出来
# 能避免两个实际问题——① 运营人员误把管理员密钥当普通密钥发出去；
# ② 用户拿到管理员密钥时能意识到"这不是普通凭证，要特别小心"。
# 前缀本身不参与权限判定（权限永远看数据库的 is_admin），只做视觉标识。
ADMIN_KEY_PREFIX = "ADM"
ADMIN_KEY_RANDOM_LEN = 32

def _load_pepper() -> str:
    """加载服务端 pepper，生产环境缺失则直接拒绝启动。

    以前这里写的是 os.environ.get(..., "dev-only-pepper-change-in-production")，
    问题在于：运维不知道要配，服务照样能起来，于是"看起来有 pepper"
    实际上是个全行业通用的常量字符串——数据库一旦泄露，
    sha256(常量 + 32位密钥) 可以被离线穷举，等于没 protection。

    fail-fast 的价值就在这里：宁可起不来，也不要带着假的安全感上线。
    开发环境允许自动生成并持久化到 data/.dev_pepper，
    避免每次重启都让所有已领取的密钥失效。
    """
    env = os.environ.get("RVCAMP_PEPPER", "").strip()
    if env:
        return env
    if config.DEV:
        f = config.DATA_DIR / ".dev_pepper"
        if not f.exists():
            f.write_text(secrets.token_hex(32))
        return f.read_text().strip()
    raise RuntimeError(
        "生产环境必须设置环境变量 RVCAMP_PEPPER。"
        "它是 sha256(PEPPER+密钥) 的组成部分，缺失 = 数据库泄露即可离线反推全部密钥。"
        "生成：python -c \"import secrets;print(secrets.token_hex(32))\"")


# 服务端私钥。作用：即使数据库被脱库，攻击者也无法离线爆破出密钥。
PEPPER = _load_pepper()


def generate_secret_key(admin: bool = False) -> str:
    """生成用户密钥。只在注册那一刻生成一次，之后服务端不再持有明文。

    管理员密钥 = "ADM" 前缀 + 32 位随机，总长 35。
    前缀占用 3 个字符，随机部分仍有 58³² ≈ 2¹⁸⁷ 的空间，安全性不受影响。
    """
    if admin:
        return ADMIN_KEY_PREFIX + "".join(
            secrets.choice(KEY_ALPHABET) for _ in range(ADMIN_KEY_RANDOM_LEN))
    # 普通密钥刻意避开 ADM 开头，防止前缀标识被误读
    while True:
        k = "".join(secrets.choice(KEY_ALPHABET) for _ in range(KEY_LENGTH))
        if not k.startswith(ADMIN_KEY_PREFIX):
            return k


def looks_like_admin_key(key: str) -> bool:
    """仅用于前端提示，**不是权限判断依据**。

    真正的权限判断永远看数据库里的 is_admin 字段。
    """
    return normalize_key(key).upper().startswith(ADMIN_KEY_PREFIX)


def normalize_key(key: str) -> str:
    """归一化用户输入：去掉空格和连字符（允许用户按 XXXX-XXXX 分组粘贴）。"""
    return "".join(ch for ch in (key or "") if ch not in " -_")


def hash_secret_key(key: str) -> str:
    """sha256(PEPPER + key)。

    这里用快哈希而不是 PBKDF2，是刻意的：
    PBKDF2 这类慢哈希是为了抵抗"低熵密码"的字典攻击，
    而 32 位随机密钥本身熵极高，字典攻击不成立。
    快哈希让每次请求的校验成本可以忽略。
    """
    return hashlib.sha256((PEPPER + normalize_key(key)).encode()).hexdigest()


def hash_code(phone: str, code: str, purpose: str) -> str:
    """验证码哈希。同样只存哈希，且把 purpose 混进去——
    否则"绑定"的验证码可以被拿去"找回密钥"用。"""
    return hashlib.sha256((PEPPER + "|" + phone + "|" + code + "|" + purpose).encode()).hexdigest()


def key_preview(key: str) -> str:
    """密钥末 4 位，用于用户在界面上核对"这是我的密钥"。

    不是凭证——只有末 4 位，无法反推完整密钥。
    """
    return normalize_key(key)[-4:]


def generate_user_no() -> str:
    """8 位纯数字用户编号，对外展示用（对应截图里的"用户编号"）。"""
    return "".join(secrets.choice("0123456789") for _ in range(8))


def format_key(key: str) -> str:
    """把密钥按 4 位一组显示，方便用户抄写和核对。"""
    k = normalize_key(key)
    return "-".join(k[i:i + 4] for i in range(0, len(k), 4))


@contextmanager
def get_conn():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ---------------------------------------------------------------- 迁移

# 表结构演进记录。每次改动 users/spots 等表的列，就在这里追加一条。
# 生产环境应该用 Alembic，这里做轻量版：启动时自动补齐缺失的列。
MIGRATIONS = [
    # (表名, 列名, 列定义)
    ("users", "user_no", "TEXT"),
    ("users", "secret_key_hash", "TEXT"),
    ("users", "key_preview", "TEXT NOT NULL DEFAULT ''"),
    ("users", "phone", "TEXT"),
    ("users", "phone_verified_at", "TEXT"),
    ("users", "email", "TEXT"),
]


def migrate() -> list[str]:
    """补齐旧库缺失的列与约束。返回本次实际执行的变更列表。

    两件事：
      1. ADD COLUMN 补新列（SQLite 支持，但不能带 UNIQUE 约束）
      2. 重建 users 表把 username 改成可空（匿名密钥账号没有用户名）
    """
    applied = []
    with get_conn() as conn:
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(users)")}

        # --- 旧库的 username 是 NOT NULL，密钥账号没有用户名，必须改成可空 ---
        if cols:
            info = {r["name"]: r for r in conn.execute("PRAGMA table_info(users)")}
            if info.get("username") and info["username"]["notnull"]:
                _rebuild_users_table(conn)
                applied.append("users: 重建表（username 改为可空）")
                cols = {r["name"] for r in conn.execute("PRAGMA table_info(users)")}

        for table, column, coldef in MIGRATIONS:
            tcols = {r["name"] for r in conn.execute(f"PRAGMA table_info({table})")}
            if not tcols or column in tcols:
                continue
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {coldef}")
            applied.append(f"{table}.{column}")
    return applied


def _rebuild_users_table(conn) -> None:
    """SQLite 的官方表重建流程：建新表 -> 拷数据 -> 删旧表 -> 改名。

    这一步在旧库升级时自动执行，用户数据不丢。
    """
    conn.executescript("""
        PRAGMA foreign_keys=OFF;
        CREATE TABLE users_new (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            user_no         TEXT    UNIQUE,
            secret_key_hash TEXT    UNIQUE,
            key_preview     TEXT    NOT NULL DEFAULT '',
            username        TEXT    UNIQUE,
            password_hash   TEXT    NOT NULL DEFAULT '',
            salt            TEXT    NOT NULL DEFAULT '',
            nickname        TEXT    NOT NULL DEFAULT '',
            level           INTEGER NOT NULL DEFAULT 0,
            points          INTEGER NOT NULL DEFAULT 0,
            expire_at       TEXT,
            is_admin        INTEGER NOT NULL DEFAULT 0,
            is_banned       INTEGER NOT NULL DEFAULT 0,
            phone           TEXT,
            phone_verified_at TEXT,
            email           TEXT,
            created_at      TEXT    NOT NULL
        );
        INSERT INTO users_new (id, username, password_hash, salt, nickname, level, points,
                               expire_at, is_admin, is_banned, created_at)
        SELECT id, username, password_hash, salt, nickname, level, points,
               expire_at, is_admin, is_banned, created_at FROM users;
        DROP TABLE users;
        ALTER TABLE users_new RENAME TO users;
        CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
        PRAGMA foreign_keys=ON;
    """)


def _ensure_unique_indexes(conn) -> None:
    """部分唯一索引：手机号可以为空，但一旦填了就必须唯一。

    注意必须放在 migrate() 之后——旧库在列补齐之前建索引会直接报错。
    """
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_phone ON users(phone)"
        " WHERE phone IS NOT NULL AND phone != ''")


def init_db() -> None:
    with get_conn() as c:
        c.executescript(SCHEMA)
    migrate()
    # 索引必须在列补齐之后再建，否则旧库会因为列不存在而报错
    with get_conn() as c:
        c.execute("CREATE INDEX IF NOT EXISTS idx_users_keyhash ON users(secret_key_hash)")
        _ensure_unique_indexes(c)


def row_to_dict(row) -> dict:
    return {k: row[k] for k in row.keys()} if row is not None else {}


def add_points(conn, user_id: int, delta: int, reason: str, ref_id=None) -> int:
    """加/扣积分并写流水，返回变动后的总积分。"""
    conn.execute(
        "INSERT INTO point_logs(user_id, delta, reason, ref_id, created_at) VALUES(?,?,?,?,?)",
        (user_id, delta, reason, ref_id, now_iso()),
    )
    conn.execute("UPDATE users SET points = MAX(0, points + ?) WHERE id=?", (delta, user_id))
    row = conn.execute("SELECT points FROM users WHERE id=?", (user_id,)).fetchone()
    return row["points"] if row else 0


def is_member(user_row) -> bool:
    """判断是否处于赞助会员有效期。管理员视同永久会员。"""
    if not user_row:
        return False
    if user_row["is_admin"]:
        return True
    if user_row["level"] != 1:
        return False
    exp = user_row["expire_at"]
    if not exp:
        return False
    return exp > now_iso()


def audit(conn, actor, action: str, target: str, detail: str = "") -> None:
    conn.execute(
        "INSERT INTO audit_log(actor, action, target, detail, created_at) VALUES(?,?,?,?,?)",
        (actor, action, target, detail, now_iso()),
    )


# ---------------------------------------------------------------- 登录失败限流

# 密钥登录是唯一入口，必须防爆破。
# 32 位随机串本身枚举不动（58³²），但限流能挡住两种情况：
#   1. 攻击者用已泄露的密钥字典批量试探
#   2. 内部人员密钥被猜/被社工
# 8 位数字的旧式"用户编号"早就不能登录了，所以这里只按 IP 限流。
LOGIN_MAX_FAILS = 10          # 窗口内允许的失败次数
LOGIN_WINDOW_SEC = 300        # 统计窗口：5 分钟
LOGIN_LOCK_SEC = 900          # 超限后锁定：15 分钟


def record_login_fail(conn, ip: str) -> None:
    """记录一次登录失败，并立即提交。

    **必须立刻 commit**：调用方紧接着会抛 HTTPException，
    而 get_conn() 在异常路径上是 rollback——不主动提交的话，
    这条失败记录会被一起回滚掉，限流就完全失效了。
    这个坑很隐蔽，表现出来就是"限流代码明明写了但从不生效"。
    """
    conn.execute(
        "INSERT INTO login_fails(ip, created_at) VALUES(?,?)", (ip, now_iso()))
    conn.commit()


def purge_old_login_fails(conn) -> None:
    cut = time.strftime("%Y-%m-%dT%H:%M:%S",
                        time.localtime(time.time() - LOGIN_LOCK_SEC * 2))
    conn.execute("DELETE FROM login_fails WHERE created_at < ?", (cut,))
    conn.commit()


def login_blocked_until(conn, ip: str) -> int:
    """返回该 IP 被锁定的剩余秒数，0 表示未被锁。"""
    now = time.time()
    window_start = time.strftime(
        "%Y-%m-%dT%H:%M:%S", time.localtime(now - LOGIN_WINDOW_SEC))
    row = conn.execute(
        "SELECT COUNT(*) c, MAX(created_at) m FROM login_fails WHERE ip=? AND created_at>?",
        (ip, window_start)).fetchone()
    if row["c"] < LOGIN_MAX_FAILS:
        return 0
    # 以窗口内最后一次失败为起点计算锁定
    last = time.mktime(time.strptime(row["m"][:19], "%Y-%m-%dT%H:%M:%S"))
    left = int(last + LOGIN_LOCK_SEC - now)
    return max(0, left)


def clear_login_fails(conn, ip: str) -> None:
    """登录成功后清空该 IP 的失败记录。"""
    conn.execute("DELETE FROM login_fails WHERE ip=?", (ip,))
    conn.commit()


def dumps(v) -> str:
    return json.dumps(v, ensure_ascii=False)


def loads(s: str, default):
    try:
        return json.loads(s) if s else default
    except Exception:
        return default
