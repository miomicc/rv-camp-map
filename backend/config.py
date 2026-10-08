"""集中配置。

以前这些常量散落在 app.py / db.py 里，改一个要翻两个文件。
现在统一在这里读环境变量，好处是：
  1. 部署时只需要看这一个文件就知道要配什么
  2. 安全相关的默认值可以集中收紧（而不是分散在各处悄悄留后门）
  3. 便于写测试时整体覆盖
"""

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
BACKEND_DIR = BASE_DIR / "backend"
FRONTEND_DIR = BASE_DIR / "frontend"


def env_str(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def env_bool(name: str, default: bool = False) -> bool:
    v = os.environ.get(name)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")


def env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, "").strip() or default)
    except ValueError:
        return default


def env_list(name: str, default=None) -> list:
    raw = os.environ.get(name, "")
    if not raw.strip():
        return list(default or [])
    return [x.strip() for x in raw.split(",") if x.strip()]


# ---------------------------------------------------------------- 环境

# 开发模式。生产部署必须显式设 RVCAMP_DEV=0。
# 它影响三件事：mock-pay 是否开放、CORS 是否放开、验证码是否回显。
DEV = env_bool("RVCAMP_DEV", True)

# ---------------------------------------------------------------- 目录

_data = os.environ.get("RVCAMP_DATA")
DATA_DIR = Path(_data) if _data else (BASE_DIR / "data")
UPLOAD_DIR = DATA_DIR / "uploads"
LOG_DIR = DATA_DIR / "logs"
BACKUP_DIR = DATA_DIR / "backups"

for _d in (DATA_DIR, UPLOAD_DIR, LOG_DIR, BACKUP_DIR):
    _d.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------- 安全

# CORS：生产必须显式列域名，绝不默认 *。
# 留空且非 DEV 时 = 不加 CORS 头（纯同源），这是最保守的默认值。
CORS_ORIGINS = env_list("RVCAMP_CORS")
if not CORS_ORIGINS and DEV:
    CORS_ORIGINS = ["*"]

# 后台入口路径。默认 /admin 太好猜，生产建议换成随机串：
#   RVCAMP_ADMIN_PATH=/rv-backstage-7f3a
# 同时 /admin 在生产环境会返回 404（开发模式仍可访问，方便调试）。
ADMIN_PATH = env_str("RVCAMP_ADMIN_PATH") or "/admin"
if not ADMIN_PATH.startswith("/"):
    ADMIN_PATH = "/" + ADMIN_PATH

# 后台 IP 白名单。支持精确 IP 和 CIDR（如 203.0.113.0/24）。
# 留空 = 不限制（开发方便）。生产强烈建议配上自己的出口 IP。
ADMIN_IP_WHITELIST = env_list("RVCAMP_ADMIN_IP_WHITELIST")

# 是否允许"演示支付"（自助开通会员）。
# 真实支付接入前，本地演示需要它；上线必须关掉，否则等于会员免费送。
ALLOW_MOCK_PAY = env_bool("RVCAMP_ALLOW_MOCK_PAY", DEV)

# ---------------------------------------------------------------- 业务配额

# 免费用户每天可查看的营地详情条数（此前只写在接口返回里，从未真正执行）
FREE_DAILY_DETAIL_QUOTA = env_int("RVCAMP_FREE_QUOTA", 3)

# 瓦片代理前缀。默认 "/tiles" = 走后端自建代理（backend/tileproxy.py）：
#   统一出口（源站只看到我们一台机器）+ 磁盘缓存（每块瓦片只回源一次）+ 防盗链。
# 全部免费、不需要任何 Key。置空才退回"浏览器直连源站"，一般不该这么配——
# 那样源站会看到 N 个用户各自的高频请求，是最容易被限流的一种形态。
TILE_PROXY = env_str("RVCAMP_TILE_PROXY", "/tiles").rstrip("/")

# 自建代理的缓存策略（详见 tileproxy.py）
TILE_CACHE_DAYS = env_int("RVCAMP_TILE_CACHE_DAYS", 180)   # 多久没人看就淘汰
TILE_CACHE_MB = env_int("RVCAMP_TILE_CACHE_MB", 4096)      # 磁盘占用上限
TILE_CACHE_AGE = env_int("RVCAMP_TILE_CACHE_AGE", 86400 * 30)   # 响应头 max-age
TILE_INFLIGHT = env_int("RVCAMP_TILE_INFLIGHT", 8)         # 同时回源的最大并发

MAX_IMAGE_BYTES = env_int("RVCAMP_MAX_IMAGE_MB", 5) * 1024 * 1024
MAX_IMAGES_PER_SPOT = env_int("RVCAMP_MAX_IMAGES", 8)
MAX_IMAGES_PER_REQUEST = MAX_IMAGES_PER_SPOT

# 图片重编码：原图最大边长、缩略图边长、JPEG 质量
IMAGE_MAX_EDGE = env_int("RVCAMP_IMAGE_MAX_EDGE", 1600)
THUMB_EDGE = env_int("RVCAMP_THUMB_EDGE", 480)
JPEG_QUALITY = env_int("RVCAMP_JPEG_QUALITY", 82)

# ---------------------------------------------------------------- 限流规则
# (窗口秒数, 窗口内允许次数)
RATE_RULES = {
    "issue_key":    (600, 5),     # 领密钥：10 分钟 5 个（防批量注册）
    "create_spot":  (3600, 15),   # 提交营地：1 小时 15 条
    "upload":       (600, 40),    # 上传图片：10 分钟 40 张
    "rate":         (600, 40),    # 评价
    "search":       (60, 30),     # 搜索：1 分钟 30 次
    "phone_code":   (600, 3),     # 短信验证码：10 分钟 3 次
    "phone_login":  (600, 10),    # 手机号登录
    "recover":      (86400, 3),   # 密钥找回：每天 3 次
}
# 全局兜底：单 IP 所有写请求（POST/PATCH/DELETE）上限
RATE_WRITE_GLOBAL = (60, 120)

# ---------------------------------------------------------------- 外部通道（可插拔）

# 短信：none=只写日志；console=打印到日志（开发）；http=POST 到自建网关
SMS_PROVIDER = env_str("RVCAMP_SMS_PROVIDER", "console" if DEV else "none")
SMS_ENDPOINT = env_str("RVCAMP_SMS_ENDPOINT")
SMS_SIGN = env_str("RVCAMP_SMS_SIGN", "房车营地")

# 邮件：未配置 SMTP 时自动降级为只写日志
SMTP_HOST = env_str("RVCAMP_SMTP_HOST")
SMTP_PORT = env_int("RVCAMP_SMTP_PORT", 465)
SMTP_USER = env_str("RVCAMP_SMTP_USER")
SMTP_PASS = env_str("RVCAMP_SMTP_PASS")
SMTP_FROM = env_str("RVCAMP_SMTP_FROM") or SMTP_USER

# ---------------------------------------------------------------- 运维

LOG_LEVEL = env_str("RVCAMP_LOG_LEVEL", "DEBUG" if DEV else "INFO")
LOG_MAX_BYTES = env_int("RVCAMP_LOG_MAX_MB", 10) * 1024 * 1024
LOG_BACKUPS = env_int("RVCAMP_LOG_BACKUPS", 5)

# 数据保留天数
TOKEN_TTL_DAYS = env_int("RVCAMP_TOKEN_TTL_DAYS", 30)
KEEP_AUDIT_DAYS = env_int("RVCAMP_KEEP_AUDIT_DAYS", 365)
KEEP_NOTIFY_DAYS = env_int("RVCAMP_KEEP_NOTIFY_DAYS", 90)
KEEP_POINTLOG_DAYS = env_int("RVCAMP_KEEP_POINTLOG_DAYS", 365)

# 孤儿文件回收：只清理 N 天前上传且从未被任何营地引用的文件
ORPHAN_FILE_AGE_DAYS = env_int("RVCAMP_ORPHAN_AGE_DAYS", 3)
# 定时任务的间隔（秒）
MAINTENANCE_INTERVAL = env_int("RVCAMP_MAINTENANCE_INTERVAL", 6 * 3600)
