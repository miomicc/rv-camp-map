"""跨模块共用的业务逻辑。

之前这些都写在 app.py 里。新功能（通知、手机号、搜索）也要用到
serialize_spot / require_user，如果从 app.py 导入就会形成
app -> routes_extra -> app 的循环导入，所以抽到这一层。
"""

import secrets
import time

from fastapi import Depends, Header, HTTPException, Request

import config
import db
from geo import gcj02_to_bd09, gcj02_to_wgs84
from logsetup import log

# ---------------------------------------------------------------- 业务常量

# 积分规则：集中定义，方便运营调参而不用改代码
POINT_RULES = {
    "spot_approved": 50,      # 提交的营地上线
    "spot_rejected": 0,       # 被驳回不扣分（避免误伤新人）
    "rate_spot": 3,           # 评价他人营地
    "spot_good_rated": 5,     # 自己的营地被评 4 星以上
    "daily_login": 2,         # 每日首次登录
    "spot_stale_reported": -30,  # 提交的营地被多人举报失效
}

# 积分兑换会员时长：积分数 -> 天数
POINT_EXCHANGE = {500: 30, 2000: 180, 6000: 730}

# 付费套餐（金额单位：分，规避浮点误差）
PLANS = {
    "basic_3y": {"name": "普通会员 · 三年", "amount_fen": 9900, "days": 1095},
    "lifetime": {"name": "尊贵会员 · 终身", "amount_fen": 29900, "days": 36500},
}

SPOT_TYPES = ["房车营地", "高速服务区", "野外驻车点", "营地酒店", "农家乐营地"]
FACILITY_KEYS = ["水电桩", "排污口", "淋浴", "卫生间", "洗衣房", "充电桩",
                 "WiFi", "餐厅", "便利店", "儿童设施", "宠物友好", "24小时门禁"]

TOKEN_TTL = config.TOKEN_TTL_DAYS * 86400


# ---------------------------------------------------------------- 会话与鉴权

def issue_token(conn, user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    conn.execute(
        "INSERT INTO tokens(token, user_id, expire_at, created_at) VALUES(?,?,?,?)",
        (token, user_id, int(time.time()) + TOKEN_TTL, db.now_iso()),
    )
    return token


def current_user(authorization: str = Header(default="")):
    """从 Authorization: Bearer xxx 解析当前用户，未登录返回 None。"""
    if not authorization.startswith("Bearer "):
        return None
    token = authorization[7:].strip()
    if not token:
        return None
    with db.get_conn() as conn:
        row = conn.execute(
            "SELECT u.* FROM tokens t JOIN users u ON u.id = t.user_id "
            "WHERE t.token=? AND t.expire_at > ?",
            (token, int(time.time())),
        ).fetchone()
        if row and row["is_banned"]:
            raise HTTPException(403, "账号已被封禁")
        return db.row_to_dict(row) if row else None


def require_user(user=Depends(current_user)):
    if not user:
        raise HTTPException(401, "请先登录")
    return user


def require_admin(user=Depends(require_user)):
    if not user["is_admin"]:
        raise HTTPException(403, "需要管理员权限")
    return user


def client_ip(request: Request) -> str:
    """取客户端 IP。生产环境若在 Nginx 后面，要读 X-Forwarded-For 的第一段。"""
    fwd = request.headers.get("x-forwarded-for", "")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def user_public(conn, uid: int) -> dict:
    row = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if not row:
        return {}
    d = db.row_to_dict(row)
    # 这三样绝对不能出接口
    d.pop("password_hash", None)
    d.pop("salt", None)
    d.pop("secret_key_hash", None)   # 哈希也不给，防止离线爆破
    d["is_member"] = db.is_member(row)
    d["is_admin"] = bool(d["is_admin"])
    d["is_anonymous"] = not row["username"]   # 是否匿名密钥账号
    d["has_phone"] = bool(row["phone"])
    # 手机号对外只给掩码，完整号码只在后台按需展示
    d["phone_masked"] = mask_phone(row["phone"]) if row["phone"] else ""
    d.pop("phone", None)
    d.pop("is_banned", None)
    return d


def mask_phone(phone: str) -> str:
    if not phone or len(phone) < 7:
        return ""
    return phone[:3] + "****" + phone[-4:]


def unique_user_no(conn) -> str:
    for _ in range(10):
        no = db.generate_user_no()
        if not conn.execute("SELECT 1 FROM users WHERE user_no=?", (no,)).fetchone():
            return no
    raise HTTPException(500, "用户编号生成失败，请重试")


def grant_daily_login(conn, uid: int) -> None:
    """每日首次登录送积分。密钥登录、账号登录、手机号登录共用这一份逻辑。"""
    today = db.now_iso()[:10]
    got = conn.execute(
        "SELECT id FROM point_logs WHERE user_id=? AND reason=? AND created_at LIKE ?",
        (uid, "daily_login", f"{today}%"),
    ).fetchone()
    if not got:
        db.add_points(conn, uid, POINT_RULES["daily_login"], "daily_login")


def add_days(iso: str, days: int) -> str:
    t = time.strptime(iso[:19], "%Y-%m-%dT%H:%M:%S")
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(time.mktime(t) + days * 86400))


# ---------------------------------------------------------------- 序列化

def thumb_of(url: str) -> str:
    """由原图路径推导缩略图路径。已经是缩略图就原样返回。"""
    if not url or "/thumb/" in url:
        return url
    i = url.rfind("/")
    if i < 0:
        return url
    return url[:i] + "/thumb" + url[i:]


def normalize_images(raw) -> list:
    """images 字段兼容两种格式：
    老数据是字符串数组，新上传是 {url, thumb, ...} 对象数组。
    统一成对象，前端不用再判断。
    """
    items = db.loads(raw, []) if isinstance(raw, str) else (raw or [])
    out = []
    for it in items:
        if isinstance(it, str) and it:
            out.append({"url": it, "thumb": thumb_of(it)})
        elif isinstance(it, dict) and it.get("url"):
            out.append({"url": it["url"], "thumb": it.get("thumb") or thumb_of(it["url"])})
    return out


def serialize_spot(row, user, full: bool = False) -> dict:
    """按用户等级裁剪字段。

    这是商业模式的技术落点：
      - 匿名/免费用户：只看得到点位、名称、类型 —— 知道"这儿有营地"
      - 会员：看得到地址、电话、价格、设施、详情 —— 知道"怎么去、多少钱"
    """
    is_member = bool(user) and (user["is_admin"] or db.is_member(user))

    d = {
        "id": row["id"],
        "name": row["name"],
        "lng": row["lng"],
        "lat": row["lat"],
        "spot_type": row["spot_type"],
        "province": row["province"],
        "city": row["city"],
        "status": row["status"],
        "verify_score": round(row["verify_score"], 1),
        "verify_count": row["verify_count"],
        "created_at": row["created_at"],
        "locked": not is_member,
    }

    # 百度坐标顺手带出去，方便接入百度 SDK 的项目直接用
    bd = gcj02_to_bd09(row["lng"], row["lat"])
    wgs = gcj02_to_wgs84(row["lng"], row["lat"])
    d["lng_bd09"], d["lat_bd09"] = round(bd[0], 7), round(bd[1], 7)
    d["lng_wgs84"], d["lat_wgs84"] = round(wgs[0], 7), round(wgs[1], 7)

    imgs = normalize_images(row["images"])
    # 封面缩略图：给列表/搜索结果用，避免为了一个角标去下载 4MB 原图
    d["cover"] = (imgs[0]["thumb"] or imgs[0]["url"]) if imgs else ""

    if is_member:
        d.update({
            "address": row["address"],
            "phone": row["phone"],
            "price_range": row["price_range"],
            "facilities": db.loads(row["facilities"], []),
            "detail": row["detail"],
            "images": imgs,
            "contact_locked": False,
        })
    else:
        d.update({
            "address": mask(row["address"]),
            "phone": "",
            "price_range": "",
            "facilities": [],
            "detail": "",
            # 免费用户连缩略图都不给——照片本身也是付费内容的一部分
            "images": [],
            "contact_locked": True,
        })
        d["cover"] = ""

    if full:
        d["created_by"] = row["created_by"]
        d["reject_reason"] = row["reject_reason"]
        d["updated_at"] = row["updated_at"]
        d["report_count"] = row["report_count"]
    return d


def mask(text: str) -> str:
    """免费用户看到的地址做模糊化：保留省市，隐去门牌。"""
    if not text:
        return ""
    if len(text) <= 4:
        return text[0] + "***"
    keep = max(3, len(text) // 3)
    return text[:keep] + "***"
