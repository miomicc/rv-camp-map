"""跨模块共用的业务逻辑。

之前这些都写在 app.py 里。新功能（通知、手机号、搜索）也要用到
serialize_spot / require_user，如果从 app.py 导入就会形成
app -> routes_extra -> app 的循环导入，所以抽到这一层。
"""

import re
import secrets
import time

from fastapi import Depends, Header, HTTPException, Request

import config
import db
import invite
from geo import gcj02_to_bd09, gcj02_to_wgs84
from logsetup import log

# ---------------------------------------------------------------- 业务常量

# 积分规则：集中定义，方便运营调参而不用改代码
POINT_RULES = {
    "spot_approved": 100,     # 提交的营地上线（营地是最贵的产出，值这个价）
    "spot_rejected": 0,       # 被驳回不扣分（避免误伤新人）
    "rate_spot": 3,           # 评价他人营地
    "spot_good_rated": 5,     # 自己的营地被评 4 星以上
    "daily_login": 2,         # 每日首次登录
    "invite_reward": 20,      # 邀请一个真人：反作弊判定通过后当场发放（见 invite.py）
    "spot_stale_reported": -30,  # 提交的营地被多人举报失效
}

# 积分兑换会员时长：积分数 -> 天数。
# 只有两档，且"买多送多"——300 分换 90 天（3 个月），600 分换 180 天（6 个月）。
# 之前那套 500分=30天 / 2000分=180天 / 6000分=730天 是早年随手定的，
# 换算下来 500 分才 30 天、2000 分才半年，正常用户一辈子够不着，
# 等于没有兑换功能。现在的档位是有意让用户"够得着"的。
POINT_EXCHANGE = {300: 90, 600: 180}

# 兑换档位的中文说明。天数自己算容易把 90 天算成"3 个月还是 90 天"，
# 统一在这里定义，前端/通知/后台三处读同一份。
POINT_EXCHANGE_LABEL = {300: "3 个月", 600: "6 个月"}


def exchange_label(points: int, days: int) -> str:
    """把天数说成人话（3 个月），900 天以上说年。"""
    label = POINT_EXCHANGE_LABEL.get(points)
    if label:
        return label
    return "终身" if days >= 36500 else f"{days} 天"

# 管理员手动调整积分的事由白名单。
# 积分能换会员天数，等于间接影响收入，所以不允许"随便给个理由就调"——
# 必须落在这几个分类里，事后对账才知道每一分钱是从哪来的。
MANUAL_POINT_REASONS = {
    "reward": "活动奖励",
    "compensate": "投诉/故障补偿",
    "penalty": "违规扣除",
    "review_fix": "数据补录/纠正",
    "other": "其他",
}

# 付费套餐（金额单位：分，规避浮点误差）
PLANS = {
    "basic_3y": {"name": "普通会员 · 三年", "amount_fen": 9900, "days": 1095},
    "lifetime": {"name": "尊贵会员 · 终身", "amount_fen": 29900, "days": 36500},
}

SPOT_TYPES = ["房车营地", "高速服务区", "野外驻车点", "营地酒店", "农家乐营地"]
FACILITY_KEYS = ["水电桩", "排污口", "淋浴", "卫生间", "洗衣房", "充电桩",
                 "WiFi", "餐厅", "便利店", "儿童设施", "宠物友好", "24小时门禁"]

# ---------------------------------------------------------------- 昵称规则
# 昵称是后台识别"这个人是谁"的唯一线索。早期没做限制时，
# 默认昵称（"露营者xxxx"）和手动填的名字可以随便重名，后台一排同名人
# 根本分不清谁是谁，出问题时也没法追溯。所以现在收口成：
#   自己可以改 + 全站唯一 + 不允许冒充官方角色。
NICKNAME_MIN = config.NICKNAME_MIN
NICKNAME_MAX = config.NICKNAME_MAX
# 中文 / 字母 / 数字 / 下划线 / 连字符 / 间隔号。不要空格和 emoji：
# 前者会让搜索和展示错位，后者在后台列表里基本糊成一坨看不清。
NICKNAME_RE = re.compile(r"^[\u4e00-\u9fa5A-Za-z0-9_\-·]+$")
# 普通用户不允许把自己叫成这些，避免冒充官方/管理人员去忽悠别人。
# 管理员自己改或者后台代改时放开（allow_privileged=True）。
NICKNAME_RESERVED = ("管理员", "官方", "客服", "系统", "房车地图", "营地地图",
                     "admin", "administrator", "root")

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
    # 邀请功能加的这几列属于内部判定数据：注册 IP 和设备指纹是个人隐私信息
    # （泄露了相当于告诉别人"这个账号从哪个网络、用哪台电脑注册的"），
    # 绝不能出接口。invite_code 虽然是自己的，但没必要跟着每个 /api/auth/me
    # 回传——要分享时走 /api/invite/mine 单独取。
    d.pop("reg_ip", None)
    d.pop("reg_fp", None)
    d.pop("invited_by", None)
    d.pop("invite_code", None)
    return d


def mask_phone(phone: str) -> str:
    if not phone or len(phone) < 7:
        return ""
    return phone[:3] + "****" + phone[-4:]


# ---------------------------------------------------------------- 昵称

def normalize_nickname(raw: str) -> str:
    """去掉首尾空白，中间连续空白压成一个——很多人是直接粘贴名字进来的。"""
    return re.sub(r"\s+", " ", (raw or "")).strip()


def nickname_taken(conn, nickname: str, exclude_uid=None) -> bool:
    """昵称是否已被占用。

    用 COLLATE NOCASE：SQLite 默认按二进制比较，Tom 和 tom 会被当成两个
    不同的名字，唯一约束就形同虚设了。
    """
    sql = "SELECT 1 FROM users WHERE nickname = ? COLLATE NOCASE"
    args = [nickname]
    if exclude_uid is not None:
        sql += " AND id != ?"
        args.append(int(exclude_uid))
    return bool(conn.execute(sql, args).fetchone())


def validate_nickname(raw, conn, exclude_uid=None, allow_privileged=False) -> str:
    """校验昵称并返回规范化后的字符串。

    不合规一律抛 ValueError，由路由层转成 400 给前端展示，
    这样这套规则能同时给用户自己改名、领密钥、后台代改三条路径复用。
    """
    nick = normalize_nickname(raw)
    if len(nick) < NICKNAME_MIN:
        raise ValueError(f"昵称至少 {NICKNAME_MIN} 个字符")
    if len(nick) > NICKNAME_MAX:
        raise ValueError(f"昵称最多 {NICKNAME_MAX} 个字符")
    if not NICKNAME_RE.match(nick):
        raise ValueError("昵称只能包含中文、字母、数字、下划线、连字符和间隔号，不能有空格或表情")
    if nick[0] in "_-·":
        raise ValueError("昵称不能以符号开头")
    if not allow_privileged:
        low = nick.casefold()
        hit = next((w for w in NICKNAME_RESERVED if w in low), None)
        if hit:
            raise ValueError(f"昵称不能含「{hit}」，容易让人误以为是官方人员")
    if nickname_taken(conn, nick, exclude_uid):
        raise ValueError(f"昵称「{nick}」已经被占用了，换一个吧")
    return nick


def unique_user_no(conn) -> str:
    for _ in range(10):
        no = db.generate_user_no()
        if not conn.execute("SELECT 1 FROM users WHERE user_no=?", (no,)).fetchone():
            return no
    raise HTTPException(500, "用户编号生成失败，请重试")


def grant_daily_login(conn, uid: int) -> None:
    """每日首次登录送积分。密钥登录、账号登录共用这一份逻辑。

    顺带调一次 invite.settle：新版邀请在 bind() 里当场结算，这里只剩给
    老版本遗留的 pending 记录兜底（见 invite.settle 的注释），没有 pending
    记录时就是一次带索引的空查询。
    """
    today = db.now_iso()[:10]
    got = conn.execute(
        "SELECT id FROM point_logs WHERE user_id=? AND reason=? AND created_at LIKE ?",
        (uid, "daily_login", f"{today}%"),
    ).fetchone()
    if not got:
        db.add_points(conn, uid, POINT_RULES["daily_login"], "daily_login")
    invite.settle(conn, uid)


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
