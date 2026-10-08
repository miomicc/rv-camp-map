"""
房车露营营地地图 · 后端 API

技术栈刻意选最朴素的组合：FastAPI + SQLite + 纯 SQL。
理由：这类应用 99% 的请求是"给我这个屏幕范围内的点"，
瓶颈在读不在写，加缓存就能扛。上分布式是过度设计。

启动：
    uvicorn app:app --reload --port 8000
"""

import ipaddress
import json
import os
import time
from typing import List, Optional

from fastapi import (Depends, FastAPI, File, Header, HTTPException, Query,
                     Request, UploadFile)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

import captcha
import common
import config
import db
import images
import maintenance
import notify
import ratelimit
import tileproxy
from common import (FACILITY_KEYS, PLANS, POINT_EXCHANGE, POINT_RULES,
                    SPOT_TYPES, TOKEN_TTL, add_days, client_ip, current_user,
                    grant_daily_login, issue_token, mask, normalize_images,
                    require_admin, require_user, serialize_spot, unique_user_no,
                    user_public)
from geo import haversine_m, wgs84_to_gcj02
from logsetup import access as access_log
from logsetup import log

# 免费用户每天可查看的营地详情条数（这次是**真的执行**，不再只是个数字）
FREE_DAILY_DETAIL_QUOTA = config.FREE_DAILY_DETAIL_QUOTA

MAX_IMAGE_BYTES = config.MAX_IMAGE_BYTES
MAX_IMAGES_PER_SPOT = config.MAX_IMAGES_PER_SPOT
MAX_IMAGES_PER_REQUEST = config.MAX_IMAGES_PER_REQUEST

# 只认这几种。不靠扩展名判断（可以伪造），而是校验文件头的魔数。
ALLOWED_MAGIC = {
    b"\xff\xd8\xff": "jpg",                # JPEG
    b"\x89PNG\r\n\x1a\n": "png",           # PNG
    b"RIFF": "webp",                       # WebP（还需在第 8-12 字节校验 WEBP）
    b"GIF87a": "gif",                      # GIF
    b"GIF89a": "gif",
}


def sniff_image_type(head: bytes) -> Optional[str]:
    """通过文件头魔数识别真实图片类型，防止把 .php/.html 改名成 .jpg 上传。"""
    for magic, ext in ALLOWED_MAGIC.items():
        if head.startswith(magic):
            if ext == "webp" and head[8:12] != b"WEBP":
                continue
            return ext
    return None


app = FastAPI(title="房车营地地图 API", version="1.1")

# CORS：开发放开，生产必须显式列域名。留空则完全不加 CORS 头（同源）。
if config.CORS_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=config.CORS_ORIGINS,
        allow_methods=["*"],
        allow_headers=["*"],
    )


# ---------------------------------------------------------------- 中间件

@app.middleware("http")
async def access_log_mw(request: Request, call_next):
    """访问日志 + 耗时。放在最外层才能记录到被限流/被拦截的请求。

    注意：这里绝不记录请求体——里面有密钥和验证码。
    """
    t0 = time.time()
    try:
        resp = await call_next(request)
        status = resp.status_code
    except Exception as e:
        log.exception("请求异常 %s %s: %s", request.method, request.url.path, e)
        status = 500
        resp = JSONResponse({"detail": "服务器内部错误"}, status_code=500)
    # 瓦片一个视野就是几十上百个请求，写访问日志只会把日志撑爆且毫无价值；
    # 命中情况看 /api/admin/tile-cache 的统计即可。
    if not request.url.path.startswith("/tiles/"):
        access_log(request, status, t0)
    return resp


@app.middleware("http")
async def write_rate_mw(request: Request, call_next):
    """所有写请求的兜底限流。单 IP 单位时间内的总次数上限。"""
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        try:
            ratelimit.guard_write(request)
        except HTTPException as e:
            return JSONResponse({"detail": e.detail}, status_code=429)
    return await call_next(request)


def _ip_allowed(ip: str) -> bool:
    if not config.ADMIN_IP_WHITELIST:
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for rule in config.ADMIN_IP_WHITELIST:
        try:
            if "/" in rule:
                if addr in ipaddress.ip_network(rule, strict=False):
                    return True
            elif addr == ipaddress.ip_address(rule):
                return True
        except ValueError:
            continue
    return False


@app.middleware("http")
async def admin_guard_mw(request: Request, call_next):
    """后台入口的 IP 白名单。

    /admin 这种固定路径任何人都能猜到，一旦后台登录页暴露在公网，
    就等于把爆破入口摆在门口。IP 白名单是最省事也最有效的一道闸。
    """
    path = request.url.path
    if path.startswith("/api/admin") or path.startswith(config.ADMIN_PATH):
        ip = client_ip(request)
        if not _ip_allowed(ip):
            log.warning("后台访问被拒 ip=%s path=%s", ip, path)
            return JSONResponse({"detail": "该网络不允许访问后台"}, status_code=403)
    return await call_next(request)


@app.on_event("startup")
def _startup():
    db.init_db()
    maintenance.start_scheduler()
    log.info("服务启动：dev=%s admin_path=%s mock_pay=%s cors=%s",
             config.DEV, config.ADMIN_PATH, config.ALLOW_MOCK_PAY,
             config.CORS_ORIGINS or "(同源)")


# ---------------------------------------------------------------- 请求模型

class RegisterIn(BaseModel):
    username: str = Field(min_length=3, max_length=24)
    password: str = Field(min_length=6, max_length=64)
    nickname: str = Field(default="", max_length=24)


class LoginIn(BaseModel):
    username: str
    password: str


class SpotIn(BaseModel):
    name: str = Field(min_length=2, max_length=60)
    lng: float = Field(ge=-180, le=180)
    lat: float = Field(ge=-90, le=90)
    spot_type: str = "房车营地"
    province: str = ""
    city: str = ""
    address: str = ""
    phone: str = ""
    price_range: str = ""
    facilities: List[str] = []
    detail: str = ""
    coordinate: str = "gcj02"   # 前端上报的坐标系：gcj02 或 wgs84
    images: List[dict] = []     # [{"url": "/uploads/...", "thumb": "..."}]

    @field_validator("spot_type")
    @classmethod
    def _check_type(cls, v):
        return v if v in SPOT_TYPES else "房车营地"


class RateIn(BaseModel):
    stars: int = Field(ge=1, le=5)
    comment: str = Field(default="", max_length=500)
    verdict: str = "ok"          # ok=信息准确 / stale=已失效


class CheckoutIn(BaseModel):
    plan: str


class ReviewIn(BaseModel):
    action: str                  # approve / reject
    reason: str = ""


class KeyLoginIn(BaseModel):
    secret_key: str = Field(min_length=8, max_length=64)


# ---------------------------------------------------------------- 认证接口

@app.post("/api/auth/register")
def register(body: RegisterIn, request: Request):
    ratelimit.rule("issue_key", client_ip(request), "注册太频繁")
    with db.get_conn() as conn:
        exists = conn.execute("SELECT id FROM users WHERE username=?", (body.username,)).fetchone()
        if exists:
            raise HTTPException(400, "用户名已被占用")
        salt = db.make_salt()
        cur = conn.execute(
            "INSERT INTO users(user_no, username, password_hash, salt, nickname, created_at) "
            "VALUES(?,?,?,?,?,?)",
            (unique_user_no(conn), body.username,
             db.hash_password(body.password, salt), salt,
             body.nickname or body.username, db.now_iso()),
        )
        uid = cur.lastrowid
        token = issue_token(conn, uid)
        db.audit(conn, uid, "register", f"user:{uid}")
        return {"token": token, "user": user_public(conn, uid)}


@app.get("/api/captcha")
def get_captcha():
    """取一道图形验证码。返回 id + 图片（data URL），前端直接塞进 <img src>。

    不放进登录接口而单独出接口，是因为图片要能"点一下换一张"，
    而换一张不应该顺带做别的事。
    """
    with db.get_conn() as conn:
        cid, png = captcha.new_challenge(conn)
    import base64
    return {"id": cid,
            "image": "data:image/png;base64," + base64.b64encode(png).decode()}


@app.post("/api/auth/key/issue")
def issue_key(request: Request, nickname: str = Query(default="", max_length=24),
              captcha_id: str = Query(default=""), captcha_code: str = Query(default="")):
    """免费领取密钥 —— 即"注册"。

    关键设计：
      1. 明文密钥**只在这一刻返回一次**，服务端只存 sha256(PEPPER+key)。
      2. 同时下发一个登录 token，用户领完就是登录态。
      3. 匿名账号一样是完整用户，能提交营地、攒积分、付费升级。
      4. **必须过验证码**：这是全站唯一一个"什么都不用提供就能拿走东西"的
         接口，不限的话一个循环就能刷出几万个账号，把积分、审核队列、
         数据库全冲垮。IP 限流只能挡住最粗糙的那一种。
    """
    # 这是全站最容易被人写脚本刷的接口：不限制的话几千个账号几分钟就出来了
    ratelimit.rule("issue_key", client_ip(request), "领取太频繁")
    with db.get_conn() as conn:
        if captcha.enabled():
            captcha.verify(conn, captcha_id, captcha_code)
        for _ in range(5):
            key = db.generate_secret_key()
            kh = db.hash_secret_key(key)
            if not conn.execute("SELECT 1 FROM users WHERE secret_key_hash=?", (kh,)).fetchone():
                break
        else:
            raise HTTPException(500, "密钥生成冲突，请重试")

        cur = conn.execute(
            "INSERT INTO users(user_no, secret_key_hash, key_preview, nickname, created_at) "
            "VALUES(?,?,?,?,?)",
            (unique_user_no(conn), kh, db.key_preview(key),
             nickname or f"露营者{db.generate_user_no()[:4]}", db.now_iso()),
        )
        uid = cur.lastrowid
        token = issue_token(conn, uid)
        db.audit(conn, uid, "issue_key", f"user:{uid}")
        notify.notify(conn, uid, "system", "欢迎加入",
                      "你的密钥是本平台唯一的登录凭证，请立即保存。"
                      "密钥不可找回，丢失后只能重新领取一个。", "welcome")
        return {
            "secret_key": db.format_key(key),   # 明文，仅此一次
            "token": token,
            "user": user_public(conn, uid),
            "warning": "密钥是您唯一的身份凭证，请立即保存。建议绑定手机号，丢失后可用手机号找回。",
        }


@app.post("/api/auth/key/login")
def key_login(body: KeyLoginIn, request: Request):
    """密钥登录。用户端和管理端用同一个接口——权限差异由 is_admin 决定。"""
    ip = client_ip(request)
    kh = db.hash_secret_key(body.secret_key)
    with db.get_conn() as conn:
        left = db.login_blocked_until(conn, ip)
        if left:
            raise HTTPException(429, f"尝试次数过多，请 {left // 60 + 1} 分钟后再试")

        row = conn.execute("SELECT * FROM users WHERE secret_key_hash=?", (kh,)).fetchone()
        if not row:
            db.record_login_fail(conn, ip)
            db.purge_old_login_fails(conn)
            # 统一话术，不区分"格式错"和"密钥不存在"，避免被枚举探测
            raise HTTPException(400, "密钥无效，请检查是否输入完整")
        if row["is_banned"]:
            raise HTTPException(403, "该密钥已被封禁")

        db.clear_login_fails(conn, ip)
        grant_daily_login(conn, row["id"])
        token = issue_token(conn, row["id"])
        u = user_public(conn, row["id"])
        db.audit(conn, row["id"], "login", f"user:{row['id']}",
                 "admin" if row["is_admin"] else "user")
        log.info("登录成功 user=%s admin=%s ip=%s", row["id"], row["is_admin"], ip)
        return {"token": token, "user": u}


@app.post("/api/admin/key/issue")
def issue_admin_key(nickname: str = Query(default="", max_length=24),
                    admin=Depends(require_admin)):
    """签发一个新的管理员密钥。只能由现有管理员调用。"""
    with db.get_conn() as conn:
        for _ in range(5):
            key = db.generate_secret_key(admin=True)
            kh = db.hash_secret_key(key)
            if not conn.execute("SELECT 1 FROM users WHERE secret_key_hash=?", (kh,)).fetchone():
                break
        else:
            raise HTTPException(500, "密钥生成冲突，请重试")

        cur = conn.execute(
            "INSERT INTO users(user_no, secret_key_hash, key_preview, nickname, level,"
            " expire_at, is_admin, created_at) VALUES(?,?,?,?,1,?,1,?)",
            (unique_user_no(conn), kh, db.key_preview(key),
             nickname or "管理员", "2099-12-31T23:59:59", db.now_iso()),
        )
        db.audit(conn, admin["id"], "issue_admin_key", f"user:{cur.lastrowid}",
                 nickname or "管理员")
        return {
            "secret_key": db.format_key(key),
            "user_no": conn.execute("SELECT user_no FROM users WHERE id=?",
                                    (cur.lastrowid,)).fetchone()["user_no"],
            "warning": "管理员密钥权限最高，请立即保存并妥善保管。泄露等同于后台被完全接管。",
        }


@app.post("/api/admin/key/demote")
def demote_admin(user_no: str = Query(..., description="要降权的管理员编号"),
                 admin=Depends(require_admin)):
    """撤销某个管理员密钥的管理权限（保留账号，降为普通用户）。"""
    with db.get_conn() as conn:
        row = conn.execute("SELECT id, is_admin FROM users WHERE user_no=?",
                           (user_no,)).fetchone()
        if not row:
            raise HTTPException(404, "用户不存在")
        if not row["is_admin"]:
            raise HTTPException(400, "该用户本来就不是管理员")
        if row["id"] == admin["id"]:
            raise HTTPException(400, "不能撤销自己的管理员权限")
        left = conn.execute("SELECT COUNT(*) c FROM users WHERE is_admin=1").fetchone()["c"]
        if left <= 1:
            raise HTTPException(400, "系统必须保留至少一个管理员")
        conn.execute("UPDATE users SET is_admin=0 WHERE id=?", (row["id"],))
        conn.execute("DELETE FROM tokens WHERE user_id=?", (row["id"],))
        db.audit(conn, admin["id"], "demote_admin", f"user:{row['id']}", user_no)
        return {"ok": True, "message": "已撤销管理员权限，该密钥现在只是普通用户"}


@app.post("/api/auth/key/rotate")
def rotate_key(user=Depends(current_user)):
    """更换密钥。换发后旧密钥立即失效，所有会话清空。"""
    if not user:
        raise HTTPException(401, "请先登录")
    with db.get_conn() as conn:
        for _ in range(5):
            key = db.generate_secret_key()
            kh = db.hash_secret_key(key)
            if not conn.execute("SELECT 1 FROM users WHERE secret_key_hash=?", (kh,)).fetchone():
                break
        else:
            raise HTTPException(500, "密钥生成冲突，请重试")
        conn.execute("UPDATE users SET secret_key_hash=?, key_preview=? WHERE id=?",
                     (kh, db.key_preview(key), user["id"]))
        conn.execute("DELETE FROM tokens WHERE user_id=?", (user["id"],))
        db.audit(conn, user["id"], "rotate_key", f"user:{user['id']}")
        notify.notify(conn, user["id"], "key_rotated", "密钥已换发",
                      "你的密钥已更新，旧密钥立即失效，请用新密钥重新登录。")
        return {
            "secret_key": db.format_key(key),
            "warning": "旧密钥已立即失效，请用新密钥重新登录。",
        }


@app.get("/api/auth/key/reissue")
def reissue_preview():
    """解释密钥找回策略。"""
    return {
        "policy": "no_recovery",
        "message": "密钥只存哈希，服务端无法还原，丢失后无法找回。请务必妥善保存。",
        "mitigations": [
            "领取后立即下载密钥卡片（前端生成 txt）",
            "怀疑泄露时用「换发新密钥」自救（旧密钥立即失效）",
            "付费用户在订单里留有联系方式，客服可人工核验后重签密钥",
        ],
    }


@app.post("/api/auth/login")
def login(body: LoginIn, request: Request):
    """账号密码登录。保留此接口供历史管理员账号使用（新管理员建议用密钥）。"""
    ip = client_ip(request)
    with db.get_conn() as conn:
        left = db.login_blocked_until(conn, ip)
        if left:
            raise HTTPException(429, f"尝试次数过多，请 {left // 60 + 1} 分钟后再试")

        row = conn.execute("SELECT * FROM users WHERE username=?", (body.username,)).fetchone()
        if not row or not row["password_hash"] or \
                db.hash_password(body.password, row["salt"] or "") != row["password_hash"]:
            db.record_login_fail(conn, ip)
            db.purge_old_login_fails(conn)
            raise HTTPException(400, "用户名或密码错误")
        if row["is_banned"]:
            raise HTTPException(403, "账号已被封禁")

        db.clear_login_fails(conn, ip)
        grant_daily_login(conn, row["id"])
        token = issue_token(conn, row["id"])
        return {"token": token, "user": user_public(conn, row["id"])}


@app.get("/api/auth/me")
def me(request: Request, user=Depends(current_user)):
    if not user:
        return {"user": None, "quota": _quota_public(None, client_ip(request))}
    with db.get_conn() as conn:
        return {"user": user_public(conn, user["id"]),
                "quota": _quota_public(user, client_ip(request))}


@app.post("/api/auth/logout")
def logout(authorization: str = Header(default="")):
    if authorization.startswith("Bearer "):
        with db.get_conn() as conn:
            conn.execute("DELETE FROM tokens WHERE token=?", (authorization[7:].strip(),))
    return {"ok": True}


# ---------------------------------------------------------------- 免费额度

def _user_key(user, ip: str = "") -> str:
    """额度归属：登录用户按 uid，匿名按 IP。

    匿名不能共用一个桶——否则第一个访客看完 8 条，后面所有人都被挡住。
    """
    return f"u{user['id']}" if user else f"ip:{ip or 'unknown'}"


def _detail_used(conn, user_key: str) -> int:
    today = db.now_iso()[:10]
    return conn.execute(
        "SELECT COUNT(*) c FROM detail_views WHERE user_key=? AND day=?",
        (user_key, today)).fetchone()["c"]


def _quota_public(user, ip: str = "") -> dict:
    """给前端展示的额度信息。会员返回不限。"""
    if user and (user["is_admin"] or db.is_member(user)):
        return {"limit": -1, "used": 0, "left": -1, "member": True}
    with db.get_conn() as conn:
        used = _detail_used(conn, _user_key(user, ip))
    return {"limit": FREE_DAILY_DETAIL_QUOTA, "used": used,
            "left": max(0, FREE_DAILY_DETAIL_QUOTA - used), "member": False}


def _charge_detail_quota(conn, user, spot_id: int, ip: str = "") -> dict:
    """扣一次免费额度。同一营地当天只扣一次（反复刷新不惩罚）。

    返回 {"ok": True} 或 {"ok": False, "used": n, "limit": n}。
    会员与作者本人不扣。
    """
    if user and (user["is_admin"] or db.is_member(user)):
        return {"ok": True}
    key = _user_key(user, ip)
    today = db.now_iso()[:10]
    existed = conn.execute(
        "SELECT 1 FROM detail_views WHERE user_key=? AND spot_id=? AND day=?",
        (key, spot_id, today)).fetchone()
    if existed:
        return {"ok": True}
    used = _detail_used(conn, key)
    if used >= FREE_DAILY_DETAIL_QUOTA:
        return {"ok": False, "used": used, "limit": FREE_DAILY_DETAIL_QUOTA}
    conn.execute(
        "INSERT INTO detail_views(user_key, spot_id, day, created_at) VALUES(?,?,?,?)",
        (key, spot_id, today, db.now_iso()))
    return {"ok": True, "used": used + 1, "left": FREE_DAILY_DETAIL_QUOTA - used - 1}


# ---------------------------------------------------------------- 营地标记

@app.get("/api/spots")
def list_spots(
    bbox: str = Query(..., description="minLng,minLat,maxLng,maxLat（GCJ-02）"),
    zoom: int = Query(5, ge=1, le=19),
    keyword: str = "",
    spot_type: str = "",
    limit: int = Query(800, ge=1, le=3000),
    user=Depends(current_user),
):
    """视口查询——这是整个系统最关键的接口。永远不要一次返回全国数据。"""
    try:
        parts = [float(x) for x in bbox.split(",")]
        assert len(parts) == 4
        min_lng, min_lat, max_lng, max_lat = parts
    except Exception:
        raise HTTPException(400, "bbox 格式应为 minLng,minLat,maxLng,maxLat")

    sql = ("SELECT * FROM spots WHERE status=1 AND lng BETWEEN ? AND ? "
           "AND lat BETWEEN ? AND ?")
    params = [min_lng, max_lng, min_lat, max_lat]

    if keyword:
        sql += " AND (name LIKE ? OR city LIKE ? OR province LIKE ? OR address LIKE ?)"
        kw = f"%{keyword}%"
        params += [kw, kw, kw, kw]
    if spot_type:
        sql += " AND spot_type = ?"
        params.append(spot_type)

    sql += " ORDER BY verify_score DESC, id DESC LIMIT ?"
    params.append(limit)

    with db.get_conn() as conn:
        rows = conn.execute(sql, params).fetchall()

    items = [serialize_spot(r, user) for r in rows]

    # 降采样：低缩放级别下按地理网格抽样，保证任意视口返回量可控
    sampled = extra = 0
    if zoom <= 9 and len(items) > 300:
        grid = 0.5 if zoom <= 6 else (0.2 if zoom <= 8 else 0.08)
        seen, kept = set(), []
        for it in items:
            key = (round(it["lng"] / grid), round(it["lat"] / grid))
            if key in seen:
                continue
            seen.add(key)
            kept.append(it)
        extra = len(items) - len(kept)
        sampled = 1
        items = kept

    return {"total": len(items), "sampled": bool(sampled), "hidden_by_sample": extra,
            "items": items, "facility_keys": FACILITY_KEYS, "spot_types": SPOT_TYPES}


@app.get("/api/search")
def search(q: str = Query("", min_length=1, max_length=40),
           page: int = Query(1, ge=1), size: int = Query(20, ge=1, le=50),
           user=Depends(current_user)):
    """全库搜索。

    之前搜索只能匹配"当前视野已加载的点"——用户搜"三亚"却什么都没有，
    因为地图正停在北京。搜索必须查全库，而不是查屏幕。
    """
    q = q.strip()
    if not q:
        return {"total": 0, "items": [], "page": page, "pages": 1}
    kw = f"%{q}%"
    where = ("status=1 AND (name LIKE ? OR city LIKE ? OR province LIKE ?"
             " OR address LIKE ? OR spot_type LIKE ?)")
    params = [kw, kw, kw, kw, kw]
    with db.get_conn() as conn:
        total = conn.execute(
            f"SELECT COUNT(*) c FROM spots WHERE {where}", params).fetchone()["c"]
        rows = conn.execute(
            f"SELECT * FROM spots WHERE {where} ORDER BY verify_score DESC, id DESC"
            " LIMIT ? OFFSET ?", params + [size, (page - 1) * size]).fetchall()
    return {
        "total": total, "page": page, "size": size,
        "pages": max(1, (total + size - 1) // size),
        "items": [serialize_spot(r, user) for r in rows],
    }


@app.get("/api/spots/{spot_id}")
def spot_detail(spot_id: int, request: Request, user=Depends(current_user)):
    with db.get_conn() as conn:
        row = conn.execute("SELECT * FROM spots WHERE id=?", (spot_id,)).fetchone()
        if not row:
            raise HTTPException(404, "营地不存在")
        if row["status"] != 1:
            # 未过审的只有作者本人和管理员能看
            if not user or (user["id"] != row["created_by"] and not user["is_admin"]):
                raise HTTPException(404, "营地不存在或尚未通过审核")

        # 免费额度：这是会员转化最核心的一处门禁，必须真的执行
        if not (user and (user["is_admin"] or db.is_member(user))):
            quota = _charge_detail_quota(conn, user, spot_id, client_ip(request))
            if not quota.get("ok"):
                raise HTTPException(
                    402, f"今日免费查看额度已用完（{quota['used']}/{quota['limit']}），"
                         "开通会员可不限次查看全部营地信息")

        ratings = conn.execute(
            "SELECT r.*, u.nickname FROM ratings r JOIN users u ON u.id=r.user_id "
            "WHERE r.spot_id=? ORDER BY r.created_at DESC LIMIT 50", (spot_id,)).fetchall()
        data = serialize_spot(row, user, full=True)
        data["ratings"] = [
            {"stars": r["stars"], "comment": r["comment"], "verdict": r["verdict"],
             "nickname": r["nickname"], "created_at": r["created_at"]}
            for r in ratings
        ]
        data["quota"] = _quota_public(user, client_ip(request))
        return data


# ---------------------------------------------------------------- 图片上传

@app.post("/api/upload/images")
async def upload_images(request: Request, files: List[UploadFile] = File(...),
                        user=Depends(require_user)):
    """批量上传营地图片，落盘前统一重编码。

    安全四道关（缺一不可）：
      1. **验魔数**——shell.php 改名成 a.jpg 是最经典的攻击
      2. **随机重命名**——彻底丢弃客户端文件名，防路径穿越
      3. **体积上限**
      4. **重新解码编码**——杀掉藏在图片容器里的脚本，同时剥离 EXIF 中的 GPS

    第 4 条是这次补上的：手机照片的 EXIF 里带着拍摄坐标，
    原样存下来再公开展示，等于把用户行踪挂在网站上。
    """
    ratelimit.rule("upload", f"u{user['id']}", "上传太频繁")
    if not files:
        raise HTTPException(400, "没有选择文件")
    if len(files) > MAX_IMAGES_PER_REQUEST:
        raise HTTPException(400, f"一次最多上传 {MAX_IMAGES_PER_REQUEST} 张")

    urls, errors = [], []
    for f in files:
        raw = await f.read()
        if len(raw) > MAX_IMAGE_BYTES:
            errors.append(f"{f.filename}: 超过 {MAX_IMAGE_BYTES // 1024 // 1024}MB 限制")
            continue
        if len(raw) < 32:
            errors.append(f"{f.filename}: 文件损坏或为空")
            continue
        if not sniff_image_type(raw[:16]):
            errors.append(f"{f.filename}: 不是有效的图片（仅支持 JPG/PNG/WebP/GIF）")
            continue

        try:
            meta = images.process(raw)
        except Exception as e:
            log.warning("图片处理失败 %s: %s", f.filename, e)
            errors.append(f"{f.filename}: 图片无法解析")
            continue

        with db.get_conn() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO uploads(path, thumb, uploader, bytes, created_at)"
                " VALUES(?,?,?,?,?)",
                (meta["url"], meta["thumb"], user["id"], meta["bytes"], db.now_iso()))
        meta["name"] = f.filename
        urls.append(meta)

    if not urls and errors:
        raise HTTPException(400, "；".join(errors))
    log.info("上传完成 user=%s count=%d", user["id"], len(urls))
    return {"urls": urls, "errors": errors, "count": len(urls)}


@app.delete("/api/upload/images")
def delete_image(path: str = Query(...), user=Depends(require_user)):
    """删除自己刚上传的图片（提交前反悔时用）。

    以前任何人登录就能删任何人的图——只要拿到路径。
    现在校验 uploader：只有本人和管理员能删。
    """
    safe = images.safe_join(path)
    if not os.path.isfile(safe):
        return {"ok": True}
    with db.get_conn() as conn:
        rec = conn.execute("SELECT uploader FROM uploads WHERE path=?", (path,)).fetchone()
        if rec and rec["uploader"] and rec["uploader"] != user["id"] \
                and not user["is_admin"]:
            raise HTTPException(403, "不能删除他人上传的图片")
        os.remove(safe)
        thumb = common.thumb_of(path)
        if thumb != path:
            try:
                p = images.safe_join(thumb)
                if os.path.isfile(p):
                    os.remove(p)
            except Exception:
                pass
        conn.execute("DELETE FROM uploads WHERE path=? OR thumb=?", (path, thumb))
    return {"ok": True}


# ---------------------------------------------------------------- 提交与评价

@app.post("/api/spots")
def create_spot(body: SpotIn, request: Request, user=Depends(require_user)):
    ratelimit.rule("create_spot", f"u{user['id']}", "提交太频繁")
    lng, lat = body.lng, body.lat
    if body.coordinate == "wgs84":
        lng, lat = wgs84_to_gcj02(lng, lat)

    with db.get_conn() as conn:
        near = conn.execute(
            "SELECT id, name, lng, lat FROM spots WHERE status=1 "
            "AND lng BETWEEN ? AND ? AND lat BETWEEN ? AND ?",
            (lng - 0.01, lng + 0.01, lat - 0.01, lat + 0.01),
        ).fetchall()
        for n in near:
            if haversine_m(lng, lat, n["lng"], n["lat"]) < 300 and n["name"] == body.name:
                raise HTTPException(400, f"附近 300 米内已有同名营地「{n['name']}」")

        imgs = [{"url": i.get("url", ""), "thumb": i.get("thumb") or common.thumb_of(i.get("url", ""))}
                for i in (body.images or []) if i.get("url")]
        cur = conn.execute(
            "INSERT INTO spots(name, lng, lat, province, city, spot_type, address, phone,"
            " price_range, facilities, detail, images, status, created_by, created_at, updated_at)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,0,?,?,?)",
            (body.name, lng, lat, body.province, body.city, body.spot_type, body.address,
             body.phone, body.price_range, db.dumps(body.facilities), body.detail,
             db.dumps(imgs[:MAX_IMAGES_PER_SPOT]),
             user["id"], db.now_iso(), db.now_iso()),
        )
        sid = cur.lastrowid
        # 图片归属落库：营地一旦过审，这些文件就不再是可回收的孤儿
        for i in imgs[:MAX_IMAGES_PER_SPOT]:
            conn.execute("UPDATE uploads SET spot_id=? WHERE path=?", (sid, i["url"]))
        db.audit(conn, user["id"], "spot_create", f"spot:{sid}", body.name)
        notify.notify(conn, user["id"], "system", "提交已收到",
                      f"「{body.name}」已提交，审核通过后将获得 "
                      f"{POINT_RULES['spot_approved']} 积分。", f"spot:{sid}")
        notify.notify_admins(conn, "system", "新的待审营地",
                             f"「{body.name}」等待审核", f"spot:{sid}")
        return {"id": sid, "status": 0,
                "message": "提交成功，等待审核。审核通过后你将获得 "
                           f"{POINT_RULES['spot_approved']} 积分。"}


@app.get("/api/my/spots")
def my_spots(user=Depends(require_user)):
    """我的提交。前端这次真正接上了入口（以前接口存在但没人调用）。"""
    with db.get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM spots WHERE created_by=? ORDER BY id DESC", (user["id"],)).fetchall()
        items = [serialize_spot(r, user, full=True) for r in rows]
        stat = {"total": len(items)}
        for it in items:
            stat[str(it["status"])] = stat.get(str(it["status"]), 0) + 1
        return {"items": items, "stat": stat,
                "status_text": {"0": "待审核", "1": "已上线", "2": "已驳回", "3": "已失效"}}


@app.post("/api/spots/{spot_id}/rate")
def rate_spot(spot_id: int, body: RateIn, user=Depends(require_user)):
    """评星 + 真伪核实。"""
    ratelimit.rule("rate", f"u{user['id']}", "评价太频繁")
    with db.get_conn() as conn:
        spot = conn.execute("SELECT * FROM spots WHERE id=? AND status=1", (spot_id,)).fetchone()
        if not spot:
            raise HTTPException(404, "营地不存在")
        if spot["created_by"] == user["id"]:
            raise HTTPException(400, "不能给自己提交的营地评分")

        old = conn.execute(
            "SELECT * FROM ratings WHERE spot_id=? AND user_id=?", (spot_id, user["id"])).fetchone()
        if old:
            conn.execute("UPDATE ratings SET stars=?, comment=?, verdict=?, created_at=? "
                         "WHERE id=?", (body.stars, body.comment, body.verdict,
                                        db.now_iso(), old["id"]))
        else:
            conn.execute(
                "INSERT INTO ratings(spot_id, user_id, stars, comment, verdict, created_at)"
                " VALUES(?,?,?,?,?,?)",
                (spot_id, user["id"], body.stars, body.comment, body.verdict, db.now_iso()),
            )
            if body.verdict == "stale":
                conn.execute("UPDATE spots SET report_count = report_count + 1 WHERE id=?", (spot_id,))

        agg = conn.execute(
            "SELECT AVG(stars) a, COUNT(*) n FROM ratings WHERE spot_id=?", (spot_id,)).fetchone()
        score = round(agg["a"] or 0, 2)
        conn.execute("UPDATE spots SET verify_score=?, verify_count=?, updated_at=? WHERE id=?",
                     (score, agg["n"] or 0, db.now_iso(), spot_id))

        if body.stars >= 4 and not old and spot["created_by"]:
            db.add_points(conn, spot["created_by"], POINT_RULES["spot_good_rated"],
                          "spot_good_rated", spot_id)
        if not old:
            db.add_points(conn, user["id"], POINT_RULES["rate_spot"], "rate_spot", spot_id)

        # 多人举报失效 -> 自动转待审，等人工确认
        if (conn.execute("SELECT report_count FROM spots WHERE id=?", (spot_id,)).fetchone()
                ["report_count"] >= 3):
            conn.execute("UPDATE spots SET status=0, reject_reason=? WHERE id=?",
                         ("多人举报信息失效，待复核", spot_id))
            if spot["created_by"]:
                notify.notify(conn, spot["created_by"], "spot_reported", "营地被举报",
                              f"「{spot['name']}」被多人举报信息失效，已转为待复核状态。",
                              f"spot:{spot_id}")
        return {"ok": True, "verify_score": score, "verify_count": agg["n"]}


# ---------------------------------------------------------------- 积分与会员

@app.get("/api/points")
def my_points(user=Depends(require_user)):
    with db.get_conn() as conn:
        logs = conn.execute(
            "SELECT * FROM point_logs WHERE user_id=? ORDER BY id DESC LIMIT 100",
            (user["id"],)).fetchall()
        return {
            "points": user["points"],
            "rules": POINT_RULES,
            "exchange": [{"points": k, "days": v} for k, v in sorted(POINT_EXCHANGE.items())],
            "logs": [db.row_to_dict(r) for r in logs],
        }


@app.post("/api/points/exchange/{points}")
def exchange_membership(points: int, user=Depends(require_user)):
    days = POINT_EXCHANGE.get(points)
    if not days:
        raise HTTPException(400, f"不支持的兑换额度，可选：{sorted(POINT_EXCHANGE)}")
    if user["points"] < points:
        raise HTTPException(400, f"积分不足，当前 {user['points']}，需要 {points}")
    with db.get_conn() as conn:
        db.add_points(conn, user["id"], -points, "exchange_membership")
        base = user["expire_at"] if db.is_member(user) else db.now_iso()
        new_exp = add_days(base, days)
        conn.execute("UPDATE users SET level=1, expire_at=? WHERE id=?", (new_exp, user["id"]))
        db.audit(conn, user["id"], "exchange_membership", f"user:{user['id']}", f"{points}分/{days}天")
        notify.notify(conn, user["id"], "points", "积分兑换成功",
                      f"已用 {points} 积分兑换 {days} 天会员，有效期至 {new_exp[:10]}。")
        return {"ok": True, "expire_at": new_exp, "days": days,
                "user": user_public(conn, user["id"])}


@app.get("/api/plans")
def plans():
    return {"plans": [{"key": k, **v} for k, v in PLANS.items()],
            "free_quota": FREE_DAILY_DETAIL_QUOTA}


@app.post("/api/orders")
def create_order(body: CheckoutIn, user=Depends(require_user)):
    plan = PLANS.get(body.plan)
    if not plan:
        raise HTTPException(400, "套餐不存在")
    order_no = "RV" + time.strftime("%Y%m%d%H%M%S") + db.generate_user_no()[:6]
    with db.get_conn() as conn:
        conn.execute(
            "INSERT INTO orders(order_no, user_id, plan, amount_fen, status, created_at)"
            " VALUES(?,?,?,?,0,?)",
            (order_no, user["id"], body.plan, plan["amount_fen"], db.now_iso()),
        )
        # 真实场景：这里调用微信支付/支付宝下单，拿到 prepay_id 或跳转链接返回前端
        hint = ("演示环境：调用 /api/orders/{order_no}/mock-pay 模拟支付成功"
                if config.ALLOW_MOCK_PAY else
                "请按页面提示完成支付，支付结果由平台异步回调确认")
        return {
            "order_no": order_no,
            "amount_fen": plan["amount_fen"],
            "plan_name": plan["name"],
            "pay_hint": hint,
        }


@app.post("/api/orders/{order_no}/mock-pay")
def mock_pay(order_no: str, user=Depends(require_user)):
    """演示用的自助支付。**生产环境必须关掉**（RVCAMP_ALLOW_MOCK_PAY=0）。

    以前这个接口没有任何开关，任何人登录后都能给自己开通终身会员——
    等于把会员费直接归零。现在默认只在开发模式开放。
    """
    if not config.ALLOW_MOCK_PAY:
        raise HTTPException(404, "演示支付已关闭")
    with db.get_conn() as conn:
        o = conn.execute("SELECT * FROM orders WHERE order_no=? AND user_id=?",
                         (order_no, user["id"])).fetchone()
        if not o:
            raise HTTPException(404, "订单不存在")
        if o["status"] == 1:
            return {"ok": True, "message": "订单已支付（幂等）"}
        plan = PLANS[o["plan"]]
        conn.execute("UPDATE orders SET status=1, paid_at=?, channel=? WHERE id=?",
                     (db.now_iso(), "mock", o["id"]))
        u = conn.execute("SELECT * FROM users WHERE id=?", (user["id"],)).fetchone()
        base = u["expire_at"] if db.is_member(u) else db.now_iso()
        new_exp = add_days(base, plan["days"])
        conn.execute("UPDATE users SET level=1, expire_at=? WHERE id=?", (new_exp, user["id"]))
        db.audit(conn, user["id"], "order_paid", order_no, f"{plan['amount_fen']}分")
        notify.notify(conn, user["id"], "order_paid", "开通成功",
                      f"已开通「{plan['name']}」，有效期至 {new_exp[:10]}。", order_no)
        return {"ok": True, "expire_at": new_exp, "user": user_public(conn, user["id"])}


@app.get("/api/my/orders")
def my_orders(user=Depends(require_user)):
    with db.get_conn() as conn:
        rows = conn.execute("SELECT * FROM orders WHERE user_id=? ORDER BY id DESC",
                            (user["id"],)).fetchall()
        return {"items": [db.row_to_dict(r) for r in rows]}


# ---------------------------------------------------------------- 管理后台

@app.get("/api/admin/pending")
def pending(admin=Depends(require_admin)):
    with db.get_conn() as conn:
        rows = conn.execute("SELECT * FROM spots WHERE status=0 ORDER BY id ASC").fetchall()
        return {"items": [serialize_spot(r, admin, full=True) for r in rows]}


@app.post("/api/admin/spots/{spot_id}/review")
def review(spot_id: int, body: ReviewIn, admin=Depends(require_admin)):
    if body.action not in ("approve", "reject"):
        raise HTTPException(400, "action 只能是 approve 或 reject")
    with db.get_conn() as conn:
        row = conn.execute("SELECT * FROM spots WHERE id=?", (spot_id,)).fetchone()
        if not row:
            raise HTTPException(404, "营地不存在")
        if body.action == "approve":
            conn.execute("UPDATE spots SET status=1, reject_reason='', updated_at=? WHERE id=?",
                         (db.now_iso(), spot_id))
            if row["created_by"]:
                db.add_points(conn, row["created_by"], POINT_RULES["spot_approved"],
                              "spot_approved", spot_id)
                notify.notify(conn, row["created_by"], "spot_approved", "营地上线了",
                              f"「{row['name']}」已通过审核，获得 {POINT_RULES['spot_approved']} 积分。",
                              f"spot:{spot_id}")
        else:
            conn.execute("UPDATE spots SET status=2, reject_reason=?, updated_at=? WHERE id=?",
                         (body.reason or "信息不符合规范", db.now_iso(), spot_id))
            if row["created_by"]:
                notify.notify(conn, row["created_by"], "spot_rejected", "营地未通过审核",
                              f"「{row['name']}」：{body.reason or '信息不符合规范'}",
                              f"spot:{spot_id}")
        db.audit(conn, admin["id"], f"review_{body.action}", f"spot:{spot_id}", body.reason)
        return {"ok": True, "status": 1 if body.action == "approve" else 2}


@app.get("/api/admin/stats")
def stats(admin=Depends(require_admin)):
    with db.get_conn() as conn:
        def one(sql, *a):
            return conn.execute(sql, a).fetchone()[0]
        today = db.now_iso()[:10]
        return {
            "users": one("SELECT COUNT(*) FROM users"),
            "members": one("SELECT COUNT(*) FROM users WHERE level=1"),
            "anonymous": one("SELECT COUNT(*) FROM users WHERE username IS NULL OR username=''"),
            "new_users_today": one("SELECT COUNT(*) FROM users WHERE created_at LIKE ?", f"{today}%"),
            "spots_total": one("SELECT COUNT(*) FROM spots"),
            "spots_pending": one("SELECT COUNT(*) FROM spots WHERE status=0"),
            "spots_live": one("SELECT COUNT(*) FROM spots WHERE status=1"),
            "spots_rejected": one("SELECT COUNT(*) FROM spots WHERE status=2"),
            "spots_with_photo": one("SELECT COUNT(*) FROM spots WHERE images != '[]' AND images != ''"),
            "spots_today": one("SELECT COUNT(*) FROM spots WHERE created_at LIKE ?", f"{today}%"),
            "ratings": one("SELECT COUNT(*) FROM ratings"),
            "orders_paid": one("SELECT COUNT(*) FROM orders WHERE status=1"),
            "revenue_fen": one("SELECT COALESCE(SUM(amount_fen),0) FROM orders WHERE status=1"),
            "revenue_today_fen": one(
                "SELECT COALESCE(SUM(amount_fen),0) FROM orders WHERE status=1 AND paid_at LIKE ?",
                f"{today}%"),
            "notifications": one("SELECT COUNT(*) FROM notifications"),
            "unread_notify": one("SELECT COUNT(*) FROM notifications WHERE is_read=0"),
            "uploads": one("SELECT COUNT(*) FROM uploads"),
            "upload_bytes": one("SELECT COALESCE(SUM(bytes),0) FROM uploads"),
        }


@app.get("/api/admin/spots")
def admin_spots(
    status: Optional[int] = Query(default=None, description="0待审 1已上线 2已驳回"),
    keyword: str = "",
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    admin=Depends(require_admin),
):
    where, params = ["1=1"], []
    if status is not None:
        where.append("status = ?")
        params.append(status)
    if keyword:
        where.append("(name LIKE ? OR province LIKE ? OR city LIKE ?)")
        kw = f"%{keyword}%"
        params += [kw, kw, kw]
    w = " AND ".join(where)

    with db.get_conn() as conn:
        total = conn.execute(f"SELECT COUNT(*) c FROM spots WHERE {w}", params).fetchone()["c"]
        rows = conn.execute(
            f"SELECT * FROM spots WHERE {w} ORDER BY id DESC LIMIT ? OFFSET ?",
            params + [size, (page - 1) * size]).fetchall()
        items = []
        for r in rows:
            d = serialize_spot(r, admin, full=True)
            d["submitter"] = ""
            if r["created_by"]:
                u = conn.execute("SELECT nickname, user_no FROM users WHERE id=?",
                                 (r["created_by"],)).fetchone()
                if u:
                    d["submitter"] = f"{u['nickname']}({u['user_no']})"
            items.append(d)
        return {"total": total, "page": page, "size": size,
                "pages": max(1, (total + size - 1) // size), "items": items}


@app.patch("/api/admin/spots/{spot_id}")
def admin_update_spot(spot_id: int, body: dict, admin=Depends(require_admin)):
    """后台直接编辑营地。

    审计这次记录了**改前值 + 改后值**。以前只记"改了哪些字段"，
    出问题时根本看不出原来是错的还是改错的。
    """
    editable = {"name", "lng", "lat", "province", "city", "spot_type", "address",
                "phone", "price_range", "detail"}
    with db.get_conn() as conn:
        row = conn.execute("SELECT * FROM spots WHERE id=?", (spot_id,)).fetchone()
        if not row:
            raise HTTPException(404, "营地不存在")
        sets, params, changes = [], [], {}
        for k, v in body.items():
            before = row[k] if k in row.keys() else None
            if k in editable:
                sets.append(f"{k} = ?")
                params.append(v)
                changes[k] = {"from": before, "to": v}
            elif k == "facilities" and isinstance(v, list):
                sets.append("facilities = ?")
                params.append(db.dumps(v))
                changes[k] = {"from": db.loads(row["facilities"], []), "to": v}
            elif k == "images" and isinstance(v, list):
                sets.append("images = ?")
                params.append(db.dumps(v))
                changes[k] = {"from": normalize_images(row["images"]), "to": v}
            elif k == "status" and v in (0, 1, 2, 3):
                sets.append("status = ?")
                params.append(v)
                changes[k] = {"from": row["status"], "to": v}
        if not sets:
            raise HTTPException(400, "没有可更新的字段")
        sets.append("updated_at = ?")
        params += [db.now_iso(), spot_id]
        conn.execute(f"UPDATE spots SET {', '.join(sets)} WHERE id = ?", params)
        db.audit(conn, admin["id"], "admin_edit_spot", f"spot:{spot_id}",
                 json.dumps(changes, ensure_ascii=False)[:2000])
        return {"ok": True, "changes": changes}


@app.delete("/api/admin/spots/{spot_id}")
def admin_delete_spot(spot_id: int, admin=Depends(require_admin)):
    """物理删除营地（仅用于垃圾/测试数据，正常下架请用 status=3）。"""
    with db.get_conn() as conn:
        row = conn.execute("SELECT name, images FROM spots WHERE id=?", (spot_id,)).fetchone()
        if not row:
            raise HTTPException(404, "营地不存在")
        conn.execute("DELETE FROM ratings WHERE spot_id=?", (spot_id,))
        conn.execute("DELETE FROM spots WHERE id=?", (spot_id,))
        # 图片交给孤儿回收处理，这里只解除引用
        for it in normalize_images(row["images"]):
            conn.execute("UPDATE uploads SET spot_id=NULL WHERE path=?", (it["url"],))
        db.audit(conn, admin["id"], "admin_delete_spot", f"spot:{spot_id}", row["name"])
        return {"ok": True, "deleted": row["name"]}


@app.get("/api/admin/users")
def admin_users(
    keyword: str = "",
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    admin=Depends(require_admin),
):
    where, params = ["1=1"], []
    if keyword:
        where.append("(nickname LIKE ? OR user_no LIKE ? OR phone LIKE ?)")
        kw = f"%{keyword}%"
        params += [kw, kw, kw]
    w = " AND ".join(where)
    with db.get_conn() as conn:
        total = conn.execute(f"SELECT COUNT(*) c FROM users WHERE {w}", params).fetchone()["c"]
        rows = conn.execute(
            f"SELECT * FROM users WHERE {w} ORDER BY id DESC LIMIT ? OFFSET ?",
            params + [size, (page - 1) * size]).fetchall()
        items = []
        for r in rows:
            cnt = conn.execute("SELECT COUNT(*) c FROM spots WHERE created_by=?",
                               (r["id"],)).fetchone()["c"]
            d = db.row_to_dict(r)
            for k in ("password_hash", "salt", "secret_key_hash"):
                d.pop(k, None)
            d["is_member"] = db.is_member(r)
            d["is_anonymous"] = not r["username"]
            d["spots_count"] = cnt
            # 后台看得到完整号码（客服需要联系用户），但仍脱敏展示，
            # 需要完整号码时走单独的、有审计的接口
            d["phone"] = common.mask_phone(r["phone"]) if r["phone"] else ""
            items.append(d)
        return {"total": total, "page": page, "pages": max(1, (total + size - 1) // size),
                "items": items}


@app.post("/api/admin/users/{uid}/ban")
def admin_ban_user(uid: int, body: dict, admin=Depends(require_admin)):
    """封禁/解封。封禁后该用户的 token 立即失效。"""
    banned = 1 if body.get("banned") else 0
    with db.get_conn() as conn:
        row = conn.execute("SELECT nickname FROM users WHERE id=?", (uid,)).fetchone()
        if not row:
            raise HTTPException(404, "用户不存在")
        conn.execute("UPDATE users SET is_banned=? WHERE id=?", (banned, uid))
        if banned:
            conn.execute("DELETE FROM tokens WHERE user_id=?", (uid,))
        db.audit(conn, admin["id"], "ban" if banned else "unban", f"user:{uid}", row["nickname"])
        return {"ok": True, "banned": bool(banned)}


@app.get("/api/admin/admins")
def admin_list(admin=Depends(require_admin)):
    """管理员列表。只返回编号和密钥末 4 位，不返回任何可用于登录的信息。"""
    with db.get_conn() as conn:
        rows = conn.execute(
            "SELECT id, user_no, nickname, key_preview, username, created_at"
            " FROM users WHERE is_admin=1 ORDER BY id").fetchall()
        return {"items": [
            {**db.row_to_dict(r),
             "is_self": r["id"] == admin["id"],
             "has_password": bool(r["username"])}
            for r in rows
        ]}


@app.get("/api/admin/audit")
def admin_audit(limit: int = Query(50, ge=1, le=200), admin=Depends(require_admin)):
    """操作日志，用于责任追溯。detail 里现在带改前/改后值。"""
    with db.get_conn() as conn:
        rows = conn.execute(
            "SELECT a.*, u.nickname FROM audit_log a LEFT JOIN users u ON u.id=a.actor"
            " ORDER BY a.id DESC LIMIT ?", (limit,)).fetchall()
        return {"items": [db.row_to_dict(r) for r in rows]}


@app.post("/api/admin/notify/broadcast")
def admin_broadcast(body: dict, admin=Depends(require_admin)):
    """后台群发站内信（发给全体用户或指定用户）。"""
    title = (body.get("title") or "").strip()
    text = (body.get("body") or "").strip()
    uid = body.get("user_id")
    if not title:
        raise HTTPException(400, "标题不能为空")
    with db.get_conn() as conn:
        if uid:
            notify.push(conn, int(uid), "system", title, text)
            n = 1
        else:
            ids = [r["id"] for r in conn.execute(
                "SELECT id FROM users WHERE is_banned=0").fetchall()]
            for i in ids:
                notify.notify(conn, i, "system", title, text)
            n = len(ids)
        db.audit(conn, admin["id"], "broadcast", f"users:{n}", title)
    return {"ok": True, "sent": n}


@app.get("/api/meta")
def meta():
    # 演示凭证只在开发模式下回传。它来自 seed.py 随机生成的 data/dev_keys.json，
    # 生产环境不生成这个文件，前端登录框也就不再显示"演示密钥"提示。
    demo_keys = None
    if config.DEV:
        try:
            demo_keys = json.loads(
                (config.DATA_DIR / "dev_keys.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            demo_keys = None
    return {"spot_types": SPOT_TYPES, "facility_keys": FACILITY_KEYS,
            "point_rules": POINT_RULES, "plans": PLANS,
            "free_quota": FREE_DAILY_DETAIL_QUOTA,
            "dev": config.DEV, "demo_keys": demo_keys,
            # 非空 = 前端走自建瓦片代理，而不是让浏览器直连源站
            "tile_proxy": config.TILE_PROXY}


# ---------------------------------------------------------------- 自建瓦片代理
# 浏览器 -> 我们的 /tiles/{up}/{path} -> 上游（默认 OpenFreeMap，免费无 Key）
# 落盘缓存 + 单飞回源 + 防盗链，细节都在 tileproxy.py 里。

@app.get("/tiles/{up}/{rest:path}")
def tile_proxy(request: Request, up: str, rest: str):
    # 用同步 def：阻塞的回源 IO 交给线程池，不占事件循环
    return tileproxy.handle(request, up, rest)


@app.get("/api/admin/tile-cache")
def tile_cache_stat(admin=Depends(require_admin)):
    """瓦片缓存占用与命中率，用来判断是不是该换自建离线瓦片了。"""
    return tileproxy.stats()


@app.post("/api/admin/tile-cache/purge")
def tile_cache_purge(admin=Depends(require_admin)):
    return tileproxy.purge()


# ---------------------------------------------------------------- 附加路由（站内通知）

from routes_extra import router as extra_router   # noqa: E402
app.include_router(extra_router)


# ---------------------------------------------------------------- 静态资源

FRONTEND_DIR = str(config.FRONTEND_DIR)

# 用户上传的图片：直接静态挂载。生产环境建议换成对象存储 + CDN。
app.mount("/uploads", StaticFiles(directory=str(config.UPLOAD_DIR)), name="uploads")

if os.path.isdir(FRONTEND_DIR):
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")

    @app.get("/")
    def index():
        return FileResponse(os.path.join(FRONTEND_DIR, "index.html"))

    def _admin_page():
        """后台管理页面。路径可通过 RVCAMP_ADMIN_PATH 改掉。"""
        return FileResponse(os.path.join(FRONTEND_DIR, "admin.html"))

    app.add_api_route(config.ADMIN_PATH, _admin_page, methods=["GET"],
                      include_in_schema=False)

    # 开发模式保留 /admin 方便调试；生产环境若已改成自定义路径，/admin 直接 404
    if config.DEV and config.ADMIN_PATH != "/admin":
        app.add_api_route("/admin", _admin_page, methods=["GET"], include_in_schema=False)
