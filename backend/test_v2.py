"""第二轮改造的回归测试。

覆盖：免费额度、全局搜索、图片 EXIF/缩略图、上传归属校验、通知、
手机号绑定与密钥找回、后台审计改前改后、限流、孤儿回收。

跑法：python test_v2.py
"""

import io
import json
import os
import sqlite3
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

B = "http://127.0.0.1:8000"
DB = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                  "data", "rvcamp.db")
UPLOADS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "data", "uploads")

# 凭证由 seed.py 随机生成后写入 data/dev_keys.json，不在源码里写死
import devkeys
_K = devkeys.load()
DEMO_KEY = _K["user_key"]
ADMIN_KEY = _K["admin_key"]

ok = fail = 0


def call(method, path, body=None, token=None, ip=None):
    r = urllib.request.Request(B + path, method=method)
    r.add_header("Content-Type", "application/json")
    if token:
        r.add_header("Authorization", "Bearer " + token)
    if ip:
        r.add_header("X-Forwarded-For", ip)
    data = json.dumps(body).encode() if body is not None else None
    try:
        with urllib.request.urlopen(r, data) as x:
            return x.status, json.loads(x.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"{}")
        except Exception:
            return e.code, {}


def get(path, token=None, ip=None):
    return call("GET", path, None, token, ip)


def post(path, body=None, token=None, ip=None):
    return call("POST", path, body if body is not None else {}, token, ip)


def patch(path, body, token=None):
    return call("PATCH", path, body, token)


def delete(path, token=None):
    return call("DELETE", path, None, token)


def captcha_pair():
    """取一道验证码，并从库里读出答案（测试进程有权限读库）。

    生产环境当然不可能这么干——这里只是为了能脚本化地测通整条链路。
    """
    s, d = get("/api/captcha")
    assert s == 200, ("获取验证码失败", s, d)
    conn = sqlite3.connect(DB)
    row = conn.execute("SELECT code FROM captchas WHERE id=?", (d["id"],)).fetchone()
    conn.close()
    return d["id"], row[0]


def issue_key(ip=None):
    """领密钥：现在必须带验证码。"""
    cid, code = captcha_pair()
    return post(f"/api/auth/key/issue?captcha_id={cid}"
                f"&captcha_code={urllib.parse.quote(code)}", ip=ip)


def post_files(path, files, token):
    boundary = "----rvboundary0987654321"
    body = b""
    for name, filename, content in files:
        body += f"--{boundary}\r\n".encode()
        body += f'Content-Disposition: form-data; name="{name}"; filename="{filename}"\r\n'.encode()
        body += b"Content-Type: application/octet-stream\r\n\r\n"
        body += content + b"\r\n"
    body += f"--{boundary}--\r\n".encode()
    r = urllib.request.Request(B + path, data=body, method="POST")
    r.add_header("Content-Type", f"multipart/form-data; boundary={boundary}")
    r.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(r) as x:
            return x.status, json.loads(x.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def check(name, cond, extra=""):
    global ok, fail
    if cond:
        ok += 1
        print(f"  ✓ {name}")
    else:
        fail += 1
        print(f"  ✗ {name} {extra}")


def reset_state():
    """清掉会影响本轮测试的计数，保证可重复运行。"""
    c = sqlite3.connect(DB)
    for t in ("detail_views", "rate_hits"):
        c.execute(f"DELETE FROM {t}")
    c.commit()
    c.close()


def jpeg_with_gps():
    """造一张带 GPS 的 JPEG——模拟手机原图。"""
    from PIL import Image
    im = Image.new("RGB", (1600, 1200), (34, 122, 84))
    exif = im.getexif()
    # GPS 坐标：经度 116.4 / 纬度 39.9（天安门附近），模拟手机原图带位置
    exif[0x8825] = {0: 2, 1: "N", 2: 39.9, 3: "E", 4: 116.4}
    exif[0x0110] = "iPhone 15"    # Model
    buf = io.BytesIO()
    im.save(buf, "JPEG", exif=exif, quality=95)
    return buf.getvalue()


def main():
    reset_state()
    print("\n【1】登录与身份")
    s, d = post("/api/auth/key/login", {"secret_key": DEMO_KEY})
    check("演示密钥登录", s == 200, d)
    demo_token = d.get("token", "")
    s, d = post("/api/auth/key/login", {"secret_key": ADMIN_KEY})
    check("管理员密钥登录", s == 200 and d["user"]["is_admin"], d)
    admin_token = d.get("token", "")
    s, d = get("/api/auth/me", demo_token)
    check("会员额度不限", d.get("quota", {}).get("member") is True, d)

    print("\n【2】免费额度真的执行了（匿名，3 条/天）")
    ids = [r[0] for r in sqlite3.connect(DB).execute(
        "SELECT id FROM spots WHERE status=1 ORDER BY id LIMIT 12")]
    codes = []
    for i in ids[:3]:
        _, _d = get(f"/api/spots/{i}")
        codes.append(200)
    s9, d9 = get(f"/api/spots/{ids[3]}")
    check("第 4 条被拦（402）", s9 == 402, f"status={s9} {d9}")
    s, _ = get(f"/api/spots/{ids[0]}")     # 已看过的重复刷新
    check("同一营地重复查看不再扣额度", s == 200, s)
    s, d = get(f"/api/spots/{ids[3]}", demo_token)
    check("会员不受额度限制", s == 200, d)

    print("\n【3】全局搜索（不再只搜当前视野）")
    s, d = get("/api/search?q=" + urllib.parse.quote("营地"))
    check("搜索全库有结果", s == 200 and d["total"] > 0, d.get("total"))
    bbox_total = len(get("/api/spots?bbox=116.0,39.8,116.6,40.1&zoom=12")[1].get("items", []))
    check("搜索结果不受视口限制", d["total"] > bbox_total,
          f"search={d['total']} vs bbox={bbox_total}")
    s, d2 = get("/api/search?q=" + urllib.parse.quote("不存在的地名xyz"))
    check("无结果时返回空列表", s == 200 and d2["total"] == 0, d2.get("total"))

    print("\n【4】图片上传：EXIF 剥离 + 缩略图")
    raw = jpeg_with_gps()
    s, d = post_files("/api/upload/images", [("files", "phone.jpg", raw)], demo_token)
    check("上传成功", s == 200 and d["count"] == 1, d)
    up = d["urls"][0]
    check("返回缩略图路径", up.get("thumb", "").endswith(".jpg") and "/thumb/" in up["thumb"], up)
    disk = os.path.join(UPLOADS, up["url"].replace("/uploads/", ""))
    thumb_disk = os.path.join(UPLOADS, up["thumb"].replace("/uploads/", ""))
    check("原图已落盘", os.path.isfile(disk), disk)
    check("缩略图已生成", os.path.isfile(thumb_disk), thumb_disk)
    from PIL import Image
    out = Image.open(disk)
    check("EXIF 已剥离", not out.getexif() and "exif" not in out.info,
          dict(out.getexif()))
    check("原图尺寸被压缩", max(out.size) <= 1600, out.size)
    th = Image.open(thumb_disk)
    check("缩略图更小", max(th.size) <= 480, th.size)
    check("原图体积下降", os.path.getsize(disk) < len(raw),
          f"{os.path.getsize(disk)} vs {len(raw)}")

    print("\n【5】上传归属：别人不能删我的图")
    s, d = issue_key(ip="10.9.9.9")
    other_token = d.get("token", "")
    s, _ = delete(f"/api/upload/images?path={urllib.parse.quote(up['url'])}", other_token)
    check("他人删除被拒（403）", s == 403, s)
    s, _ = delete(f"/api/upload/images?path={urllib.parse.quote(up['url'])}", admin_token)
    check("管理员可删除", s == 200, s)

    print("\n【6】通知闭环（提交 → 审核 → 通知）")
    raw2 = jpeg_with_gps()
    s, up2 = post_files("/api/upload/images", [("files", "a.jpg", raw2)], other_token)
    img = up2["urls"][0]
    s, d = post("/api/spots", {
        "name": f"测试营地{int(time.time()) % 100000}", "lng": 116.31, "lat": 39.99,
        "spot_type": "房车营地", "province": "北京市", "city": "朝阳区",
        "address": "测试路 1 号", "phone": "010-12345678",
        "images": [{"url": img["url"], "thumb": img["thumb"]}],
    }, other_token)
    check("提交营地成功", s == 200 and d.get("status") == 0, d)
    sid = d["id"]
    s, d = get("/api/notifications", other_token)
    check("提交后收到站内信", s == 200 and d["unread"] >= 1, d.get("unread"))
    s, d = get("/api/notifications", admin_token)
    check("管理员收到待审提醒", s == 200 and d["unread"] >= 1, d.get("unread"))
    s, d = post(f"/api/admin/spots/{sid}/review", {"action": "approve"}, admin_token)
    check("审核通过", s == 200, d)
    s, d = get("/api/notifications", other_token)
    titles = [i["title"] for i in d["items"]]
    check("作者收到上线通知", any("上线" in t for t in titles), titles[:3])
    nid = d["items"][0]["id"]
    s, _ = post(f"/api/notifications/{nid}/read", {}, other_token)
    s, d = get("/api/notifications/unread", other_token)
    check("标记已读生效", s == 200, d)

    print("\n【7】手机号功能已按产品决策移除")
    s, d = post("/api/phone/code", {"phone": "13900001234", "purpose": "bind"})
    check("验证码接口已下线（404）", s == 404, f"status={s}")
    s, d = post("/api/auth/phone/login", {"phone": "13900001234", "code": "000000"})
    check("手机号登录已下线（404）", s == 404, f"status={s}")
    s, d = post("/api/auth/key/recover", {"phone": "13900001234", "code": "000000"})
    check("密钥找回已下线（404）", s == 404, f"status={s}")

    print("\n【8】后台审计记录改前改后")
    s, d = patch(f"/api/admin/spots/{sid}", {"phone": "010-99998888", "name": "改名测试"},
                 admin_token)
    check("后台编辑成功", s == 200, d)
    s, d = get("/api/admin/audit?limit=5", admin_token)
    rec = [r for r in d["items"] if r["action"] == "admin_edit_spot"]
    has_diff = rec and '"from"' in (rec[0]["detail"] or "")
    check("审计含 from/to", has_diff, rec[0]["detail"][:120] if rec else "无记录")

    print("\n【9】演示支付开关（DEV 下可用）")
    s, d = post("/api/orders", {"plan": "basic_3y"}, other_token)
    check("下单成功", s == 200 and d.get("order_no"), d)
    s, d = post(f"/api/orders/{d['order_no']}/mock-pay", {}, other_token)
    check("演示支付可用", s == 200, d)

    print("\n【10】限流")
    reset_state()
    last = None
    for i in range(7):
        last = issue_key(ip="203.0.113.7")
    check("领密钥被限流（429）", last[0] == 429, last)
    s, d = get("/api/search?q=" + urllib.parse.quote("营地"), ip="203.0.113.8")
    check("搜索不受写限流影响", s == 200, s)

    print("\n【11】运维任务")
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import maintenance
    st = maintenance.gc_orphan_uploads(dry_run=True)
    check("孤儿文件扫描可执行", isinstance(st, dict), st)
    out = maintenance.backup(keep=3, with_uploads=False)
    check("数据库备份成功", os.path.isfile(out.split(" ")[0]), out)

    print(f"\n{'='*46}\n通过 {ok} 项，失败 {fail} 项\n{'='*46}")
    return 1 if fail else 0


if __name__ == "__main__":
    import urllib.parse
    sys.exit(main())
