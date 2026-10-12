"""邀请奖励、积分规则、以及"换号刷免费额度"的防线测试。

分三段：
  A. 数据层离线测试（临时库，不动开发数据）——反作弊判定与"跨账号额度桶"。
     这部分各种边界条件自己造，不需要网络。
  B. 接口层（打运行中的 8000）——领密钥带邀请码、/api/invite 两个接口、
     积分兑换档位、营地上线 +100。
  C. 换密钥能不能把免费额度刷回去——这是最容易变成"永久免费"的一条缝。

为什么 A 要离线做：场景里有"同一 IP 全是同一个人""一个人当天邀请 20 个"
这类极端情况，通过 HTTP 复现的话要么伪造大量请求头，要么污染开发库。
直接调 invite / app 里的函数反而更准，也跑得快。
"""
import json
import os
import random
import sqlite3
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request

B = "http://127.0.0.1:8000"
ok = failed = 0

# 占位：下面的 os.environ 必须在 import db 之前设置
tmp_db = os.path.join(tempfile.mkdtemp(), "invite.db")
os.environ["RVCAMP_DB"] = tmp_db
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import config           # noqa: E402
import db               # noqa: E402
import invite           # noqa: E402


last = {}


def call(method, path, body=None, token=None, headers=None):
    global last
    r = urllib.request.Request(B + path, method=method)
    r.add_header("Content-Type", "application/json")
    if token:
        r.add_header("Authorization", "Bearer " + token)
    for k, v in (headers or {}).items():
        r.add_header(k, v)
    data = json.dumps(body).encode() if body is not None else None
    try:
        with urllib.request.urlopen(r, data) as x:
            last = json.loads(x.read())
            return x.status, last
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            last = json.loads(raw)
        except ValueError:
            last = {"detail": raw[:200].decode("utf-8", "ignore")}
        return e.code, last


def check(name, cond, extra=""):
    global ok, failed
    if cond:
        ok += 1
        print(f"  ✅ {name} {extra}")
    else:
        failed += 1
        print(f"  ❌ {name} {extra}")


def line(t):
    print("\n" + "=" * 66 + f"\n{t}\n" + "=" * 66)


# ================================================================ A
line("A. 数据层：反作弊判定（临时库）")

db.init_db()


def mk_user(nick, ip, dev):
    """在临时库里造一个用户，带注册 IP 与设备指纹。"""
    with db.get_conn() as c:
        cur = c.execute(
            "INSERT INTO users(user_no, nickname, created_at) VALUES(?,?,?)",
            (str(random.randrange(10000000, 99999999)), nick, db.now_iso()))
        uid = cur.lastrowid
    with db.get_conn() as c:
        invite.register_identity(c, uid, ip, dev)
    return uid


def pts_of(uid):
    with db.get_conn() as c:
        return c.execute("SELECT points FROM users WHERE id=?", (uid,)).fetchone()["points"]


with db.get_conn() as c:
    a = mk_user("邀请人甲", "203.0.113.10", "AAA-DEVICE-1")
    code_a = c.execute("SELECT invite_code FROM users WHERE id=?", (a,)).fetchone()["invite_code"]

# 1. 不能邀请自己
with db.get_conn() as c:
    r = invite.bind(c, a, code_a, "203.0.113.10", "AAA-DEVICE-1")
check("自己邀请自己被拒", r["status"] == "rejected" and "自己" in r["reason"], f"-> {r['reason']}")

# 2. 同一网络 + 同一设备（最典型的"换个号接着薅"）
with db.get_conn() as c:
    b = mk_user("小号乙", "203.0.113.10", "AAA-DEVICE-1")
    r = invite.bind(c, b, code_a, "203.0.113.10", "AAA-DEVICE-1")
check("同网络 + 同设备被拒", r["status"] == "rejected" and "同一设备" in r["reason"],
      f"-> {r['reason']}")
with db.get_conn() as k:
    n_rows = k.execute("SELECT COUNT(*) c FROM invites WHERE invitee_id=?", (b,)).fetchone()["c"]
check("被拒时不写 invites 行", n_rows == 0)

# 3. 不同网络、不同设备 -> 判定通过，**当场发分**
before = pts_of(a)
with db.get_conn() as c:
    c_ = mk_user("真人丙", "198.51.100.20", "BBB-DEVICE-2")
    r = invite.bind(c, c_, code_a, "198.51.100.20", "BBB-DEVICE-2")
check("正常邀请 -> 立即发放", r["status"] == "rewarded" and r["points"] == config.INVITE_REWARD,
      f"-> {r}")
check("邀请人积分 +20", pts_of(a) == before + config.INVITE_REWARD, f"{before} -> {pts_of(a)}")
with db.get_conn() as k:
    row = k.execute("SELECT * FROM invites WHERE invitee_id=?", (c_,)).fetchone()
check("invites 记为 rewarded", row["status"] == "rewarded" and row["rewarded_at"])
check("弱命中被标记出来", row["same_ip"] == 0 and row["same_device"] == 0)
with db.get_conn() as k:
    diff = k.execute("SELECT reason FROM point_logs WHERE user_id=? ORDER BY id DESC LIMIT 1",
                     (a,)).fetchone()["reason"]
check("积分流水写的是 invite_reward", diff == "invite_reward", f"-> {diff}")

# 4. 弱命中：同一 WiFi（IP 完全相同）但换了另一台电脑 —— 放过去，但要留痕。
#    这里比的是"注册 IP 是否完全相同"（同一 NAT 出口），而不是同 /24：
#    同一个 /24 可能是一整层办公楼，太宽；完全相同的出口 IP 才值得怀疑。
with db.get_conn() as c:
    d = mk_user("同事丁", "203.0.113.10", "DDD-DEVICE-4")
    r = invite.bind(c, d, code_a, "203.0.113.10", "DDD-DEVICE-4")
with db.get_conn() as k:
    row = k.execute("SELECT * FROM invites WHERE invitee_id=?", (d,)).fetchone()
check("同 IP 不同设备 -> 仍然发放", r["status"] == "rewarded", f"-> {r}")
check("同 IP 被写成弱命中", row["same_ip"] == 1 and row["same_device"] == 0,
      f"-> ip={row['same_ip']} dev={row['same_device']}")

# 5. 互邀：丙是被甲邀请的，丙反过来邀请甲 -> 拒绝
with db.get_conn() as k:
    code_c = k.execute("SELECT invite_code FROM users WHERE id=?", (c_,)).fetchone()["invite_code"]
with db.get_conn() as c:
    r = invite.bind(c, a, code_c, "198.51.100.20", "BBB-DEVICE-2")
check("互相邀请被拒", r["status"] == "rejected" and "互相" in r["reason"], f"-> {r['reason']}")

# 6. 一个人只能被算一次
with db.get_conn() as c:
    r = invite.bind(c, c_, code_a, "198.51.100.20", "BBB-DEVICE-2")
check("同一个人不会被重复计入", r["status"] == "rejected" and "登记过" in r["reason"],
      f"-> {r['reason']}")

# 7. 同一网段批量：这个网段里已经有丙这笔记录了，把阈值压到 1 就应该卡住后续
_old_net = config.INVITE_NET_MAX
config.INVITE_NET_MAX = 1
with db.get_conn() as c:
    e = mk_user("批量号戊", "198.51.100.55", "EEE-DEVICE-5")
    r = invite.bind(c, e, code_a, "198.51.100.55", "EEE-DEVICE-5")
check("同一网段超出阈值被拒", r["status"] == "rejected" and "同一网络" in r["reason"],
      f"-> {r['reason']}")
config.INVITE_NET_MAX = _old_net

# 8. 日上限 / 总量上限
_old_daily, _old_total = config.INVITE_DAILY_CAP, config.INVITE_TOTAL_CAP
config.INVITE_DAILY_CAP = 0
with db.get_conn() as c:
    f = mk_user("超限号己", "198.51.100.31", "FFF-DEVICE-6")
    r = invite.bind(c, f, code_a, "198.51.100.31", "FFF-DEVICE-6")
check("邀请人当日超上限被拒", r["status"] == "rejected" and "上限" in r["reason"], f"-> {r['reason']}")
config.INVITE_DAILY_CAP = _old_daily
config.INVITE_TOTAL_CAP = _old_total

# 9. 补填邀请码的时间窗
with db.get_conn() as c:
    g = mk_user("迟到庚", "198.51.100.44", "GGG-DEVICE-7")
    c.execute("UPDATE users SET created_at=? WHERE id=?", ("2020-01-01T00:00:00", g))
with db.get_conn() as c:
    r = invite.bind_later(c, g, code_a, "198.51.100.44", "GGG-DEVICE-7")
check("注册超窗口不能再补填", r["status"] == "rejected" and "超过" in r["reason"], f"-> {r['reason']}")

# ================================================================ A2
line("A2. 数据层：换号能不能把免费额度刷回去")

import app                                    # noqa: E402  （要 import heavy deps）

app.FREE_DAILY_DETAIL_QUOTA = config.FREE_DAILY_DETAIL_QUOTA


def is_member_stub(row):
    return False


def view(uid, spot_id, ip, dev):
    """模拟某人查看一个营地详情，返回是否被放行。"""
    with db.get_conn() as c:
        user = c.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
        return app._charge_detail_quota(c, dict(user), spot_id, ip, dev)


with db.get_conn() as c:
    u1 = c.execute(
        "INSERT INTO users(user_no, nickname, created_at) VALUES(?,?,?)",
        (str(random.randrange(10000000, 99999999)), "额度A号", db.now_iso())).lastrowid
    u2 = c.execute(
        "INSERT INTO users(user_no, nickname, created_at) VALUES(?,?,?)",
        (str(random.randrange(10000000, 99999999)), "额度B号", db.now_iso())).lastrowid

check("第 1 次查看放行", view(u1, 1, "203.0.113.9", "DEV-X")["ok"])
check("第 2 次查看放行", view(u1, 2, "203.0.113.9", "DEV-X")["ok"])
check("第 3 次查看放行", view(u1, 3, "203.0.113.9", "DEV-X")["ok"])
r4 = view(u1, 4, "203.0.113.9", "DEV-X")
check("第 4 次被本人额度拦住", not r4["ok"] and "额度已用完" in r4["why"], f"-> {r4}")

# 换密钥不换账号：uid 没变，所以额度不会刷新（这是设计效果，见 _user_key 注释）
r5 = view(u1, 5, "203.0.113.9", "DEV-X")
check("换发密钥（同一 uid）不刷新额度", not r5["ok"], f"-> {r5}")

# 真正能刷新的是"再领一个新密钥"= 新账号：靠设备桶和网络桶兜底
_old_dev, _old_net_q = config.FREE_DEVICE_QUOTA, config.FREE_NETWORK_QUOTA
config.FREE_DEVICE_QUOTA = 4          # 压小以便一次跑完
check("新账号第 1 次查看放行", view(u2, 10, "203.0.113.9", "DEV-X")["ok"])
r = view(u2, 11, "203.0.113.9", "DEV-X")
check("同一设备累计超上限后，新账号也被拦", not r["ok"] and "设备" in r["why"], f"-> {r}")
with db.get_conn() as k:
    row_u2 = k.execute("SELECT * FROM users WHERE id=?", (u2,)).fetchone()
q = app._quota_public(dict(row_u2), "203.0.113.9", "DEV-X")
check("前端能拿到被拦原因", q["blocked_by"] and q["blocked_by"]["why"] == r["why"],
      f"-> {q.get('blocked_by')}")

# 换台新设备、同一个网络 -> 网络桶继续兜。先清掉前面几步留下的计数，
# 否则这一段会连 u1 看过的三条一起算进去，测不出"恰好卡在阈值上"。
with db.get_conn() as k:
    k.execute("DELETE FROM detail_views")
config.FREE_NETWORK_QUOTA = 2        # 整个出口当天最多免费看 2 个不同的营地
check("换设备后重新放行", view(u2, 20, "203.0.113.9", "DEV-Y")["ok"])
check("换设备第 2 次放行", view(u2, 21, "203.0.113.9", "DEV-Y")["ok"])
r = view(u2, 22, "203.0.113.9", "DEV-Y")
check("同一网络累计超上限后被拦", not r["ok"] and "网络" in r["why"], f"-> {r}")
config.FREE_DEVICE_QUOTA, config.FREE_NETWORK_QUOTA = _old_dev, _old_net_q

# ================================================================ B
line("B. 接口层：领密钥带邀请码 / 邀请接口")

import subprocess           # noqa: E402
subprocess.run(["rm", "-rf", tmp_db], check=False)

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "data", "rvcamp.db")

with sqlite3.connect(DB_PATH) as k:
    k.execute("DELETE FROM rate_hits")
    k.commit()


def captcha_pair():
    s, d = call("GET", "/api/captcha")
    assert s == 200, (s, d)
    with sqlite3.connect(DB_PATH) as k:
        row = k.execute("SELECT code FROM captchas WHERE id=?", (d["id"],)).fetchone()
    return d["id"], row[0]


def key_issue(nick, ip, dev, code=""):
    """发一个新密钥。X-Forwarded-For 用来伪造"另一个网络出口"。"""
    cid, ccode = captcha_pair()
    q = {"captcha_id": cid, "captcha_code": ccode, "device": dev}
    if nick:
        q["nickname"] = nick
    if code:
        q["invite_code"] = code
    return call("POST", "/api/auth/key/issue?" + urllib.parse.urlencode(q),
                headers={"X-Forwarded-For": ip})


def show(name, s, expect=200):
    """带错误详情的断言，方便定位（限流/验证码/拒绝都走 400/429）。"""
    global last
    check(name, s == expect, "" if s == expect else f"-> HTTP {s} {last.get('detail', '')}")


IP_A, DEV_A = "203.0.113.101", "HTTP-DEV-A"
IP_B, DEV_B = "198.51.100.102", "HTTP-DEV-B"

# 昵称全站唯一，测试要能反复跑，所以每次都带随机后缀
SUF = str(random.randrange(1000, 9999))
s, d = key_issue("邀请人" + SUF, IP_A, DEV_A)
check("邀请人注册成功", s == 200, f"-> {s} {d.get('detail', '')}")
AT = d.get("token")

s, mine = call("GET", "/api/invite/mine", token=AT)
check("取到自己的邀请码", s == 200 and len(mine["code"]) >= 6, f"-> {mine.get('code')}")
CODE = mine["code"]
check("邀请人的 reward 已下发", mine["reward"] == 20)

# 同网络同设备 -> 判为本人，邀请不成立但账号照常创建
s, d = key_issue("自邀" + SUF, IP_A, DEV_A, CODE)
check("同网络同设备：账号仍能创建", s == 200, f"-> {s}")
check("同网络同设备：邀请被拒", d.get("invite_status") == "rejected",
      f"-> {d.get('invite_status')} {d.get('invite_message')}")

# 不同网络不同设备 -> 当场计 20 分
s, d = key_issue("受邀" + SUF, IP_B, DEV_B, CODE)
check("换网络换设备：邀请成立", d.get("invite_status") == "rewarded",
      f"-> {d.get('invite_status')} {d.get('invite_message')}")
BT = d["token"]
s, mine2 = call("GET", "/api/invite/mine", token=AT)
check("邀请列表里出现这位", mine2["stats"]["total"] == 1 and mine2["stats"]["rewarded"] == 1,
      f"-> {mine2['stats']}")
check("邀请人积分已到账", mine2["stats"]["rewarded"] * 20 == 20)

# 无效邀请码不影响注册
s, d = key_issue("乱填" + SUF, "198.51.100.155", "HTTP-DEV-C", "NOTEXIST")
check("邀请码填错也能注册", s == 200, f"-> {s}")
check("但会明说未生效", d.get("invite_status") == "rejected", f"-> {d.get('invite_message')}")

# 已邀请过的人不能再补填
s, d = call("POST", "/api/invite/bind", {"code": CODE, "device": "HTTP-DEV-Z"}, token=BT)
check("已有邀请关系 -> 补填被拒", s == 400, f"-> {s} {d.get('detail')}")

# 未登录不能查/不能绑
s, d = call("GET", "/api/invite/mine")
check("未登录查邀请 401", s == 401, f"-> {s}")
s, d = call("POST", "/api/invite/bind", {"code": CODE})
check("未登录补填 401", s == 401, f"-> {s}")

# 台账：/api/invite/mine 返回 code/link/stats/items/rules
check("邀请页返回链接与规则", bool(mine2.get("link")) and bool(mine2.get("rules")),
      f"-> {mine2.get('link')}")

# ================================================================ B2
line("B2. 接口层：积分规则与兑换档位")

s, noreg = call("GET", "/api/points", token=BT)
check("兑换档位只有 300 / 600", sorted(x["points"] for x in noreg["exchange"]) == [300, 600],
      f"-> {[ (x['points'], x['days']) for x in noreg['exchange'] ]}")
ex = {x["points"]: x for x in noreg["exchange"]}
check("300 分 -> 90 天（3 个月）", ex[300]["days"] == 90 and ex[300]["label"] == "3 个月",
      f"-> {ex[300]}")
check("600 分 -> 180 天（6 个月）", ex[600]["days"] == 180 and ex[600]["label"] == "6 个月",
      f"-> {ex[600]}")
check("营地积分为 100", noreg["rules"]["spot_approved"] == 100, f"-> {noreg['rules']}")

s, hmm = call("GET", "/api/meta")
check("meta 下发邀请奖励数", hmm.get("invite_reward") == 20, f"-> {hmm.get('invite_reward')}")

s, d = call("POST", "/api/points/exchange/500", token=BT)
check("旧档位 500 已不可兑换", s == 400, f"-> {s} {d.get('detail')}")

# ================================================================ C
line("C. 换密钥能不能刷新免费额度")

NO_REG = call("GET", "/api/auth/me", headers={"X-Forwarded-For": "192.0.2.77"})
bench = NO_REG[1]["quota"]
check("匿名额度按 IP 计", bench["limit"] == 3, f"-> {bench}")

s, d = key_issue("轮换" + SUF, "192.0.2.200", "HTTP-DEV-Q")
QT = d["token"]
s, me3 = call("GET", "/api/auth/me?device=HTTP-DEV-Q", token=QT,
              headers={"X-Forwarded-For": "192.0.2.200"})
check("新号额度为 0/3", me3["quota"]["used"] == 0 and me3["quota"]["limit"] == 3,
      f"-> {me3['quota']}")

# 需要有已通过的营地才能真的消耗额度：直接用数据库插入一条（审核链路 B 段已验证）
now = db.now_iso()
with sqlite3.connect(DB_PATH) as k:
    k.row_factory = sqlite3.Row
    ids = []
    for i in range(5):
        cur = k.execute(
            "INSERT INTO spots(name, lng, lat, spot_type, status, created_by, created_at,"
            " updated_at) VALUES(?,?,?,?,1,?,?,?)",
            (f"额度测试营地{i}", 104.0 + i * 0.001, 30.5, "房车营地", 0, now, now))
        ids.append(cur.lastrowid)
    k.commit()

QIP = {"X-Forwarded-For": "192.0.2.200"}
seen = 0
for sid in ids:
    s, d = call("GET", f"/api/spots/{sid}?device={urllib.parse.quote('HTTP-DEV-Q')}",
                token=QT, headers=QIP)
    if s == 200:
        seen += 1
check("连看 3 个营地后第 4 个被拦", seen == 3, f"放行 {seen} 次")

s, d = call("POST", "/api/auth/key/rotate", token=QT)
check("换发密钥成功", s == 200 and bool(d.get("secret_key")), f"-> {s}")
s, login = call("POST", "/api/auth/key/login", {"secret_key": d["secret_key"]},
                headers=QIP)
check("用新密钥登录成功", s == 200, f"-> {s}")
QT2 = login["token"]
s, d = call("GET", f"/api/spots/{ids[3]}?device={urllib.parse.quote('HTTP-DEV-Q')}",
            token=QT2, headers=QIP)
check("换密钥后额度没有回到 0", s == 402, f"-> {s} {d.get('detail', '')[:60]}")
s, me4 = call("GET", f"/api/auth/me?device={urllib.parse.quote('HTTP-DEV-Q')}",
              token=QT2, headers=QIP)
check("额度计数跟着账号走", me4["quota"]["used"] == 3, f"-> {me4['quota']}")
check("新旧 token 指向同一个用户", me4["user"]["id"] == me3["user"]["id"])

with sqlite3.connect(DB_PATH) as k:
    for sid in ids:
        k.execute("DELETE FROM spots WHERE id=?", (sid,))
        k.execute("DELETE FROM detail_views WHERE spot_id IN (?, ?)", (sid, -sid))
    k.commit()

# ---------------------------------------------------------------- 审核才给分
import devkeys                                          # noqa: E402

_s, _adm = call("POST", "/api/auth/key/login",
                {"secret_key": devkeys.load()["admin_key"]})
check("管理员登录成功", _s == 200, f"-> {_s}")
ADM = _adm.get("token")

s, sp = call("POST", "/api/spots", {
    "name": "待审营地" + SUF, "lng": 104.05, "lat": 30.6, "coordinate": "wgs84",
    "spot_type": "房车营地"}, token=AT)
check("提交营地成功", s == 200, f"-> {s} {sp.get('detail', '')}")
SID = sp.get("id")


def _points_of(token):
    _, p = call("GET", "/api/points", token=token)
    return p["points"]


before = _points_of(AT)
check("刚提交还没审核 -> 不加分", before == 20, f"-> {before}（应为邀请所得的 20）")
_, logs = call("GET", "/api/points", token=AT)
check("此时没有 spot_approved 流水",
      not [l for l in logs["logs"] if l["reason"] == "spot_approved"])

s, _ = call("POST", f"/api/admin/spots/{SID}/review",
            {"action": "approve"}, token=ADM)
check("管理员审核通过", s == 200, f"-> {s}")
after = _points_of(AT)
check("审核通过后才 +100", after == before + 100, f"{before} -> {after}")

s, _ = call("POST", f"/api/admin/spots/{SID}/review",
            {"action": "reject", "reason": "重复了"}, token=ADM)

print("\n" + "=" * 66)
print(f"通过 {ok} 项，失败 {failed} 项")
print("=" * 66)
sys.exit(1 if failed else 0)
