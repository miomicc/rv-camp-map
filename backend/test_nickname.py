"""昵称自助修改 + 全站唯一 测试。

昵称是后台认人的唯一线索：同名太多就分不清谁是谁。
所以这一版做了三件事——用户能自己改、全站不允许重名、不许冒充官方。
本文件同时覆盖数据层（旧库重名迁移）和接口层（各种非法输入与越权）。
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

import devkeys

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "data", "rvcamp.db")
B = "http://127.0.0.1:8000"
ok = failed = 0


def call(method, path, body=None, token=None):
    r = urllib.request.Request(B + path, method=method)
    r.add_header("Content-Type", "application/json")
    if token:
        r.add_header("Authorization", "Bearer " + token)
    data = json.dumps(body).encode() if body is not None else None
    try:
        with urllib.request.urlopen(r, data) as x:
            return x.status, json.loads(x.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def check(name, cond, extra=""):
    global ok, failed
    if cond:
        ok += 1
        print(f"  ✅ {name} {extra}")
    else:
        failed += 1
        print(f"  ❌ {name} {extra}")


def captcha_pair():
    """拿一道验证码并从本地库读出答案（测试进程有权限读库，生产绝无可能）。"""
    s, d = call("GET", "/api/captcha")
    assert s == 200, ("获取验证码失败", s, d)
    with sqlite3.connect(DB_PATH) as k:
        row = k.execute("SELECT code FROM captchas WHERE id=?", (d["id"],)).fetchone()
    return d["id"], row[0]


def line(t):
    print("\n" + "=" * 64 + f"\n{t}\n" + "=" * 64)


line("A. 数据层：旧库重名迁移（必须先拆散才能建唯一索引）")

# 用独立临时库，不碰开发数据
tmp_db = os.path.join(tempfile.mkdtemp(), "nick.db")
os.environ["RVCAMP_DB"] = tmp_db
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import db  # noqa: E402  （必须在 RVCAMP_DB 设好之后导入）

db.init_db()
with db.get_conn() as c:
    c.execute("DROP INDEX IF EXISTS idx_users_nickname")   # 模拟"还没有约束"的旧库
now = db.now_iso()
with db.get_conn() as c:
    for i, nick in enumerate(["张三", "张三", "张三", "露营者1234", "露营者1234", "", ""]):
        c.execute("INSERT INTO users(user_no, nickname, created_at) VALUES(?,?,?)",
                  (f"900{i}", nick, now))

cur = sqlite3.connect(tmp_db)
check("制造出重名数据", cur.execute(
    "SELECT COUNT(*) FROM (SELECT nickname FROM users"
    " GROUP BY nickname COLLATE NOCASE HAVING COUNT(*)>1)").fetchone()[0] >= 2)

affected = 0
with db.get_conn() as c:
    affected = db._dedupe_nicknames(c)          # 迁移逻辑本体
check("重名已被拆开", cur.execute(
    "SELECT COUNT(*) FROM (SELECT nickname FROM users WHERE nickname != ''"
    " GROUP BY nickname COLLATE NOCASE HAVING COUNT(*)>1)").fetchone()[0] == 0,
      f"（调整了 {affected} 行）")
check("空昵称已补默认值", cur.execute(
    "SELECT COUNT(*) FROM users WHERE nickname IS NULL OR nickname=''").fetchone()[0] == 0)
rows = [r[0] for r in cur.execute("SELECT nickname FROM users ORDER BY id").fetchall()]
print(f"  迁移后的昵称：{rows}")

db.init_db()    # 索引应该能顺利建起来
with sqlite3.connect(tmp_db) as fresh:
    idx = [r[1] for r in fresh.execute("PRAGMA index_list(users)").fetchall()]
check("唯一索引建立", "idx_users_nickname" in idx, f"-> {idx}")
try:
    cur.execute("INSERT INTO users(user_no, nickname, created_at) VALUES('9999',?,?)",
                (rows[0], now))
    cur.commit()
    check("重复昵称被数据库拒绝", False, "-> 竟然插进去了")
except sqlite3.IntegrityError:
    check("重复昵称被数据库拒绝", True)
cur.close()

# ---- 旧库升级：users 表重建不能丢密钥 ----
# _rebuild_users_table 曾经把拷贝列写死，漏了 user_no / secret_key_hash /
# key_preview：旧库（username 还是 NOT NULL 的那种）一升级，所有用户的密钥
# 和编号全部清零，等于全员锁死，而且不报错。这里固化"重建后数据还在"。
tmp_db2 = os.path.join(tempfile.mkdtemp(), "rebuild.db")
_old = sqlite3.connect(tmp_db2)
_old.executescript("""
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_no TEXT NOT NULL UNIQUE,
    secret_key_hash TEXT UNIQUE,
    key_preview TEXT NOT NULL DEFAULT '',
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL DEFAULT '',
    salt TEXT NOT NULL DEFAULT '',
    nickname TEXT NOT NULL DEFAULT '',
    level INTEGER NOT NULL DEFAULT 0,
    points INTEGER NOT NULL DEFAULT 0,
    expire_at TEXT,
    is_admin INTEGER NOT NULL DEFAULT 0,
    is_banned INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);
CREATE TABLE spots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL, lng REAL, lat REAL, province TEXT DEFAULT '', city TEXT DEFAULT '',
    spot_type TEXT DEFAULT '', address TEXT DEFAULT '', phone TEXT DEFAULT '',
    price_range TEXT DEFAULT '', facilities TEXT DEFAULT '[]', detail TEXT DEFAULT '',
    images TEXT DEFAULT '[]', status INTEGER DEFAULT 0, reject_reason TEXT DEFAULT '',
    created_by INTEGER, created_at TEXT, updated_at TEXT,
    verify_score REAL DEFAULT 0, verify_count INTEGER DEFAULT 0, report_count INTEGER DEFAULT 0
);
""")
_old.execute("INSERT INTO users(user_no, secret_key_hash, key_preview, username,"
             " password_hash, salt, nickname, points, created_at)"
             " VALUES('90000001','hash-abc','B-9p','olduser','ph','salt','老用户',42,?)",
             (now,))
_old.execute("INSERT INTO spots(name, lng, lat, created_by, created_at, updated_at)"
             " VALUES('某个营地',116.0,39.0,1,?,?)", (now, now))
_old.commit()
_old.close()

_saved_path = db.DB_PATH
db.DB_PATH = tmp_db2
try:
    db.init_db()      # username 是 NOT NULL -> 触发表重建
    with db.get_conn() as c:
        r = c.execute("SELECT user_no, secret_key_hash, key_preview, nickname, points"
                      " FROM users").fetchone()
        check("旧库重建：密钥/编号/积分不丢",
              bool(r) and r["user_no"] == "90000001" and r["secret_key_hash"] == "hash-abc"
              and r["key_preview"] == "B-9p" and r["points"] == 42,
              f"-> {dict(r) if r else None}")
        check("旧库重建：外键引用不断",
              c.execute("SELECT COUNT(*) FROM spots WHERE created_by=1").fetchone()[0] == 1)
finally:
    db.DB_PATH = _saved_path

line("B. 接口层：自己改昵称")
_K = devkeys.load()
s, ad = call("POST", "/api/auth/login",
             {"username": "admin", "password": _K["admin_password"]})
AT = ad["token"]
s, ud = call("POST", "/api/auth/key/login", {"secret_key": _K["user_key"]})
UT = ud["token"]
s, me = call("GET", "/api/auth/me", token=UT)
me = me["user"]
UID = me["id"]
ORIG = me["nickname"]
print(f"  测试账号 #{UID} 当前昵称「{ORIG}」")

# 限流是持久化状态：改昵称限 1 小时 5 次，上一轮跑测试留下的计数会让这一轮
# 直接 429。每条用例前清一次，保证校验类用例能跑完；限流本身在最后单独验证。
def clear_rename():
    with sqlite3.connect(DB_PATH) as k:
        k.execute("DELETE FROM rate_hits WHERE scope='rename' AND identity=?",
                  (str(UID),))
        k.commit()


def rename(nick, token=None):
    clear_rename()
    return call("POST", "/api/user/nickname", {"nickname": nick}, token or UT)


s, d = call("POST", "/api/user/nickname", {"nickname": "房车老王"}, None)
check("未登录被拒", s == 401, f"-> {s}")

# "Tom\u0020Smith"：显式写空格转义，避免写源码时被输入法吞掉（那会变成三个汉字）
for nick in ["王", "Tom\u0020Smith", "昵称😀emoji", "管理员小号", "a" * 20, "-下划线开头"]:
    s, d = rename(nick)
    check(f"非法昵称被拒：{nick}", s == 400 and bool(d.get("detail")),
          f"-> {s} {d.get('detail', '')}")

# 找一个别人正在用的昵称（跳过带敏感词的，那会先被敏感词规则挡下）
others = call("GET", "/api/admin/users?size=50", token=AT)[1]["items"]
other_nick = next(u["nickname"] for u in others
                  if u["id"] != UID and "管理员" not in (u["nickname"] or "")
                  and "官方" not in (u["nickname"] or ""))
s, d = rename(other_nick)
check("占用他人昵称被拒", s == 400 and "已经被占用" in str(d.get("detail", "")),
      f"-> “{other_nick}” {d.get('detail', '')}")

s, d = rename("  房车老王  ")
check("改名成功", s == 200, f"-> {s}")
check("前后空格被清理", d.get("nickname") == "房车老王", f"-> {d.get('nickname')}")
s, me2 = call("GET", "/api/auth/me", token=UT)
check("登录态信息同步", me2["user"]["nickname"] == "房车老王")

s, d = rename("房车老王")
check("改成同名（自己）不算冲突", s == 200)

s, d = rename("TestUser")
check("英文昵称可用", s == 200 and d.get("nickname") == "TestUser")
# 换成管理员账号去抢同一个名字的大小写变体：唯一性必须大小写不敏感，
# 否则 Tom 和 tom 会是两个不同的"人"，约束就形同虚设。
s, d = rename("testuser", AT)
check("大小写不同也算重名", s == 400 and "已经被占用" in str(d.get("detail", "")),
      f"-> {s} {d.get('detail', '')}")

s, al = call("GET", "/api/admin/audit?limit=20", token=AT)
hit = [a for a in al.get("items", []) if a["action"] == "rename"]
check("审计记录了改前 → 改后", any("→ 房车老王" in (a["detail"] or "") for a in hit),
      f"{(hit[0]['detail'] if hit else '无')}")

# 限流：连续改 5 次之后应该被挡住，防止有人用改名接口刷名字/骚扰别人
clear_rename()
codes = [call("POST", "/api/user/nickname", {"nickname": f"改名测试{i}"}, UT)[0]
         for i in range(6)]
check("改名频率受限（1 小时 5 次）", codes[:5] == [200] * 5 and codes[5] == 429,
      f"-> {codes}")

def clear_limits():
    """清掉本机 IP/测试账号的限流计数（连同全局写限流），便于反复跑本脚本。"""
    with sqlite3.connect(DB_PATH) as k:
        k.execute("DELETE FROM rate_hits WHERE identity IN (?, '127.0.0.1')", (str(UID),))
        k.commit()


line("C. 管理员代改（处理违规昵称）")
clear_limits()
s, d = call("POST", f"/api/admin/users/{UID}/nickname",
            {"nickname": "不当昵称已被改", "note": "含联系方式"}, AT)
check("管理员改名成功", s == 200, f"-> {s} {d.get('nickname')}")
s, d = call("POST", f"/api/admin/users/{UID}/nickname",
            {"nickname": "官方巡查号"}, AT)
check("管理员可使用官方字样", s == 200, f"-> {s}")
s, d = call("POST", f"/api/admin/users/{UID}/nickname", {"nickname": "平台管理员"}, AT)
check("管理员也不能改成别人的昵称", s == 400, f"-> {d.get('detail', '')}")
s, nt = call("GET", "/api/notifications?limit=20", token=UT)
check("用户收到改名通知", any(n["title"] == "昵称已被修改" for n in nt.get("items", [])),
      f"-> {[n['title'] for n in nt.get('items', [])][:3]}")
s, d = call("POST", f"/api/admin/users/{UID}/nickname", {"nickname": "官方巡查号"}, UT)
check("普通用户调后台改名接口被拒", s == 403, f"-> {s}")

# 已经有人在用
line("D. 注册/领密钥时的昵称冲突")
clear_limits()      # 领密钥按 IP 限流（10 分钟 5 个），本轮之前的计数先清掉
target = other_nick
cid, code = captcha_pair()
s, d = call("POST", f"/api/auth/key/issue?nickname={urllib.parse.quote(target)}"
                    f"&captcha_id={cid}&captcha_code={urllib.parse.quote(code)}")
check("领密钥时重名被拒", s == 400 and "已经被占用" in str(d.get("detail", "")),
      f"-> {s} {d.get('detail', '')}")

fresh_nick = "路上闲云" + str(random.randrange(10000, 99999))
cid, code = captcha_pair()
s, d = call("POST", f"/api/auth/key/issue?nickname={urllib.parse.quote(fresh_nick)}"
                    f"&captcha_id={cid}&captcha_code={urllib.parse.quote(code)}")
check("领密钥时昵称合法则通过", s == 200, f"-> {s} {d.get('user', {}).get('nickname')}")

uname = "nicktest" + str(random.randrange(10000, 99999))
cid, code = captcha_pair()
s, d = call("POST", "/api/auth/register",
            {"username": uname, "password": "Abcd123!",
             "captcha_id": cid, "captcha_code": code})
if s == 200:
    check("注册时不填昵称也能成功", bool(d.get("user", {}).get("nickname")),
          f"-> {d.get('user', {}).get('nickname')}")
else:
    check("注册空昵称", False, f"-> {s} {d.get('detail', '')}")

# 注册与领密钥同一套门：没有验证码不许开账号
# （先清限流计数，否则这天级建号上限会先于验证码返回 429，测的就不是同一件事了）
clear_limits()
s, d = call("POST", "/api/auth/register",
            {"username": "nicktest" + str(random.randrange(10000, 99999)),
             "password": "Abcd123!"})
check("注册也要过验证码", s == 400 and "验证码" in str(d.get("detail", "")),
      f"-> {s} {d.get('detail', '')}")

# 还原，方便下次演示
call("POST", f"/api/admin/users/{UID}/nickname", {"nickname": ORIG}, AT)

print("\n" + "=" * 64)
print(f"通过 {ok} 项，失败 {failed} 项（测试账号昵称已还原为「{ORIG}」）")
print("=" * 64)
raise SystemExit(1 if failed else 0)
