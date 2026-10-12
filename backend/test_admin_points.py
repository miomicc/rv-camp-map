"""积分手动调整测试：管理员加减积分、越权、非法入参、流水与通知。

积分能兑换会员天数，等于间接影响付费权益，所以这个口子的校验必须
比普通写接口更严：谁能调、能调多少、事由是否合规、余额会不会扣成负数，
每种情况都要有一条用例卡住。
"""
import json
import urllib.error
import urllib.request

B = "http://127.0.0.1:8000"


def call(method, path, body=None, token=None):
    r = urllib.request.Request(B + path, method=method)
    r.add_header("Content-Type", "application/json")
    if token:
        r.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(
                r, json.dumps(body).encode() if body is not None else None) as x:
            return x.status, json.loads(x.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


line = lambda t: print("\n" + "=" * 64 + "\n" + t + "\n" + "=" * 64)
ok = failed = 0


def check(name, cond, extra=""):
    global ok, failed
    if cond:
        ok += 1
        print(f"  ✅ {name} {extra}")
    else:
        failed += 1
        print(f"  ❌ {name} {extra}")


# 凭证来自 seed.py 随机生成的 data/dev_keys.json
import devkeys
_K = devkeys.load()
_, admin_d = call("POST", "/api/auth/login",
                  {"username": "admin", "password": _K["admin_password"]})
AT = admin_d["token"]
_, user_d = call("POST", "/api/auth/key/login", {"secret_key": _K["user_key"]})
UT = user_d["token"]

line("准备：取一个普通用户")
# 直接拿测试账号本人当目标：后面要检查他收到了站内信
s, me = call("GET", "/api/auth/me", token=UT)
me = me["user"]
s, _u = call("GET", f"/api/admin/users?keyword={me['user_no']}&size=20", token=AT)
target = next((u for u in _u["items"] if u["id"] == me["id"]), None)
check("取到测试账号本人", target is not None)
uid = target["id"]
before = target["points"]
print(f"  目标用户 #{uid} 昵称 {target['nickname']} 当前积分 {before}")

line("1. 权限隔离")
s, d = call("POST", f"/api/admin/users/{uid}/points", {"amount": 10, "reason": "reward"}, UT)
check("普通用户调用被拒", s == 403, f"-> {s}")
s, d = call("POST", f"/api/admin/users/{uid}/points", {"amount": 10}, None)
check("未登录调用被拒", s in (401, 403), f"-> {s}")
s, d = call("GET", f"/api/admin/users/{uid}/point-logs", token=UT)
check("普通用户看流水被拒", s == 403, f"-> {s}")

line("2. 非法入参")
for name, body, want in [
    ("变动值为 0 被拒", {"amount": 0}, 400),
    ("非数字变动值被拒", {"amount": "abc"}, 400),
    ("超过单次上限被拒", {"amount": 100001, "reason": "reward"}, 400),
    ("非法事由被拒", {"amount": 10, "reason": "随便给点"}, 400),
    ("用户不存在被拒", {"amount": 10, "reason": "reward"}, 404),
]:
    if body.get("reason") is None:
        body = dict(body, reason="reward")
    path = f"/api/admin/users/{999999}/points" if "不存在" in name else f"/api/admin/users/{uid}/points"
    s, d = call("POST", path, body, AT)
    check(name, s == want, f"-> {s} {d.get('detail', '')}")

line("3. 增加积分")
s, d = call("POST", f"/api/admin/users/{uid}/points",
            {"amount": 120, "reason": "reward", "note": "活动第一名"}, AT)
check("返回 200", s == 200, f"-> {s}")
check("积分增加正确", d.get("points") == before + 120, f"{before} -> {d.get('points')}")
check("返回变动量", d.get("delta") == 120)
mid = d.get("points")

line("4. 扣减积分")
s, d = call("POST", f"/api/admin/users/{uid}/points",
            {"amount": -20, "reason": "penalty", "note": "重复提交已要求整改"}, AT)
check("返回 200", s == 200, f"-> {s}")
check("积分扣减正确", d.get("points") == mid - 20, f"{mid} -> {d.get('points')}")

s, d = call("POST", f"/api/admin/users/{uid}/points",
            {"amount": -(d.get("points", 0) + 1), "reason": "penalty"}, AT)
check("扣成负数被拒", s == 400, f"-> {s} {d.get('detail', '')}")

line("5. 流水与通知")
s, lg = call("GET", f"/api/admin/users/{uid}/point-logs?limit=20", token=AT)
items = lg.get("items", [])
check("流水返回 200", s == 200, f"-> {s}")
check("流水中含 admin_reward", any(i["reason"] == "admin_reward" and i["delta"] == 120 for i in items))
check("流水中含 admin_penalty", any(i["reason"] == "admin_penalty" and i["delta"] == -20 for i in items))

s, nt = call("GET", "/api/notifications?limit=50", token=UT)
titles = [n["title"] for n in nt.get("items", [])] if s == 200 else []
check("用户收到积分通知", "积分已增加" in titles and "积分已扣减" in titles,
      f"-> {s} {titles[:4]}")

line("6. 列表积分同步")
s, users = call("GET", "/api/admin/users?size=100", token=AT)
now = next(u for u in users["items"] if u["id"] == uid)
check("列表里的积分已更新", now["points"] == mid - 20, f"{now['points']}")

line("7. 审计留痕")
s, al = call("GET", "/api/admin/audit?limit=50", token=AT)
check("审计里有 adj_points", any(a["action"] == "adj_points" for a in al.get("items", [])),
      f"{[a['action'] for a in al.get('items', [])][:5]}")

print("\n" + "=" * 64)
print(f"通过 {ok} 项，失败 {failed} 项")
print("=" * 64)
raise SystemExit(1 if failed else 0)
