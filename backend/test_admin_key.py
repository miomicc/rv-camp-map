"""管理员密钥登录测试：权限、签发、撤销、限流。"""
import json
import urllib.parse
import urllib.request

B = "http://127.0.0.1:8000"
import devkeys
_K = devkeys.load()
ADM_KEY = _K["admin_key"]
USER_KEY = _K["user_key"]


def call(method, path, body=None, token=None, ip=None):
    r = urllib.request.Request(B + path, method=method)
    r.add_header("Content-Type", "application/json")
    if token:
        r.add_header("Authorization", "Bearer " + token)
    if ip:
        r.add_header("X-Forwarded-For", ip)
    try:
        with urllib.request.urlopen(r, json.dumps(body).encode() if body is not None else None) as x:
            return x.status, json.loads(x.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def line(t):
    print("\n" + "=" * 62 + "\n" + t + "\n" + "=" * 62)


# ---------------------------------------------------------------- 1
line("1. 管理员用密钥登录（与用户端同一个 key/login 接口）")
st, d = call("POST", "/api/auth/key/login", {"secret_key": ADM_KEY})
print(f"  HTTP {st} | 昵称 {d['user']['nickname']} | is_admin={d['user']['is_admin']}")
AT = d["token"]

# ---------------------------------------------------------------- 2
line("2. 管理员密钥可访问后台接口")
for name, path in [("待审队列", "/api/admin/pending"), ("运营统计", "/api/admin/stats"),
                   ("管理员列表", "/api/admin/admins"), ("全部营地", "/api/admin/spots?size=3")]:
    st, d = call("GET", path, token=AT)
    n = len(d.get("items", [])) if isinstance(d, dict) else "-"
    print(f"  {name:<10s} HTTP {st} | 条目 {n}")

# ---------------------------------------------------------------- 3
line("3. 权限判断看 is_admin，与密钥格式无关")
st, d = call("POST", "/api/auth/key/login", {"secret_key": USER_KEY})
UT = d["token"]
print(f"  普通密钥登录 -> is_admin={d['user']['is_admin']}")
st, d = call("GET", "/api/admin/pending", token=UT)
print(f"  普通密钥访问后台 -> HTTP {st} {d.get('detail')}")

# ---------------------------------------------------------------- 4
line("4. 签发新管理员密钥（只能由现有管理员操作）")
st, d = call("POST", "/api/admin/key/issue?nickname=" + urllib.parse.quote("运营二号"), token=AT)
NEW = d["secret_key"]
NEW_NO = d["user_no"]
print(f"  新密钥   -> {NEW}")
print(f"  编号     -> {NEW_NO}")
print(f"  前缀     -> {'ADM ✓' if NEW.startswith('ADM') else '✗'}")
print(f"  提示     -> {d['warning'][:40]}…")
st2, d2 = call("POST", "/api/admin/key/issue", token=UT)
print(f"  普通用户尝试签发 -> HTTP {st2} {d2.get('detail')}")

# ---------------------------------------------------------------- 5
line("5. 新管理员密钥可用")
st, d = call("POST", "/api/auth/key/login", {"secret_key": NEW})
print(f"  登录 -> is_admin={d['user']['is_admin']} | 昵称 {d['user']['nickname']}")

# ---------------------------------------------------------------- 6
line("6. 管理员列表不泄露任何可登录信息")
st, d = call("GET", "/api/admin/admins", token=AT)
for a in d["items"]:
    tag = "（我自己）" if a["is_self"] else ""
    kind = "账号密码" if a["has_password"] else "密钥"
    print(f"  {a['user_no']}  {a['nickname']:<12s} {kind:<6s} 末4位={a['key_preview'] or '—':<5s} {tag}")
keys = list(d["items"][0].keys())
bad = [k for k in keys if "hash" in k or k == "secret_key"]
print(f"  返回字段 {keys}")
print(f"  敏感字段泄露检查 -> {'✗ ' + str(bad) if bad else '✓ 未泄露'}")

# ---------------------------------------------------------------- 7
line("7. 撤销管理员权限（应对密钥泄露 / 人员离职）")
st, d = call("POST", f"/api/admin/key/demote?user_no={NEW_NO}", token=AT)
print(f"  撤销 -> {d.get('message')}")
st, d = call("POST", "/api/auth/key/login", {"secret_key": NEW})
print(f"  被撤销的密钥登录 -> is_admin={d['user']['is_admin']}（保留账号，降为普通用户）")
st, d = call("GET", "/api/admin/pending", token=d["token"])
print(f"  它再访问后台 -> HTTP {st} {d.get('detail')}")

# ---------------------------------------------------------------- 8
line("8. 保护机制：不能撤销自己 / 不能撤销最后一个管理员")
st, d = call("GET", "/api/admin/admins", token=AT)
me = [a for a in d["items"] if a["is_self"]][0]
st, r = call("POST", f"/api/admin/key/demote?user_no={me['user_no']}", token=AT)
print(f"  撤销自己 -> HTTP {st} {r.get('detail')}")

# ---------------------------------------------------------------- 9
line("9. 登录失败限流（防爆破）")
FAKE_IP = "203.0.113.99"
print(f"  用伪造 IP {FAKE_IP} 连续提交错误密钥：")
for i in range(1, 13):
    st, d = call("POST", "/api/auth/key/login",
                 {"secret_key": "WRONG" + "A" * 27}, ip=FAKE_IP)
    msg = str(d.get("detail"))[:38]
    mark = " ← 已锁定" if st == 429 else ""
    print(f"    第 {i:>2d} 次 -> HTTP {st} {msg}{mark}")
    if st == 429:
        break

line("10. 限流不影响其他 IP 正常登录")
st, d = call("POST", "/api/auth/key/login", {"secret_key": ADM_KEY}, ip="198.51.100.7")
print(f"  换个 IP 用正确密钥 -> HTTP {st} {'登录成功' if d.get('token') else d.get('detail')}")
print()
print("=" * 62)
print("管理员密钥登录测试完成")
print("=" * 62)
