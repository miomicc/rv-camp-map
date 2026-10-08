"""密钥登录全流程测试。用 Python 直接打接口，避免 shell 转义干扰。"""
import json
import urllib.request
import urllib.parse

B = "http://127.0.0.1:8000"


def call(method, path, body=None, token=None):
    req = urllib.request.Request(B + path, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    data = json.dumps(body).encode() if body is not None else None
    try:
        with urllib.request.urlopen(req, data) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def line(t):
    print("\n" + "=" * 66)
    print(t)
    print("=" * 66)


# ---------------------------------------------------------------- 1
line("1. 领取密钥（等效于「注册」，但不需要用户名和密码）")
st, d = call("POST", "/api/auth/key/issue?nickname=" + urllib.parse.quote("老王"))
print(f"  HTTP {st}")
print(f"  用户编号  : {d['user']['user_no']}")
print(f"  昵称      : {d['user']['nickname']}")
print(f"  密钥      : {d['secret_key']}")
print(f"  是否匿名  : {d['user']['is_anonymous']}")
print(f"  会员状态  : {d['user']['is_member']}")
print(f"  提醒      : {d['warning']}")
raw_key = d["secret_key"]
bare_key = raw_key.replace("-", "")

# ---------------------------------------------------------------- 2
line("2. 用密钥登录（不输用户名、不需要密码）")
st, d = call("POST", "/api/auth/key/login", {"secret_key": raw_key})
print(f"  HTTP {st} | 编号 {d['user']['user_no']} | 会员 {d['user']['is_member']}")
tok = d["token"]

# ---------------------------------------------------------------- 3
line("3. 容错测试：用户从聊天记录/截图里粘贴时的常见情况")
variants = {
    "标准格式 XXXX-XXXX": raw_key,
    "去掉连字符": bare_key,
    "前后带空格": "   " + raw_key + "   ",
    "用下划线分隔": "_".join(bare_key[i:i+8] for i in range(0, 32, 8)),
    "全小写（应失败）": bare_key.lower(),
}
for name, v in variants.items():
    st, d = call("POST", "/api/auth/key/login", {"secret_key": v})
    print(f"  {name:<22s} -> {'登录成功' if d.get('token') else '拒绝: ' + str(d.get('detail'))}")
print("  说明：密钥区分大小写（字符集同时含大小写），全小写必须被拒绝，符合预期。")

# ---------------------------------------------------------------- 4
line("4. 错误密钥 / 枚举防护")
for name, v in [("全 A（不存在）", "A" * 32), ("长度不足", "ABC123"), ("空", "")]:
    st, d = call("POST", "/api/auth/key/login", {"secret_key": v})
    msg = d.get("detail")
    if isinstance(msg, list):
        msg = msg[0].get("msg", str(msg))
    print(f"  {name:<16s} -> {msg}")

# ---------------------------------------------------------------- 5
line("5. 密钥账号是完整用户：能提交营地、能攒积分")
st, d = call("POST", "/api/spots", {
    "name": "测试·密钥账号提交的营地", "lng": 118.5, "lat": 32.0,
    "province": "江苏省", "city": "南京市", "spot_type": "房车营地",
    "address": "南京市江宁区测试路 1 号", "phone": "025-1234****",
    "facilities": ["水电桩", "排污口"], "detail": "由密钥账号提交",
}, token=tok)
print(f"  提交营地 -> {d.get('message') or d.get('detail')}")

st, d = call("GET", "/api/points", token=tok)
print(f"  当前积分 -> {d['points']}（每日登录 +{d['logs'][0]['delta']}）")

# ---------------------------------------------------------------- 6
line("6. 会员门禁对密钥账号同样生效")
st, d = call("GET", "/api/spots?bbox=110,28,122,42&zoom=7&limit=1", token=tok)
it = d["items"][0]
print(f"  免费密钥账号: locked={it['locked']} 地址={it['address']} 电话={it['phone'] or '(空)'}")

st, d = call("POST", "/api/orders", {"plan": "basic_3y"}, token=tok)
ono = d["order_no"]
st, d = call("POST", f"/api/orders/{ono}/mock-pay", token=tok)
newtok = call("POST", "/api/auth/key/login", {"secret_key": raw_key})[1]["token"]
st, d = call("GET", "/api/spots?bbox=110,28,122,42&zoom=7&limit=1", token=newtok)
it = d["items"][0]
print(f"  付费后      : locked={it['locked']} 地址={it['address']} 电话={it['phone']}")

# ---------------------------------------------------------------- 7
line("7. 密钥泄露了怎么办：换发新密钥")
st, d = call("POST", "/api/auth/key/rotate", token=newtok)
new_key = d["secret_key"]
print(f"  新密钥    : {new_key}")
print(f"  提示      : {d['warning']}")
st, _ = call("POST", "/api/auth/key/login", {"secret_key": raw_key})
print(f"  用旧密钥登录 -> HTTP {st}（应 400，旧密钥已作废）")
st, d = call("POST", "/api/auth/key/login", {"secret_key": new_key})
print(f"  用新密钥登录 -> {'成功' if d.get('token') else '失败'}")

# ---------------------------------------------------------------- 8
line("8. 打印在界面上的『用户信息』（对应截图左侧栏）")
st, d = call("GET", "/api/auth/me", token=d["token"])
u = d["user"]
print(f"  用户编号  : {u['user_no']}")
print(f"  用户密钥  : ????????????????????????{u['key_preview']}   ← 仅显示末 4 位供核对")
print(f"  贡献积分  : {u['points']}")
print(f"  会员类型  : {'赞助会员' if u['is_member'] else '免费会员'}")
print(f"  会员到期  : {u['expire_at'] or '—'}")
print(f"  账号形态  : {'匿名密钥账号' if u['is_anonymous'] else '账号密码账号'}")
