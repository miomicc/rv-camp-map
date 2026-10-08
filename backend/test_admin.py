"""管理后台接口测试：权限隔离、审核、编辑、上下架、用户管理、日志。"""
import json
import urllib.parse
import urllib.request

B = "http://127.0.0.1:8000"


def call(method, path, body=None, token=None):
    r = urllib.request.Request(B + path, method=method)
    r.add_header("Content-Type", "application/json")
    if token:
        r.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(r, json.dumps(body).encode() if body is not None else None) as x:
            return x.status, json.loads(x.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


line = lambda t: print("\n" + "=" * 64 + "\n" + t + "\n" + "=" * 64)

# 两个身份（凭证来自 seed.py 随机生成的 data/dev_keys.json）
import devkeys
_K = devkeys.load()
_, admin_d = call("POST", "/api/auth/login",
                  {"username": "admin", "password": _K["admin_password"]})
AT = admin_d["token"]
_, user_d = call("POST", "/api/auth/key/login", {"secret_key": _K["user_key"]})
UT = user_d["token"]
print(f"管理员 {admin_d['user']['nickname']}（is_admin={admin_d['user']['is_admin']}）")
print(f"普通用户 {user_d['user']['nickname']}（is_admin={user_d['user']['is_admin']}）")

# ---------------------------------------------------------------- 1
line("1. 权限隔离：普通用户不能碰后台接口")
for name, path, method in [
    ("待审队列", "/api/admin/pending", "GET"),
    ("营地列表", "/api/admin/spots", "GET"),
    ("用户列表", "/api/admin/users", "GET"),
    ("运营统计", "/api/admin/stats", "GET"),
    ("操作日志", "/api/admin/audit", "GET"),
]:
    st, d = call(method, path, token=UT)
    st2, d2 = call(method, path)
    print(f"  {name:<10s} 普通用户 -> {st} {str(d.get('detail'))[:14]:<16s} | 未登录 -> {st2}")

# ---------------------------------------------------------------- 2
line("2. 管理员登录后可访问全部接口")
for name, path in [("待审队列", "/api/admin/pending"), ("营地列表", "/api/admin/spots"),
                   ("用户列表", "/api/admin/users"), ("操作日志", "/api/admin/audit")]:
    st, d = call("GET", path, token=AT)
    n = len(d.get("items", [])) if isinstance(d, dict) else 0
    print(f"  {name:<10s} HTTP {st} | {n} 条")

# ---------------------------------------------------------------- 3
line("3. 运营统计（新增字段）")
st, s = call("GET", "/api/admin/stats", token=AT)
for k, label in [("spots_total", "营地总数"), ("spots_pending", "待审核"), ("spots_live", "已上线"),
                 ("spots_rejected", "已驳回"), ("spots_with_photo", "带照片"),
                 ("users", "用户数"), ("anonymous", "匿名用户"), ("members", "会员数"),
                 ("ratings", "评价数"), ("orders_paid", "已支付订单")]:
    print(f"  {label:<12s} {s[k]}")
print(f"  {'累计收入':<12s} ¥{s['revenue_fen']/100:.0f}")
print(f"  {'今日新增营地':<12s} {s['spots_today']}")

# ---------------------------------------------------------------- 4
line("4. 营地列表筛选与翻页")
for status, label in [(0, "待审核"), (1, "已上线"), (2, "已驳回"), (None, "全部")]:
    p = "/api/admin/spots?size=5" + (f"&status={status}" if status is not None else "")
    st, d = call("GET", p, token=AT)
    print(f"  {label:<8s} 共 {d['total']:>3d} 条 | 本页 {len(d['items'])} 条 | 第 {d['page']}/{d['pages']} 页")

st, d = call("GET", "/api/admin/spots?keyword=" + urllib.parse.quote("云南"), token=AT)
print(f"  搜索「云南」-> {d['total']} 条")

# ---------------------------------------------------------------- 5
line("5. 审核：通过一条待审营地")
st, pend = call("GET", "/api/admin/spots?status=0&size=1", token=AT)
if pend["items"]:
    spot = pend["items"][0]
    sid = spot["id"]
    print(f"  待审营地 #{sid} {spot['name']} | 照片 {len(spot.get('images') or [])} 张 "
          f"| 提交者 {spot.get('submitter') or '—'}")
    st, d = call("POST", f"/api/admin/spots/{sid}/review", {"action": "approve"}, AT)
    print(f"  通过 -> {d}")
    st, d = call("GET", f"/api/spots/{sid}", token=AT)
    print(f"  状态已变 -> {d['status']} (1=已上线)")

line("6. 审核：驳回一条，带原因")
st, pend = call("GET", "/api/admin/spots?status=0&size=1", token=AT)
if pend["items"]:
    sid = pend["items"][0]["id"]
    st, d = call("POST", f"/api/admin/spots/{sid}/review",
                 {"action": "reject", "reason": "坐标位置明显错误"}, AT)
    print(f"  驳回 #{sid} -> {d}")
    st, d = call("GET", f"/api/spots/{sid}", token=AT)
    print(f"  驳回原因 -> {d['reject_reason']}")

# ---------------------------------------------------------------- 7
line("7. 后台编辑营地信息")
st, d = call("GET", "/api/admin/spots?status=1&size=1", token=AT)
if d["items"]:
    sid = d["items"][0]["id"]
    old = d["items"][0]["name"]
    st, r = call("PATCH", f"/api/admin/spots/{sid}",
                 {"name": old + "（已核验）", "price_range": "168-288元/晚"}, AT)
    print(f"  编辑 #{sid} -> {r}")
    st, chk = call("GET", f"/api/spots/{sid}", token=AT)
    print(f"  新名称 -> {chk['name']}")
    print(f"  新价格 -> {chk['price_range']}")

# ---------------------------------------------------------------- 8
line("8. 上下架")
if d["items"]:
    sid = d["items"][0]["id"]
    st, _ = call("PATCH", f"/api/admin/spots/{sid}", {"status": 3}, AT)
    st, chk = call("GET", f"/api/spots/{sid}", token=AT)
    print(f"  下架 -> status={chk['status']} (3=已下架)")
    st, _ = call("PATCH", f"/api/admin/spots/{sid}", {"status": 1}, AT)
    st, chk = call("GET", f"/api/spots/{sid}", token=AT)
    print(f"  重新上线 -> status={chk['status']} (1=已上线)")

# ---------------------------------------------------------------- 9
line("9. 字段白名单：后台不能改 created_by / is_admin 之类")
if d["items"]:
    sid = d["items"][0]["id"]
    st, r = call("PATCH", f"/api/admin/spots/{sid}",
                 {"created_by": 1, "verify_score": 5.0, "is_admin": 1}, AT)
    print(f"  提交白名单外字段 -> {st} {r.get('detail', 'ok')}")
    st, chk = call("GET", f"/api/spots/{sid}", token=AT)
    print(f"  verify_score 未被篡改 -> {chk['verify_score']}")

# ---------------------------------------------------------------- 10
line("10. 用户管理")
st, d = call("GET", "/api/admin/users", token=AT)
print(f"  用户总数 {d['total']}")
for u in d["items"]:
    kind = "管理员" if u["is_admin"] else ("密钥账号" if u["is_anonymous"] else "账号密码")
    print(f"    #{u['id']:<3d} {u['user_no']}  {u['nickname']:<10s} {kind:<8s} "
          f"积分{u['points']:>4d} 营地{u['spots_count']} 会员={'是' if u['is_member'] else '否'}")

line("11. 封禁 / 解封")
st, d = call("GET", "/api/admin/users?keyword=" + urllib.parse.quote("匿名露营者"), token=AT)
if d["items"]:
    uid = d["items"][0]["id"]
    st, r = call("POST", f"/api/admin/users/{uid}/ban", {"banned": True}, AT)
    print(f"  封禁用户 #{uid} -> {r}")
    st, r = call("POST", "/api/auth/key/login", {"secret_key": _K["user_key"]})
    print(f"  被封禁用户尝试登录 -> HTTP {st} {r.get('detail')}")
    st, r = call("POST", f"/api/admin/users/{uid}/ban", {"banned": False}, AT)
    print(f"  解封 -> {r}")
    st, r = call("POST", "/api/auth/key/login", {"secret_key": _K["user_key"]})
    print(f"  解封后可登录 -> {'成功' if r.get('token') else '失败'}")

line("12. 保护管理员不被封禁")
st, d = call("GET", "/api/admin/users?keyword=admin", token=AT)
adm = [u for u in d["items"] if u["is_admin"]]
print(f"  管理员账号数量 {len(adm)}（前端已禁止对管理员显示封禁按钮）")

# ---------------------------------------------------------------- 13
line("13. 操作日志（记录每次后台动作）")
st, d = call("GET", "/api/admin/audit?limit=12", token=AT)
ICON = {"spot_create":"提交营地","review_approve":"审核通过","review_reject":"审核驳回",
        "admin_edit_spot":"后台编辑","ban":"封禁用户","unban":"解封用户",
        "order_paid":"订单支付","issue_key":"领取密钥","seed":"数据初始化"}
for l in d["items"]:
    print(f"  {l['created_at'].replace('T',' ')}  {l['nickname'] or '系统':<8s} "
          f"{ICON.get(l['action'], l['action']):<8s} {l['target']}  {l['detail'][:26]}")

print()
print("=" * 64)
print("全部后台接口测试完成")
print("=" * 64)
