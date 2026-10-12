"""邀请奖励与反作弊判定。

为什么这个文件这么啰嗦：邀请分看着只是"+20"，但它能换会员天数
（300 分 = 90 天），本质上是钱。所以这里的每一行判断都是为了让
"刷邀请"的成本高于收益，而不是让用户觉得有人在刁难他。

判人还是判机器，用三个信号叠起来看
--------------------------------
没有手机号（产品明确不要），也没有邮箱验证，所以拿不到任何"这个人
在现实中唯一"的凭据。能用的只有三个弱信号：

  IP      同一个 WiFi/同一个出口 NAT 后面可能是几个人，也可能是同一个人的两部手机
  设备    同一个浏览器换号 = 同一个人；但一家人共用一台电脑也是合理的
  行为    注册完就再也不出现 = 大概率是我在自娱自乐；回访几天或有产出 = 像个人

单个信号都不可靠，所以规则是组合出来的：

  强判定（必是同一人，直接不发）
      自己邀请自己、互相邀请、**[同 IP 且 同设备]**
  弱判定（可疑，但可能是一家人/同事，放过去但留痕，方便事后复核）
      [同 IP 或 同设备] -> 记录 same_ip / same_device，人事后可筛出来看
  集群判定（无论上面怎么判，一个网段批量冒出来的都不正常）
      同一 IP 段在时间窗内超过阈值 -> 后面的一律不发

发放在什么时候
--------------
**判定通过的那一刻就发**。中途设计的版本是"等被邀请人活跃两天再结算"，
但那道门槛拦不住脚本（连着上线两天很容易）却拦住了信任感——邀请人看不见
到账就会来问"是不是吞了"。所以让反作弊回到它擅长的地方：上面的七条判定，
而不是把成本转嫁给已经通过判定的正常用户。

代价要认清：这套土办法防的是"顺手多开几个号"，防不了有组织的批量作弊
（代理 IP + 无头浏览器 + 接码平台）。真到了那一步，靠的是后台封号 +
`invites` 表里的 same_ip/device/network 字段做人工复核，以及
`RVCAMP_INVITE_TOTAL_CAP` 这种硬上限先把损失封顶。

被拦下来怎么办
--------------
一律写进 invites 表并给出原因，用户在自己的邀请页能看到；真有水逆
（比如两口子同一台笔记本先后注册），管理员在后台用"手动加积分"补，
每一笔都有据可查。宁可误伤后人工补，也不要让诚实用户替作弊者买单的方案
反过来：误伤了还有人看见能补，放过了就再也没人知道了。
"""

import ipaddress
import secrets
import time

import config
import db
import notify
from logsetup import log

# 邀请码字符集：沿用密钥那套——去掉 0/O/1/l/I，避免口头传达时抄错，
# 也避免用户在聊天窗口里把 "O" 打成 "0" 然后说"你的邀请码是坏的"。
CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"


# ---------------------------------------------------------------- 邀请码

def new_code(conn) -> str:
    """生成一个没被占用的邀请码。"""
    n = max(6, min(12, config.INVITE_CODE_LEN))
    for _ in range(20):
        code = "".join(secrets.choice(CODE_ALPHABET) for _ in range(n))
        if not conn.execute("SELECT 1 FROM users WHERE invite_code=?", (code,)).fetchone():
            return code
    raise RuntimeError("邀请码生成连续冲突，请重试")


def ensure_code(conn, uid: int) -> str:
    """取用户的邀请码，没有就分配一个（惰性发放，老账号也能自然补上）。"""
    row = conn.execute("SELECT invite_code FROM users WHERE id=?", (uid,)).fetchone()
    if row and row["invite_code"]:
        return row["invite_code"]
    code = new_code(conn)
    conn.execute("UPDATE users SET invite_code=? WHERE id=?", (code, uid))
    return code


# ---------------------------------------------------------------- 身份标记

def network_of(ip: str) -> str:
    """把 IP 收成"网段"，用于识别同一个出口后面批量冒出来的账号。

    IPv4 取 /24、IPv6 取 /48。为什么是这个粒度：
    家宽、办公网同一出口下面有十几个人很正常，/24 刚好能容忍这种日常情况；
    但同一个机房/同一个手机卡的 NAT 池能被别人无限量地注册下去就不正常了，
    /24 也刚好能把它们收拢到一块儿。
    """
    try:
        addr = ipaddress.ip_address((ip or "").strip())
    except ValueError:
        return ip or ""
    return str(ipaddress.ip_network(f"{addr}/{24 if addr.version == 4 else 48}",
                                    strict=False))


def register_identity(conn, uid: int, ip: str = "", fp: str = "") -> str:
    """账号落地时记下来源。**必须在 bind() 之前调用**——邀请判重比的就是它。"""
    ensure_code(conn, uid)
    if ip or fp:
        conn.execute("UPDATE users SET reg_ip=?, reg_fp=? WHERE id=?",
                     (ip or None, db.hash_device(fp), uid))
    return ensure_code(conn, uid)


# ---------------------------------------------------------------- 建立关系

def bind(conn, invitee_id: int, code: str, ip: str = "", fp: str = "") -> dict:
    """建立邀请关系并做第一轮判定。

    返回 {"status": "pending"|"rejected"|"none", "reason": 人话}。
    **不会因为邀请码有问题而throw 异常**：注册本身就是应该继续完成的，
    邀请只是附加权益，不能因为朋友手抖填错码就让人家连账号都开不了。
    """
    code = (code or "").strip().upper()
    if not code:
        return {"status": "none", "reason": ""}

    # 每一步判死都用 _reject 收口：理由统一写进 audit_log，
    # 否则"为什么这个人没拿到奖励"过两周就变成一个没人答得上来的问题。
    inviter = conn.execute("SELECT * FROM users WHERE invite_code=?", (code,)).fetchone()
    if not inviter:
        return _reject(conn, invitee_id, "邀请码不存在", code)
    if inviter["id"] == invitee_id:
        return _reject(conn, invitee_id, "不能邀请自己", code, inviter["id"])
    if inviter["is_banned"]:
        return _reject(conn, invitee_id, "邀请人的账号已被封禁", code, inviter["id"])
    invitee = conn.execute("SELECT * FROM users WHERE id=?", (invitee_id,)).fetchone()
    if not invitee:
        return {"status": "rejected", "reason": "账号不存在"}
    if invitee["invited_by"] or conn.execute(
            "SELECT 1 FROM invites WHERE invitee_id=?", (invitee_id,)).fetchone():
        return _reject(conn, invitee_id, "这个账号已经登记过邀请关系了", code, inviter["id"])
    # 互邀：A 拉了 B，B 再填 A 的码反手自己也拿一份。第一次建立关系是
    # 正常的，第二次才是问题，所以靠这条双向判断拦。
    if inviter["invited_by"] == invitee_id:
        return _reject(conn, invitee_id, "不能互相邀请", code, inviter["id"])

    same_ip = bool(ip) and ip == (inviter["reg_ip"] or "")
    same_device = bool(fp) and bool(inviter["reg_fp"]) \
        and db.hash_device(fp) == inviter["reg_fp"]

    # 强判定：同一出口 + 同一台电脑，除了本人想不出第二种解释
    if same_ip and same_device:
        return _reject(conn, invitee_id, "同一网络且同一设备，判定为本人操作",
                       code, inviter["id"])

    net = network_of(ip)
    now_iso = db.now_iso()
    recent = conn.execute(
        "SELECT COUNT(*) c FROM invites WHERE network=? AND status!='rejected'"
        " AND created_at > ?", (net, _ago(config.INVITE_NET_WINDOW))).fetchone()["c"]
    if net and recent >= config.INVITE_NET_MAX:
        return _reject(conn, invitee_id,
                       f"同一网络来源的邀请过多（{recent}/{config.INVITE_NET_MAX}）",
                       code, inviter["id"])

    today = now_iso[:10]
    n_today = conn.execute(
        "SELECT COUNT(*) c FROM invites WHERE inviter_id=? AND status!='rejected'"
        " AND created_at LIKE ?", (inviter["id"], f"{today}%")).fetchone()["c"]
    if n_today >= config.INVITE_DAILY_CAP:
        return _reject(conn, invitee_id, "邀请人今天邀请的人数已达上限",
                       code, inviter["id"])

    n_total = conn.execute(
        "SELECT COUNT(*) c FROM invites WHERE inviter_id=? AND status='rewarded'",
        (inviter["id"],)).fetchone()["c"]
    if n_total >= config.INVITE_TOTAL_CAP:
        return _reject(conn, invitee_id, "邀请人的累计邀请已达上限",
                       code, inviter["id"])

    conn.execute(
        "INSERT INTO invites(inviter_id, invitee_id, code, status, same_ip, same_device,"
        " ip, network, device_fp, created_at) VALUES(?,?,?,'pending',?,?,?,?,?,?)",
        (inviter["id"], invitee_id, code, int(same_ip), int(same_device),
         ip or "", net, db.hash_device(fp), now_iso))
    conn.execute("UPDATE users SET invited_by=?, invite_at=? WHERE id=?",
                 (inviter["id"], now_iso, invitee_id))

    db.audit(conn, invitee_id, "invite_bind", f"user:{inviter['id']}",
             f"邀请人 {inviter['nickname'] or inviter['id']}｜"
             f"{'弱命中：' if (same_ip or same_device) else ''}"
             f"{'同网络 ' if same_ip else ''}{'同设备' if same_device else ''}".strip())
    # 判定通过了就当场结算。之前设计成"等对方活跃再发"，但真实运营里
    # 邀请人看不到到账会直接来问，而这个"活跃"门槛同时可以被脚本轻松跨越
    # （连续两天上线即可），拦不住作弊却在拦住信任感。所以它不承担反作弊职责，
    # 反作弊全在上面那七条判定里完成。
    row = conn.execute("SELECT * FROM invites WHERE invitee_id=? AND status='pending'",
                       (invitee_id,)).fetchone()
    pay(conn, row, invitee)
    return {"status": "rewarded", "points": config.INVITE_REWARD,
            "reason": f"{config.INVITE_REWARD} 积分已到账",
            "inviter": inviter["nickname"]}


def _reject(conn, invitee_id: int, reason: str, code: str = "",
            inviter_id: int | None = None) -> dict:
    """判定失败：不写 invites 行，但必须留下审计。

    为什么不写成 status='rejected' 的行：那是"已经成立过又被判死"的语义，
    而这些是一次都没成立；更实际的是 invitee_id 上有 UNIQUE，一旦写死，
    这个人以后连被别人正常邀请的资格都没了——额度超限本来是会随时间恢复的。
    """
    db.audit(conn, invitee_id, "invite_reject", f"user:{inviter_id or '-'}",
             f"{reason}｜code={code or '-'}")
    return {"status": "rejected", "reason": reason}


def bind_later(conn, invitee_id: int, code: str, ip: str = "", fp: str = "") -> dict:
    """注册之后补填邀请码。只允许在注册后的时间窗内、且从未绑过的情况下使用。

    为什么要限制时间窗：不限制的话，一个老用户可以随时"认领"任意一个邀请人，
    邀请码就变成了可以事后倒卖的东西。
    """
    me = conn.execute("SELECT created_at FROM users WHERE id=?", (invitee_id,)).fetchone()
    if not me:
        raise ValueError("账号不存在")
    try:
        born = time.mktime(time.strptime(me["created_at"][:19], "%Y-%m-%dT%H:%M:%S"))
    except ValueError:
        born = time.time()
    if time.time() - born > config.INVITE_BIND_WINDOW:
        days = config.INVITE_BIND_WINDOW // 86400
        return {"status": "rejected", "reason": f"注册超过 {days} 天后不能再填写邀请码"}
    return bind(conn, invitee_id, code, ip, fp)


# ---------------------------------------------------------------- 结算

def login_days(conn, uid: int) -> int:
    """累计有几个自然日登录过。用 point_logs 里的每日登录记录算，不另开表。"""
    return conn.execute(
        "SELECT COUNT(DISTINCT substr(created_at,1,10)) c FROM point_logs"
        " WHERE user_id=? AND reason='daily_login'", (uid,)).fetchone()["c"]


def spot_count(conn, uid: int) -> int:
    return conn.execute("SELECT COUNT(*) c FROM spots WHERE created_by=?",
                        (uid,)).fetchone()["c"]


def settle(conn, invitee_id: int) -> dict | None:
    """给**还没结算的**邀请记录发放奖励。

    新版所有邀请都在 bind() 里当场结算，这条路径只剩下两个用途：
      1. 老版本留下来的 pending 记录（那时要等对方活跃），升级后不至于石沉大海
      2. 事后发现误判时，管理员手动改成 pending 再让他登录一次即可补发
    没有 pending 记录时只是一次带索引的空查询，成本可以忽略。
    """
    row = conn.execute(
        "SELECT * FROM invites WHERE invitee_id=? AND status='pending'",
        (invitee_id,)).fetchone()
    if not row:
        return None

    invitee = conn.execute("SELECT * FROM users WHERE id=?", (invitee_id,)).fetchone()
    if not invitee or invitee["is_banned"]:
        conn.execute("UPDATE invites SET status='rejected', reason='被邀请人已被封禁'"
                     " WHERE id=?", (row["id"],))
        return {"status": "rejected", "reason": "被邀请人已被封禁"}
    # 结算时才查封禁：建立关系时人是好的，等活跃这几天里可能被封了
    inviter = conn.execute("SELECT * FROM users WHERE id=?", (row["inviter_id"],)).fetchone()
    if not inviter or inviter["is_banned"]:
        conn.execute("UPDATE invites SET status='rejected', reason='邀请人已被封禁'"
                     " WHERE id=?", (row["id"],))
        return {"status": "rejected", "reason": "邀请人已被封禁"}
    return pay(conn, row, invitee)


def pay(conn, row, invitee) -> dict:
    """真正把积分记到邀请人账上。bind() 和 settle() 共用这一段。"""
    inviter = conn.execute("SELECT * FROM users WHERE id=?", (row["inviter_id"],)).fetchone()
    if not inviter or inviter["is_banned"]:
        conn.execute("UPDATE invites SET status='rejected', reason='邀请人已被封禁'"
                     " WHERE id=?", (row["id"],))
        return {"status": "rejected", "reason": "邀请人已被封禁"}

    pts = config.INVITE_REWARD
    db.add_points(conn, inviter["id"], pts, "invite_reward", invitee["id"])
    conn.execute("UPDATE invites SET status='rewarded', rewarded_at=? WHERE id=?",
                 (db.now_iso(), row["id"]))
    db.audit(conn, inviter["id"], "invite_reward", f"user:{invitee['id']}",
             f"+{pts} 积分｜被邀请人 {invitee['nickname'] or invitee['id']}"
             f"（判定通过：{'同网设备弱命中' if (row['same_ip'] or row['same_device']) else '不同网络与设备'}）")
    notify.notify(conn, inviter["id"], "invite", "邀请奖励已到账",
                  f"你邀请的「{invitee['nickname'] or '新用户'}」已加入，"
                  f"{pts} 积分已到账（累计 {inviter['points'] + pts} 分）。",
                  f"invite:{row['id']}")
    log.info("邀请奖励发放 inviter=%s invitee=%s pts=%s", inviter["id"],
             invitee["id"], pts)
    return {"status": "rewarded", "points": pts, "inviter_id": inviter["id"]}


# ---------------------------------------------------------------- 查询

def my_summary(conn, uid: int, base_url: str = "") -> dict:
    """用户在"邀请有奖"页要看到的全部内容。"""
    code = ensure_code(conn, uid)
    rows = conn.execute(
        "SELECT i.*, u.nickname, u.is_banned FROM invites i"
        " LEFT JOIN users u ON u.id = i.invitee_id"
        " WHERE i.inviter_id=? ORDER BY i.id DESC LIMIT 200", (uid,)).fetchall()
    items = []
    for r in rows:
        days = login_days(conn, r["invitee_id"])
        spots = spot_count(conn, r["invitee_id"])
        risk = bool(r["same_ip"] or r["same_device"])
        items.append({
            "invitee": r["nickname"] or "新用户",
            "status": r["status"],
            "reason": r["reason"],
            "created_at": r["created_at"],
            "rewarded_at": r["rewarded_at"],
            "login_days": days,
            "spots": spots,
            "risk": risk,
            # 只有老版本遗留的 pending 还挂着一个门槛（见 settle 的注释）
            "need": (f"回访 {config.INVITE_RISK_ACTIVATE_DAYS} 天并提交 "
                     f"{config.INVITE_ACTIVATE_SPOTS} 个营地" if risk else
                     f"回访 {config.INVITE_ACTIVATE_DAYS} 天或提交 "
                     f"{config.INVITE_ACTIVATE_SPOTS} 个营地")
                    if r["status"] == "pending" else "",
        })
    rewarded = sum(1 for r in rows if r["status"] == "rewarded")
    pending = sum(1 for r in rows if r["status"] == "pending")
    rejected = sum(1 for r in rows if r["status"] == "rejected")
    me = conn.execute("SELECT invited_by FROM users WHERE id=?", (uid,)).fetchone()
    inviter = None
    if me and me["invited_by"]:
        r = conn.execute("SELECT nickname FROM users WHERE id=?",
                         (me["invited_by"],)).fetchone()
        inviter = (r["nickname"] or "朋友") if r else "朋友"
    return {
        "code": code,
        "invited_by": inviter,     # 我自己是被谁邀请来的（用来决定要不要显示"补填"入口）
        "link": f"{base_url}/?invite={code}" if base_url else "",
        "reward": config.INVITE_REWARD,
        "stats": {"total": len(rows), "rewarded": rewarded,
                  "pending": pending, "rejected": rejected},
        "items": items,
        "rules": {
            "reward": config.INVITE_REWARD,
            "need_days": config.INVITE_ACTIVATE_DAYS,
            "need_spots": config.INVITE_ACTIVATE_SPOTS,
            "risk_days": config.INVITE_RISK_ACTIVATE_DAYS,
            "bind_days": config.INVITE_BIND_WINDOW // 86400,
            "total_cap": config.INVITE_TOTAL_CAP,
        },
    }


def _ago(seconds: int) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(time.time() - seconds))
