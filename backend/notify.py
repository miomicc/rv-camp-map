"""通知：站内信为主，外部通道可插拔。

用户提交营地之后最想知道的是"我的提交过审了吗"。没有通知，
用户只能反复刷新页面——这是众包平台留存率最低的环节之一。

设计：
  - 站内信是**唯一保证送达**的通道，永远写库
  - 邮件/短信是可选增强：配置了 SMTP / 短信网关就发，没配置就只写日志。
    这样本地开发和生产部署用同一套代码，不会因为缺配置就报错。
"""

import smtplib
from email.header import Header
from email.mime.text import MIMEText

import config
import db
from logsetup import log

# 通知类型：集中定义，前端据此渲染图标
TYPES = {
    "spot_approved": "营地上线",
    "spot_rejected": "营地被驳回",
    "spot_reported": "营地被举报",
    "member_expiring": "会员即将到期",
    "member_expired": "会员已到期",
    "order_paid": "支付成功",
    "points": "积分变动",
    "key_rotated": "密钥已换发",
    "phone_bound": "手机号已绑定",
    "system": "系统通知",
}


def notify(conn, user_id, type_: str, title: str, body: str = "", ref: str = "") -> int:
    """写一条站内信。conn 由调用方提供，保证与业务操作在同一个事务里。"""
    cur = conn.execute(
        "INSERT INTO notifications(user_id, type, title, body, ref, is_read, created_at)"
        " VALUES(?,?,?,?,?,0,?)",
        (user_id, type_, title, body, ref, db.now_iso()))
    return cur.lastrowid


def notify_admins(conn, type_: str, title: str, body: str = "", ref: str = "") -> int:
    """广播给所有管理员（比如出现新的待审营地）。"""
    ids = [r["id"] for r in conn.execute(
        "SELECT id FROM users WHERE is_admin=1 AND is_banned=0").fetchall()]
    for uid in ids:
        notify(conn, uid, type_, title, body, ref)
    return len(ids)


# ---------------------------------------------------------------- 外部通道

def send_email(to: str, subject: str, body: str) -> bool:
    """发邮件。未配置 SMTP 时只记日志并返回 False。

    返回 False 不代表失败——调用方不该因此中断业务流程。
    """
    if not to or "@" not in to:
        return False
    if not (config.SMTP_HOST and config.SMTP_USER):
        log.info("[email:未配置] -> %s | %s", to, subject)
        return False
    try:
        msg = MIMEText(body, "plain", "utf-8")
        msg["Subject"] = Header(subject, "utf-8")
        msg["From"] = config.SMTP_FROM or config.SMTP_USER
        msg["To"] = to
        with smtplib.SMTP_SSL(config.SMTP_HOST, config.SMTP_PORT, timeout=10) as s:
            s.login(config.SMTP_USER, config.SMTP_PASS)
            s.sendmail(config.SMTP_USER, [to], msg.as_string())
        log.info("[email] -> %s | %s", to, subject)
        return True
    except Exception as e:
        log.error("邮件发送失败 %s: %s", to, e)
        return False


def send_sms(phone: str, text: str) -> bool:
    """发短信。provider=none 只记日志；=console 打到日志；=http 走自建网关。

    不直连任何一家云短信 SDK：一旦绑定，换供应商就要改代码。
    留一个 HTTP 网关适配层，供应商变更只是改配置。
    """
    if not phone:
        return False
    if config.SMS_PROVIDER == "none":
        log.info("[sms:未配置] -> %s | %s", phone[:3] + "****" + phone[-4:], text)
        return False
    if config.SMS_PROVIDER == "console":
        log.info("[sms:console] -> %s | %s", phone, text)
        return True
    if config.SMS_PROVIDER == "http":
        if not config.SMS_ENDPOINT:
            log.error("SMS_PROVIDER=http 但未配置 RVCAMP_SMS_ENDPOINT")
            return False
        try:
            import urllib.request
            import json as _json
            payload = _json.dumps({"phone": phone, "text": text,
                                   "sign": config.SMS_SIGN}).encode()
            req = urllib.request.Request(
                config.SMS_ENDPOINT, data=payload,
                headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=10) as r:
                ok = 200 <= r.status < 300
                log.info("[sms:http] -> %s status=%s", phone, r.status)
                return ok
        except Exception as e:
            log.error("短信发送失败 %s: %s", phone, e)
            return False
    return False


def push(conn, user_id, type_: str, title: str, body: str = "", ref: str = "") -> int:
    """站内信 + （尽力而为的）外部通道。业务代码只需要调这一个函数。"""
    nid = notify(conn, user_id, type_, title, body, ref)
    row = conn.execute("SELECT phone, email FROM users WHERE id=?", (user_id,)).fetchone()
    if row:
        if row["phone"]:
            send_sms(row["phone"], f"{title}：{body}"[:120])
        if row["email"]:
            send_email(row["email"], title, body)
    return nid
