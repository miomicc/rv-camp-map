"""附加路由：站内通知。

通知是"运营闭环"的关键：用户提交了营地却不知道审没审过，就会流失。
（手机号绑定 / 验证码登录 / 密钥找回已按产品决策移除。）
"""

from fastapi import APIRouter, Depends, Query

import db
import notify
from common import require_admin, require_user

router = APIRouter()


# ---------------------------------------------------------------- 站内通知

@router.get("/api/notifications")
def list_notifications(limit: int = Query(30, ge=1, le=100),
                       user=Depends(require_user)):
    with db.get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM notifications WHERE user_id=? ORDER BY id DESC LIMIT ?",
            (user["id"], limit)).fetchall()
        unread = conn.execute(
            "SELECT COUNT(*) c FROM notifications WHERE user_id=? AND is_read=0",
            (user["id"],)).fetchone()["c"]
        return {"unread": unread, "items": [db.row_to_dict(r) for r in rows],
                "types": notify.TYPES}


@router.get("/api/notifications/unread")
def unread_count(user=Depends(require_user)):
    with db.get_conn() as conn:
        c = conn.execute(
            "SELECT COUNT(*) c FROM notifications WHERE user_id=? AND is_read=0",
            (user["id"],)).fetchone()["c"]
        return {"unread": c}


@router.post("/api/notifications/{nid}/read")
def read_one(nid: int, user=Depends(require_user)):
    with db.get_conn() as conn:
        conn.execute("UPDATE notifications SET is_read=1 WHERE id=? AND user_id=?",
                     (nid, user["id"]))
    return {"ok": True}


@router.post("/api/notifications/read-all")
def read_all(user=Depends(require_user)):
    with db.get_conn() as conn:
        cur = conn.execute(
            "UPDATE notifications SET is_read=1 WHERE user_id=? AND is_read=0",
            (user["id"],))
    return {"ok": True, "updated": cur.rowcount or 0}


# ---------------------------------------------------------------- 后台：通知管理

@router.get("/api/admin/notifications")
def admin_notifications(limit: int = Query(50, ge=1, le=200),
                        admin=Depends(require_admin)):
    with db.get_conn() as conn:
        rows = conn.execute(
            "SELECT n.*, u.nickname, u.user_no FROM notifications n"
            " LEFT JOIN users u ON u.id=n.user_id ORDER BY n.id DESC LIMIT ?",
            (limit,)).fetchall()
        return {"items": [db.row_to_dict(r) for r in rows]}
