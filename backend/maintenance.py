"""运维任务：清理、孤儿文件回收、备份。

这些事情没有一件是"功能"，但每一件不做都会在生产环境变成事故：
  - tokens 只增不删 -> 跑了半年表就几十万行，登录校验变慢
  - 上传的孤儿文件没人回收 -> 磁盘默默被吃光
  - 没有备份 -> 一次误删就是全站数据归零

用法：
    python maintenance.py            # 立即执行一次全部任务
    python maintenance.py --backup   # 只做备份
    python maintenance.py --gc-dry   # 孤儿文件只报告不删除

服务启动时也会拉起一个后台线程按 config.MAINTENANCE_INTERVAL 周期执行。
"""

import json
import os
import shutil
import sqlite3
import sys
import tarfile
import threading
import time

import config
import db
import ratelimit
from logsetup import log


# ---------------------------------------------------------------- 清理

def purge_tokens(days: int = None) -> int:
    days = days if days is not None else config.TOKEN_TTL_DAYS
    with db.get_conn() as conn:
        cur = conn.execute("DELETE FROM tokens WHERE expire_at < ?",
                           (int(time.time()) - days * 86400,))
        return cur.rowcount or 0


def purge_login_fails() -> int:
    with db.get_conn() as conn:
        db.purge_old_login_fails(conn)
        return 0


def purge_sms_codes() -> int:
    with db.get_conn() as conn:
        cur = conn.execute("DELETE FROM sms_codes WHERE expire_at < ?", (int(time.time()),))
        return cur.rowcount or 0


def purge_old(keep_days: int) -> str:
    """把 keep_days 转成 ISO 时间串，用于按 created_at 删除。"""
    return time.strftime("%Y-%m-%dT%H:%M:%S",
                         time.localtime(time.time() - keep_days * 86400))


def purge_logs() -> dict:
    cut_audit = purge_old(config.KEEP_AUDIT_DAYS)
    cut_notify = purge_old(config.KEEP_NOTIFY_DAYS)
    cut_points = purge_old(config.KEEP_POINTLOG_DAYS)
    with db.get_conn() as conn:
        a = conn.execute("DELETE FROM audit_log WHERE created_at < ?", (cut_audit,)).rowcount or 0
        n = conn.execute(
            "DELETE FROM notifications WHERE is_read=1 AND created_at < ?",
            (cut_notify,)).rowcount or 0
        p = conn.execute("DELETE FROM point_logs WHERE created_at < ?", (cut_points,)).rowcount or 0
    return {"audit": a, "notifications": n, "point_logs": p}


# ---------------------------------------------------------------- 孤儿文件回收

def _referenced_images() -> set:
    """所有被营地引用的图片路径。thumb 由 url 推导。"""
    refs = set()
    with db.get_conn() as conn:
        rows = conn.execute("SELECT images FROM spots").fetchall()
    for r in rows:
        try:
            items = json.loads(r["images"] or "[]")
        except Exception:
            items = []
        for it in items:
            if isinstance(it, str):
                refs.add(it)
            elif isinstance(it, dict):
                refs.add(it.get("url", ""))
                if it.get("thumb"):
                    refs.add(it["thumb"])
    return {x for x in refs if x}


def gc_orphan_uploads(dry_run: bool = False, age_days: int = None) -> dict:
    """回收没人引用的上传文件。

    只处理 uploads 表里有登记的文件——目录里来路不明的文件一律只报告不删除，
    避免误删 seed 数据或运维手工放进去的东西。
    """
    age_days = age_days if age_days is not None else config.ORPHAN_FILE_AGE_DAYS
    cut = int(time.time()) - age_days * 86400
    refs = _referenced_images()

    deleted, kept_bytes, deleted_bytes = [], 0, 0
    with db.get_conn() as conn:
        rows = conn.execute("SELECT id, path, thumb FROM uploads").fetchall()
        for r in rows:
            path, thumb = r["path"], r["thumb"] or ""
            if path in refs or thumb in refs:
                continue
            # 只回收登记时间早于阈值的（新上传的可能还在提交流程里）
            try:
                import images as _img
                abs_p = _img.safe_join(path)
                mtime = os.path.getmtime(abs_p)
            except Exception:
                continue
            if mtime > cut:
                continue
            size = 0
            try:
                size = os.path.getsize(abs_p)
            except Exception:
                pass
            if dry_run:
                deleted.append(path)
                deleted_bytes += size
                continue
            for rel in (path, thumb):
                if not rel:
                    continue
                try:
                    import images as _img
                    p = _img.safe_join(rel)
                    if os.path.isfile(p):
                        os.remove(p)
                except Exception as e:
                    log.warning("孤儿文件删除失败 %s: %s", rel, e)
            conn.execute("DELETE FROM uploads WHERE id=?", (r["id"],))
            deleted.append(path)
            deleted_bytes += size
        conn.commit()

    # 目录里没登记的文件：只统计
    stray = 0
    for root, _dirs, files in os.walk(str(config.UPLOAD_DIR)):
        for f in files:
            fp = os.path.join(root, f)
            try:
                kept_bytes += os.path.getsize(fp)
            except Exception:
                pass
            rel = "/uploads/" + os.path.relpath(fp, str(config.UPLOAD_DIR)).replace(os.sep, "/")
            if rel not in refs:
                stray += 1

    log.info("孤儿回收：删除 %d 个（%.1fMB），无登记文件 %d 个（保留）",
             len(deleted), deleted_bytes / 1048576, stray)
    return {"deleted": deleted, "deleted_bytes": deleted_bytes,
            "stray": stray, "kept_bytes": kept_bytes, "dry_run": dry_run}


# ---------------------------------------------------------------- 瓦片缓存

def purge_tile_cache(max_days: int = None, max_mb: int = None) -> dict:
    """清理自建瓦片代理的磁盘缓存（backend/tileproxy.py）。

    缓存是"能占就占"的：不淘汰，跑几个月就能吃掉几十 GB。
    """
    try:
        import tileproxy
        return tileproxy.purge(max_days, max_mb)
    except Exception as e:
        log.warning("瓦片缓存清理失败：%s", e)
        return {"error": str(e)}


def purge_captchas() -> int:
    """清掉过期/已用的图形验证码。"""
    try:
        import captcha
        return captcha.purge()
    except Exception as e:
        log.warning("验证码清理失败：%s", e)
        return 0


# ---------------------------------------------------------------- 会员到期提醒

def remind_expiring(days: int = 7) -> int:
    """会员到期前提醒。同一用户同一到期日只发一次（靠 ref 去重）。"""
    sent = 0
    with db.get_conn() as conn:
        rows = conn.execute(
            "SELECT id, expire_at FROM users WHERE level=1 AND is_banned=0"
            " AND expire_at IS NOT NULL AND expire_at != ''").fetchall()
        soon = time.time() + days * 86400
        for r in rows:
            try:
                exp = time.mktime(time.strptime(r["expire_at"][:19], "%Y-%m-%dT%H:%M:%S"))
            except Exception:
                continue
            if not (time.time() < exp <= soon):
                continue
            ref = f"expire:{r['expire_at'][:10]}"
            exists = conn.execute(
                "SELECT 1 FROM notifications WHERE user_id=? AND type='member_expiring'"
                " AND ref=?", (r["id"], ref)).fetchone()
            if exists:
                continue
            import notify
            notify.push(conn, r["id"], "member_expiring", "会员即将到期",
                        f"你的会员将在 {r['expire_at'][:10]} 到期，续费可继续查看营地完整信息。",
                        ref)
            sent += 1
    return sent


# ---------------------------------------------------------------- 备份

def backup(keep: int = 14, with_uploads: bool = True) -> str:
    """热备份：SQLite 用 VACUUM INTO（在线一致快照，不需要停服务）。"""
    import datetime
    config.BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    db_out = config.BACKUP_DIR / f"rvcamp-{stamp}.db"

    src = str(config.DATA_DIR / "rvcamp.db")
    conn = sqlite3.connect(src)
    try:
        conn.execute("VACUUM INTO ?", (str(db_out),))
    except sqlite3.OperationalError:
        # 老版本 SQLite 不支持 VACUUM INTO，退回文件拷贝
        conn.close()
        shutil.copy2(src, db_out)
    else:
        conn.close()

    out = str(db_out)
    if with_uploads:
        tar_path = config.BACKUP_DIR / f"uploads-{stamp}.tar.gz"
        try:
            with tarfile.open(tar_path, "w:gz") as tf:
                tf.add(str(config.UPLOAD_DIR), arcname="uploads")
            out = str(tar_path) + " (+" + str(db_out) + ")"
        except Exception as e:
            log.error("上传目录打包失败：%s", e)

    _rotate(keep)
    size_mb = os.path.getsize(db_out) / 1048576
    log.info("备份完成 %s（%.2fMB）", out, size_mb)
    return out


def _rotate(keep: int) -> None:
    """只保留最近 keep 份，老的删掉——否则备份自己会先撑爆磁盘。"""
    files = sorted(config.BACKUP_DIR.glob("rvcamp-*.db"),
                   key=lambda p: p.stat().st_mtime, reverse=True)
    for p in files[keep:]:
        try:
            p.unlink()
        except Exception:
            pass
    tars = sorted(config.BACKUP_DIR.glob("uploads-*.tar.gz"),
                  key=lambda p: p.stat().st_mtime, reverse=True)
    for p in tars[keep:]:
        try:
            p.unlink()
        except Exception:
            pass


# ---------------------------------------------------------------- 入口

def run_all() -> dict:
    started = time.time()
    stat = {}
    try:
        stat["tokens"] = purge_tokens()
        purge_login_fails()
        stat["sms_codes"] = purge_sms_codes()
        stat["logs"] = purge_logs()
        stat["rate_hits"] = ratelimit.purge()
        stat["orphan"] = gc_orphan_uploads()
        stat["expire_remind"] = remind_expiring()
        stat["tiles"] = purge_tile_cache()
        stat["captchas"] = purge_captchas()
    except Exception as e:
        log.error("运维任务失败：%s", e)
        stat["error"] = str(e)
    stat["cost_ms"] = int((time.time() - started) * 1000)
    log.info("运维任务完成 %s", {k: v for k, v in stat.items() if k != "orphan"})
    return stat


def start_scheduler(interval: int = None) -> threading.Thread:
    interval = interval or config.MAINTENANCE_INTERVAL

    def loop():
        while True:
            time.sleep(interval)
            try:
                run_all()
            except Exception as e:
                log.error("周期运维异常：%s", e)

    t = threading.Thread(target=loop, name="maintenance", daemon=True)
    t.start()
    log.info("运维调度已启动，间隔 %d 秒", interval)
    return t


if __name__ == "__main__":
    args = sys.argv[1:]
    if "--backup" in args:
        print(backup())
    elif "--gc-dry" in args:
        print(gc_orphan_uploads(dry_run=True))
    else:
        print(json.dumps(run_all(), ensure_ascii=False, indent=2, default=str))
