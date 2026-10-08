"""限流。

之前只有"登录"一个接口有限流，其余接口（领密钥、提交营地、上传图片、
发验证码）全部裸奔——一台机器就能把数据库灌满垃圾数据。

设计取舍：
  - 用 SQLite 记表而不是内存字典。内存字典在 uvicorn 开多个 worker
    时每个进程各记一份，限流会被放大 N 倍；而且服务一重启就清零。
  - 只统计写操作，GET 视口查询频率很高但代价低，交给全局兜底即可。
  - 计数表由 maintenance 定时清理，不需要每次请求都删旧数据。
"""

import time

from fastapi import HTTPException, Request

import config
import db
from logsetup import log


def _window_left(conn, scope: str, identity: str, window: int, now: int) -> int:
    """还需等待多少秒才恢复。取窗口内最早一条记录的过期时间。"""
    row = conn.execute(
        "SELECT MIN(created_at) m FROM rate_hits WHERE scope=? AND identity=? AND created_at>?",
        (scope, identity, now - window)).fetchone()
    oldest = row["m"] if row and row["m"] is not None else now
    return max(1, int(oldest + window - now))


def count(scope: str, identity: str, window: int) -> int:
    """只查询不计数。用于"额度"类判断（比如今日还能看几条详情）。"""
    now = int(time.time())
    with db.get_conn() as conn:
        return conn.execute(
            "SELECT COUNT(*) c FROM rate_hits WHERE scope=? AND identity=? AND created_at>?",
            (scope, identity, now - window)).fetchone()["c"]


def hit(scope: str, identity: str) -> None:
    """只计数不判定。"""
    with db.get_conn() as conn:
        conn.execute(
            "INSERT INTO rate_hits(scope, identity, created_at) VALUES(?,?,?)",
            (scope, identity, int(time.time())))
        conn.commit()


def guard(scope: str, identity: str, window: int, limit: int,
          message: str = "操作太频繁") -> None:
    """一次计数 + 判定。超限抛 429。"""
    now = int(time.time())
    with db.get_conn() as conn:
        n = conn.execute(
            "SELECT COUNT(*) c FROM rate_hits WHERE scope=? AND identity=? AND created_at>?",
            (scope, identity, now - window)).fetchone()["c"]
        if n >= limit:
            left = _window_left(conn, scope, identity, window, now)
            log.warning("限流命中 scope=%s identity=%s count=%d/%d", scope, identity, n, limit)
            raise HTTPException(429, f"{message}，请 {left} 秒后再试")
        conn.execute(
            "INSERT INTO rate_hits(scope, identity, created_at) VALUES(?,?,?)",
            (scope, identity, now))
        conn.commit()   # 必须显式提交：get_conn 在异常路径上会 rollback


def rule(name: str, identity: str, message: str = "操作太频繁") -> None:
    """按 config.RATE_RULES 里定义的规则限流。"""
    window, limit = config.RATE_RULES.get(name, (60, 20))
    guard(name, identity, window, limit, message)


def client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for", "")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def guard_write(request: Request) -> None:
    """所有写请求的兜底：单 IP 单位时间内总次数上限。"""
    if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
        return
    window, limit = config.RATE_WRITE_GLOBAL
    guard("write", client_ip(request), window, limit, "请求太频繁")


def purge(keep_seconds: int = 86400) -> int:
    """清掉过期计数。由 maintenance 定时调用。"""
    cut = int(time.time()) - keep_seconds
    with db.get_conn() as conn:
        cur = conn.execute("DELETE FROM rate_hits WHERE created_at < ?", (cut,))
        return cur.rowcount or 0
