"""日志。

之前整个项目 0 处 logging——排查线上问题只能靠猜。
这里做两件事：
  1. 控制台 + 文件双输出，文件按大小轮转，避免日志把磁盘写满
  2. 提供 access 结构化日志，记录 IP / 方法 / 路径 / 耗时 / 状态码，
     限流和安全事件才有据可查
"""

import logging
import time
from logging.handlers import RotatingFileHandler

import config

_FORMAT = "%(asctime)s | %(levelname)-7s | %(name)-12s | %(message)s"
_DATEFMT = "%Y-%m-%d %H:%M:%S"

_configured = False


def setup() -> logging.Logger:
    """初始化根 logger。重复调用安全。"""
    global _configured
    if _configured:
        return logging.getLogger("rvcamp")

    fmt = logging.Formatter(_FORMAT, datefmt=_DATEFMT)
    root = logging.getLogger()
    root.setLevel(config.LOG_LEVEL)

    sh = logging.StreamHandler()
    sh.setFormatter(fmt)
    root.addHandler(sh)

    try:
        fh = RotatingFileHandler(
            config.LOG_DIR / "rvcamp.log",
            maxBytes=config.LOG_MAX_BYTES,
            backupCount=config.LOG_BACKUPS,
            encoding="utf-8",
        )
        fh.setFormatter(fmt)
        root.addHandler(fh)
    except Exception as e:      # 日志目录不可写时不能让服务起不来
        root.warning("日志文件不可用，仅输出控制台：%s", e)

    # uvicorn 自己那套 logger 太吵，压到 WARNING
    for name in ("uvicorn", "uvicorn.access", "uvicorn.error"):
        logging.getLogger(name).setLevel(logging.WARNING)

    _configured = True
    return logging.getLogger("rvcamp")


log = setup()


def access(request, status: int, started: float, extra: str = "") -> None:
    """一行访问日志。敏感参数（密钥、验证码）绝不进日志。"""
    cost = int((time.time() - started) * 1000)
    ip = request.headers.get("x-forwarded-for", "").split(",")[0].strip() or (
        request.client.host if request.client else "-")
    log.info("%s %s %s %d %dms %s", ip, request.method,
             request.url.path, status, cost, extra)
