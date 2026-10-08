"""图形验证码。

为什么要有这一层：领密钥是"匿名就能白拿一个账号"的接口，仅靠 IP 限流
挡不住换 IP 的脚本，也挡不住校园网/公司出口这种"一个 IP 几千人"的场景
（限太狠会误伤真人）。验证码是目前成本最低、效果最直接的刹车。

实现上刻意不引第三方服务（Google reCAPTCHA 之类）：那意味着多一个外部依赖、
多一份隐私顾虑，而且国内还不一定连得上。这里用 Pillow 自己画，几百行搞定，
纯本地、零费用、零外链。

用法：
    cid, png = captcha.new_challenge(conn)     # 生成并存库，返回 id 与 PNG 字节
    captcha.verify(conn, cid, user_input)      # 校验失败直接抛 400
"""

import io
import os
import random
import secrets
import string
import time

from fastapi import HTTPException
from PIL import Image, ImageDraw, ImageFont

import config

# 去掉了 0/O、1/I/L 这种肉眼容易混的字符——验证码是用来挡机器的，不是用来为难人的
ALPHABET = "".join(c for c in (string.ascii_uppercase + string.digits)
                   if c not in "OI01L")
LENGTH = 4
TTL = config.env_int("RVCAMP_CAPTCHA_TTL", 300)      # 5 分钟
MAX_TRIES = 5                                         # 错 5 次就作废，防暴力试

_FONT_CACHE = {}


def _font(size: int):
    """找一个能用的 TrueType 字体。找不到就用 Pillow 自带位图字体（丑但能用）。"""
    if size in _FONT_CACHE:
        return _FONT_CACHE[size]
    candidates = [
        "/System/Library/Fonts/Supplemental/Arial.ttf",
        "/System/Library/Fonts/Helvetica.ttc",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/dejavu/DejaVuSans.ttf",
    ]
    f = None
    for p in candidates:
        if os.path.isfile(p):
            try:
                f = ImageFont.truetype(p, size)
                break
            except Exception:
                continue
    if f is None:
        f = ImageFont.load_default()
    _FONT_CACHE[size] = f
    return f


def _new_code() -> str:
    return "".join(secrets.choice(ALPHABET) for _ in range(LENGTH))


def render(code: str, width: int = 132, height: int = 48) -> bytes:
    """把验证码画成 PNG。

    干扰手段都用最朴素的：随机颜色 + 轻微旋转 + 噪点 + 干扰线。
    目的不是"绝对破解不了"（那做不到，也不该拿用户体验换），
    而是让批量脚本的成本高于收益。
    """
    img = Image.new("RGB", (width, height), (255, 255, 255))
    d = ImageDraw.Draw(img)

    # 背景噪点
    for _ in range(320):
        x, y = random.randrange(width), random.randrange(height)
        d.point((x, y), fill=(random.randrange(200, 245),
                              random.randrange(200, 245),
                              random.randrange(200, 245)))

    font = _font(30)
    total = len(code)
    slot = width / total
    for i, ch in enumerate(code):
        # 每个字符单独画到小图再旋转，最后贴回大图
        cell = Image.new("RGBA", (34, 40), (0, 0, 0, 0))
        cd = ImageDraw.Draw(cell)
        cd.text((4, 2), ch, font=font,
                fill=(random.randrange(20, 90),
                      random.randrange(30, 110),
                      random.randrange(40, 130)))
        cell = cell.rotate(random.uniform(-18, 18), expand=True,
                           fillcolor=(0, 0, 0, 0))
        img.paste(cell, (int(i * slot + random.uniform(-2, 4)),
                         int((height - cell.height) / 2 + random.uniform(-4, 4))),
                  cell)

    # 干扰线：压在字符上面，让简单的 OCR 分割失效
    for _ in range(3):
        y0 = random.randrange(6, height - 6)
        d.line((random.randrange(0, 20), y0,
                width - random.randrange(0, 20),
                y0 + random.uniform(-8, 8)),
               fill=(random.randrange(120, 200),
                     random.randrange(120, 200),
                     random.randrange(120, 200)), width=1)

    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def new_challenge(conn) -> tuple:
    """生成一道题并存库。返回 (id, png_bytes)。"""
    cid = secrets.token_hex(12)
    code = _new_code()
    now = int(time.time())
    conn.execute(
        "INSERT INTO captchas(id, code, expire_at, used, tries, created_at)"
        " VALUES(?,?,?,0,0,?)", (cid, code, now + TTL, now))
    return cid, render(code)


def verify(conn, cid: str, code: str) -> None:
    """校验验证码。不通过就抛 400，调用方不用自己写分支。

    注意：输错**不立即作废**（人也会看错），但累计错 5 次就作废，
    防止拿一个 id 慢慢穷举。
    """
    if not cid or not code:
        raise HTTPException(400, "请先填写验证码")
    row = conn.execute(
        "SELECT code, expire_at, used, tries FROM captchas WHERE id=?",
        (cid.strip(),)).fetchone()
    if not row:
        raise HTTPException(400, "验证码已失效，请点击「换一张」")
    if row["used"]:
        raise HTTPException(400, "验证码已使用过，请重新获取")
    if row["expire_at"] < time.time():
        raise HTTPException(400, "验证码已过期，请点击「换一张」")
    if row["tries"] >= MAX_TRIES:
        raise HTTPException(400, "错误次数过多，请点击「换一张」")
    if row["code"].upper() != code.strip().upper():
        conn.execute("UPDATE captchas SET tries=tries+1 WHERE id=?", (cid,))
        raise HTTPException(400, "验证码不正确")
    conn.execute("UPDATE captchas SET used=1 WHERE id=?", (cid,))


def purge() -> int:
    """清掉过期和已使用的验证码。运维任务每轮调一次。"""
    import db
    cut = int(time.time()) - TTL
    with db.get_conn() as conn:
        cur = conn.execute("DELETE FROM captchas WHERE expire_at < ? OR used=1", (cut,))
        return cur.rowcount or 0


def enabled() -> bool:
    """是否开启。开发环境也能开（方便测），RVCAMP_CAPTCHA=0 可关。"""
    return config.env_bool("RVCAMP_CAPTCHA", True)
