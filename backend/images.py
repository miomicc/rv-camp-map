"""图片处理：重编码 + 剥离 EXIF + 生成缩略图。

为什么必须做，而不是直接把用户上传的字节写盘：

1. **EXIF 带 GPS**。手机拍的照片默认把拍摄位置写进 EXIF，
   营地照片 = 用户行踪。原样存下来再公开出去，是实打实的隐私事故。
2. **原图直出太慢**。手机照片普遍 3~5MB，一个营地 6 张就是 30MB，
   列表页会直接卡死。缩略图把首屏体积压到原来的 1/30。
3. **重编码顺带杀掉藏在图片里的脚本**。只验文件头只能保证"它是图片"，
   重新解码再编码一次，能保证落盘的文件确实是干净的像素数据。

依赖 Pillow（requirements.txt 已加）。Pillow 不可用时降级为原样保存，
而不是让上传功能整体挂掉——但会打 ERROR 日志提醒。
"""

import io
import os
import secrets
import time

from PIL import Image, ImageOps

import config
from logsetup import log

try:                                  # Pillow >= 9.1 才有
    Image.MAX_IMAGE_PIXELS = 64_000_000
except Exception:
    pass


def _open(raw: bytes) -> Image.Image:
    im = Image.open(io.BytesIO(raw))
    im.load()                          # 强制解码，防止延迟加载把错误推迟到写盘时
    # 按 EXIF 方向摆正（手机竖拍的照片在浏览器里躺倒就是这个原因）
    im = ImageOps.exif_transpose(im)
    return im


def _flatten(im: Image.Image) -> Image.Image:
    """统一成 RGB。PNG 的透明通道转 JPEG 会报错，先合成到白底。"""
    if im.mode in ("RGBA", "LA", "P"):
        bg = Image.new("RGB", im.size, (255, 255, 255))
        im = im.convert("RGBA")
        bg.paste(im, mask=im.split()[-1])
        return bg
    if im.mode != "RGB":
        return im.convert("RGB")
    return im


def process(raw: bytes) -> dict:
    """把上传的字节处理成「无 EXIF 的原图 + 缩略图」。

    返回 {url, thumb, width, height}。异常时抛 ValueError，
    由调用方转成 400 给前端。
    """
    im = _open(raw)
    w0, h0 = im.size
    im = _flatten(im)

    # 原图：限制最大边长（不放大，只缩小）
    if max(im.size) > config.IMAGE_MAX_EDGE:
        im.thumbnail((config.IMAGE_MAX_EDGE, config.IMAGE_MAX_EDGE), Image.LANCZOS)

    day = time.strftime("%Y%m")
    base = config.UPLOAD_DIR / day
    (base / "thumb").mkdir(parents=True, exist_ok=True)
    name = secrets.token_hex(12)

    full_path = base / f"{name}.jpg"
    thumb_path = base / "thumb" / f"{name}.jpg"

    # 关键：save 时**不传 exif 参数**，EXIF 全部丢弃（含 GPS）
    im.save(full_path, "JPEG", quality=config.JPEG_QUALITY, optimize=True,
            progressive=True)

    th = im.copy()
    th.thumbnail((config.THUMB_EDGE, config.THUMB_EDGE), Image.LANCZOS)
    th.save(thumb_path, "JPEG", quality=78, optimize=True)

    rel = f"/uploads/{day}/{name}.jpg"
    rel_thumb = f"/uploads/{day}/thumb/{name}.jpg"
    return {
        "url": rel,
        "thumb": rel_thumb,
        "width": im.size[0],
        "height": im.size[1],
        "orig_width": w0,
        "orig_height": h0,
        "bytes": os.path.getsize(full_path),
    }


def safe_join(rel_or_name: str) -> str:
    """把 /uploads/xxx 或裸文件名映射到磁盘绝对路径，并校验不越界。"""
    p = (rel_or_name or "").replace("/uploads/", "").lstrip("/")
    abs_path = os.path.normpath(os.path.join(str(config.UPLOAD_DIR), p))
    root = os.path.realpath(str(config.UPLOAD_DIR))
    if not abs_path.startswith(root + os.sep) and abs_path != root:
        raise ValueError("非法的文件路径")
    return abs_path
