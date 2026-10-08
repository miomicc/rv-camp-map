"""图片上传接口测试，重点验证安全防护。"""
import io
import json
import struct
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


def post_files(path, files, token):
    """multipart/form-data 手工构造，避免额外依赖。"""
    boundary = "----rvboundary1234567890"
    body = b""
    for name, filename, content in files:
        body += f"--{boundary}\r\n".encode()
        body += f'Content-Disposition: form-data; name="{name}"; filename="{filename}"\r\n'.encode()
        body += b"Content-Type: application/octet-stream\r\n\r\n"
        body += content + b"\r\n"
    body += f"--{boundary}--\r\n".encode()

    r = urllib.request.Request(B + path, data=body, method="POST")
    r.add_header("Content-Type", f"multipart/form-data; boundary={boundary}")
    r.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(r) as x:
            return x.status, json.loads(x.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def make_png(w=1, h=1):
    """构造一个最小合法 PNG。"""
    def chunk(t, d):
        c = t + d
        return struct.pack(">I", len(d)) + c + struct.pack(">I", __import__("zlib").crc32(c))
    import zlib
    ihdr = struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)
    raw = b"".join(b"\x00" + b"\xff\x00\x00" * w for _ in range(h))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr)
            + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b""))


def make_jpeg():
    """最小 JPEG（1x1 黑点）。"""
    return bytes.fromhex(
        "ffd8ffe000104a46494600010100000100010000ffdb004300ffffffffffffffffff"
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        "ffffffffffffffffffffffc00011080001000103012200021101031101ffc4001f"
        "0000010501010101010100000000000000000102030405060708090a0bffc400b5"
        "100002010303020403050504040000017d01020300041105122131410613516107"
        "227114328191a1082342b1c11552d1f02433627282090a161718191a25262728292a"
        "3435363738393a434445464748494a535455565758595a636465666768696a737475"
        "767778797a838485868788898a92939495969798999aa2a3a4a5a6a7a8a9aab2b3"
        "b4b5b6b7b8b9bac2c3c4c5c6c7c8c9cad2d3d4d5d6d7d8d9dae1e2e3e4e5e6e7"
        "e8e9eaf1f2f3f4f5f6f7f8f9faffda000c03010002110311003f00fefa28a2803fff"
        "d9")


line = lambda t: print("\n" + "=" * 62 + "\n" + t + "\n" + "=" * 62)

import devkeys
_K = devkeys.load()
st, d = call("POST", "/api/auth/key/login", {"secret_key": _K["user_key"]})
TK = d["token"]
print(f"登录成功，用户 {d['user']['user_no']}")

# ---------------------------------------------------------------- 1
line("1. 正常上传：单张 + 多张")
st, d = post_files("/api/upload/images", [("files", "a.png", make_png())], TK)
print(f"  单张 PNG -> HTTP {st} | {d.get('urls')}")

st, d = post_files("/api/upload/images", [
    ("files", "b.png", make_png()),
    ("files", "c.jpg", make_jpeg()),
], TK)
print(f"  两张混合 -> HTTP {st} | 返回 {d.get('count')} 个")
for u in d.get("urls", []):
    print(f"    {u}")

# ---------------------------------------------------------------- 2
line("2. 安全防护：伪装成图片的恶意文件")
evil_cases = [
    ("shell.php 改名成 .jpg", "shell.jpg", b"<?php system($_GET['c']); ?>"),
    ("HTML 钓鱼页", "phish.png", b"<html><form action='//evil.com'>...</form></html>"),
    ("空文件", "empty.png", b""),
    ("随机二进制", "rand.jpg", bytes(range(256)) * 2),
]
for name, fn, content in evil_cases:
    st, d = post_files("/api/upload/images", [("files", fn, content)], TK)
    msg = d.get("detail") or d.get("errors")
    print(f"  {name:<22s} -> {'已拦截: ' + str(msg)[:52] if st != 200 or not d.get('urls') else '⚠️ 放行了'}")

# ---------------------------------------------------------------- 3
line("3. 体积限制（5MB）")
big = b"\x89PNG\r\n\x1a\n" + b"\x00" * (6 * 1024 * 1024)
st, d = post_files("/api/upload/images", [("files", "big.png", big)], TK)
print(f"  6MB 文件 -> {d.get('detail') or d.get('errors')}")

# ---------------------------------------------------------------- 4
line("4. 数量限制")
many = [("files", f"n{i}.png", make_png()) for i in range(12)]
st, d = post_files("/api/upload/images", many, TK)
print(f"  一次传 12 张 -> {d.get('detail')}")

# ---------------------------------------------------------------- 5
line("5. 未登录上传被拦截")
st, d = post_files("/api/upload/images", [("files", "x.png", make_png())], "invalid-token")
print(f"  HTTP {st} -> {d.get('detail')}")

# ---------------------------------------------------------------- 6
line("6. 路径穿越：文件名带 ../..")
st, d = post_files("/api/upload/images",
                   [("files", "../../../../tmp/pwned.png", make_png())], TK)
urls = d.get("urls", [])
print(f"  提交名 ../../../../tmp/pwned.png -> 存储为 {urls}")
print(f"  原始文件名已被丢弃: {'✓' if urls and '..' not in urls[0] else '✗'}")

# ---------------------------------------------------------------- 7
line("7. 完整流程：上传图片 -> 创建带图营地")
st, d = post_files("/api/upload/images", [
    ("files", "camp1.png", make_png(4, 4)),
    ("files", "camp2.png", make_png(5, 5)),
], TK)
imgs = d["urls"]
st, d = call("POST", "/api/spots", {
    "name": "测试·带图营地", "lng": 120.9, "lat": 31.2,
    "province": "江苏省", "city": "苏州市", "spot_type": "房车营地",
    "address": "苏州市吴中区测试路 9 号", "phone": "0512-6666****",
    "price_range": "200-320元/晚", "facilities": ["水电桩", "排污口", "淋浴"],
    "detail": "带图片的测试营地", "images": imgs,
}, token=TK)
print(f"  创建营地 -> id={d.get('id')} {d.get('message', '')[:30]}")

# ---------------------------------------------------------------- 8
line("8. 静态访问上传的图片")
for u in imgs[:2]:
    try:
        with urllib.request.urlopen(B + u) as x:
            data = x.read()
            kind = "PNG" if data[:4] == b"\x89PNG" else ("JPEG" if data[:2] == b"\xff\xd8" else "?")
            print(f"  GET {u} -> HTTP {x.status}, {len(data)} 字节, 类型 {kind}")
    except Exception as e:
        print(f"  GET {u} -> 失败 {e}")
