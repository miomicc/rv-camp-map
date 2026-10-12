"""瓦片代理测试：卫星底图能不能正常代理 + 路径参数有没有被绕过/丢失。

分两部分：
  A/B. 打运行中的 8000 服务，验证 /tiles/sat 真的返回 JPEG、会命中磁盘缓存，
       以及路径安全校验（目录穿越、未启用上游、编码后的 # 等）仍然生效。
       ⚠️ 这部分需要外网——回源 Esri；断网时会失败，属预期。
  C.  离线验证"查询串有没有被原样拼进回源请求"。用一个假的 Request + 假的
       _fetch 把上游要拿到的 URL 截下来比对，不碰网络也不依赖第三方源。

为什么要单独测 C：Starlette 的 {rest:path} 只匹配路径，查询串会被收进
request.url.query —— 不显式拼回上游 URL，天地图 img_w 这类把图层/行列号/Key
放在 ? 后面的 KVP 型图源会全部失效，而且症状是"图源坏了"而不是"参数丢了"，
极难排查。这个坑以前踩过，所以给它留一个专门的用例。
"""
import math
import os
import random
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

B = "http://127.0.0.1:8000"

ok = fail = 0


def check(name, cond, extra=""):
    global ok, fail
    if cond:
        ok += 1
        print(f"  \033[32m✓\033[0m {name}")
    else:
        fail += 1
        print(f"  \033[31m✗\033[0m {name}  {extra}")


def line(t):
    print("\n" + "=" * 64 + f"\n{t}\n" + "=" * 64)


def get(url, timeout=40):
    """返回 (status, body, headers 里的 x-tile-cache)。"""
    req = urllib.request.Request(url)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read(), (r.headers.get("X-Tile-Cache") or "")
    except urllib.error.HTTPError as e:
        return e.code, e.read(), (e.headers.get("X-Tile-Cache") or "")


# ══════════════════════════════════════════════════ A. 卫星底图代理

line("A. 卫星底图走自建代理 /tiles/sat")

# 随机挑一块偏远地区的瓦片：保证本轮一定是首次回源，不会被上一轮的缓存干扰
lon = random.uniform(100.0, 110.0)
lat = random.uniform(25.0, 37.0)
_n = 2 ** 14
_x = int((lon + 180) / 360 * _n)
_r = math.radians(lat)
_y = int((1 - math.log(math.tan(_r) + 1 / math.cos(_r)) / math.pi) / 2 * _n)
path = f"/tiles/sat/World_Imagery/MapServer/tile/14/{_y}/{_x}"

s, body, cache = get(B + path)
check("卫星瓦片返回 200", s == 200, f"-> {s}")
check("首次回源标记 MISS", cache == "MISS", f"-> {cache}")
check("内容是 JPEG（FFD8 开头）", body[:2] == b"\xff\xd8", f"-> {body[:4]!r}")
check("瓦片有实际内容", len(body) > 2000, f"-> {len(body)}B")

s2, body2, cache2 = get(B + path)
check("同一块第二次命中磁盘缓存", cache2 == "HIT", f"-> {cache2}")
check("缓存内容与首次一致", body2 == body)

s3, _, _ = get(B + "/tiles/sat/World_Imagery/MapServer/tile/14/0/0")
check("无效瓦片给 404（不是 5xx）", s3 in (200, 404), f"-> {s3}")

line("B. 路径安全：这些请求必须被挡在回源之前")

for name, url, want in [
    ("未启用的上游", "/tiles/bogus/foo.png", 404),
    ("编码后的目录穿越", "/tiles/sat/%2e%2e%2f%2e%2e%2fetc%2fpasswd", 400),
    ("反斜杠", "/tiles/sat/World%5Cfoo", 400),
    ("编码后的 # 片段", "/tiles/sat/foo%23evil", 400),
    ("查询串里塞太多参数", "/tiles/sat/foo?" + "&".join(f"a={i}" for i in range(20)), 400),
]:
    s, _, _ = get(B + url)
    check(f"{name} -> {want}", s == want, f"-> {s}")

line("C. 查询串必须原样拼进回源请求（离线）")

import tileproxy
from starlette.requests import Request

# 把缓存指向临时目录：否则第一次跑完，这几块瓦片就躺在 data/tiles 里了，
# 第二次运行会全部命中缓存、根本到不了回源，断言从"通过"变成"莫名其妙的失败"。
_tmp_cache = tempfile.mkdtemp(prefix="rvtiles-test-")
tileproxy.CACHE_DIR = Path(_tmp_cache)
tileproxy._made_dirs.clear()
tileproxy._neg.clear()

seen = {}
# upstream 'sat' 指向一个假域名，只要有请求真的发往网络，这里就会立刻失败
tileproxy.DEFAULT_UPSTREAMS = tileproxy.DEFAULT_UPSTREAMS | {
    "sat": {"origin": "http://127.0.0.1:1", "enabled": True, "note": "test"}}
os.environ["RVCAMP_TILE_UPSTREAM_SAT"] = "http://127.0.0.1:1"


def fake_fetch(origin, rest):
    seen["origin"], seen["rest"] = origin, rest
    return 200, b"\xff\xd8" + b"0" * 64, "image/jpeg"


tileproxy._fetch = fake_fetch
_real_rnd = tileproxy._rewrite
tileproxy._rewrite = lambda body, ctype, origin, prefix: body   # 缓存写盘用不到


def probe(path: str, query: str):
    """构造一个 Request 喂给 tileproxy.handle，截获它准备回源的那串 path。

    Starlette 会把 /tiles/{up}/ 之后的部分交给路由参数 rest，这里手工拆开，
    模拟的就是这一步。
    """
    seen.clear()
    rest = path[len("/tiles/sat/"):]
    scope = {"type": "http", "method": "GET", "path": path,
             "query_string": query.encode(), "scheme": "http", "server": ("127.0.0.1", 8000),
             "client": ("127.0.0.1", 50000), "root_path": "",
             "headers": [(b"host", b"127.0.0.1:8000")]}
    tileproxy.handle(Request(scope, None), "sat", rest)
    return seen.get("rest")


got = probe("/tiles/sat/img_w/wmts",
            "SERVICE=WMTS&LAYER=img&TILEMATRIX=5&TILEROW=12&TILECOL=26&tk=KEY123")
check("KVP 参数被完整拼回上游路径",
      got == "img_w/wmts?SERVICE=WMTS&LAYER=img&TILEMATRIX=5&TILEROW=12&TILECOL=26&tk=KEY123",
      f"-> {got!r}")
check("Key 这类私有参数不会被丢掉", "tk=KEY123" in (got or ""), f"-> {got!r}")

# 换成随机坐标：上面 Part A 已经把 5/12/26 写进磁盘缓存了，用同一条路径会
# 命中缓存而根本轮不到回源，_fetch 不会被调用，断言反而会误判。
_zz = random.randrange(3, 19)
bare = f"World_Imagery/MapServer/tile/{_zz}/{_y}/{_x}"
got = probe("/tiles/sat/" + bare, "")
check("不带查询串时路径不受影响", got == bare, f"-> {got!r}")

# 曾经踩过的坑：字体路径里有空格（/fonts/Noto Sans Regular/0-255.pbf），
# 安全校验一度把它当成非法字符拒掉，整张矢量底图的地名全没了。
got = probe("/tiles/sat/fonts/Noto Sans Regular/0-255.pbf", "")
check("含空格的路径仍能通过（字体坑回归）",
      got == "fonts/Noto Sans Regular/0-255.pbf", f"-> {got!r}")

try:
    probe("/tiles/sat/foo", "&".join(f"a={i}" for i in range(20)))
    too_many = True
except Exception:
    too_many = False
check("查询串过长被拒（400 而非打出去）", not too_many)

# 收尾：把 monkeypatch 还原，免得影响同一进程里的其他用例
tileproxy._rewrite = _real_rnd
shutil.rmtree(_tmp_cache, ignore_errors=True)

print("\n" + "=" * 64)
print(f"通过 {ok} 项，失败 {fail} 项")
print("=" * 64)
sys.exit(1 if fail else 0)
