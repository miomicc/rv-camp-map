"""瓦片缓存预热：把指定区域、指定缩放级别的瓦片提前搬到本地。

为什么要预热：用户第一次打开某块区域时，那几十块瓦片要现去回源，
在国内网络下能明显感觉到"地图一格一格地冒出来"。热门城市提前跑一遍，
用户打开就是本地命中，等于自建了常用区域的瓦片库。

用法：
    # 直接调后端函数写缓存（不需要服务在跑）
    python warm_cache.py --bbox 116.0,39.6,116.8,40.2 --minz 10 --maxz 14

    # 预热一台远程机器：走 HTTP，让那台机器自己的缓存目录落盘
    python warm_cache.py --bbox 116,39.6,116.8,40.2 --minz 10 --maxz 14 \
                         --host http://127.0.0.1:8000

    # 全国概览（块数很少，几秒完事）
    python warm_cache.py --bbox 73,18,135,54 --minz 3 --maxz 9
"""

import argparse
import json
import math
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "..", "backend"))

import config          # noqa: E402
import tileproxy       # noqa: E402


def deg2tile(lon, lat, z):
    """经纬度 -> 瓦片号（Web Mercator / XYZ）。"""
    n = 2 ** z
    x = int((lon + 180.0) / 360.0 * n)
    lat_r = math.radians(lat)
    y = int((1.0 - math.log(math.tan(lat_r) + 1 / math.cos(lat_r)) / math.pi) / 2.0 * n)
    return x, y


def tile_range(bbox, z):
    minlon, minlat, maxlon, maxlat = bbox
    x0, y1 = deg2tile(minlon, minlat, z)
    x1, y0 = deg2tile(maxlon, maxlat, z)
    return range(min(x0, x1), max(x0, x1) + 1), range(min(y0, y1), max(y0, y1) + 1)


def total_tiles(bbox, minz, maxz):
    n = 0
    for z in range(minz, maxz + 1):
        xs, ys = tile_range(bbox, z)
        n += len(xs) * len(ys)
    return n


def tile_url_template(up, origin, prefix):
    """从 tilejson 取真实的瓦片路径模板。

    别自己拼 —— OpenFreeMap 的真实路径里带数据版本号
    （/planet/20261004_113936_pt/{z}/{x}/{y}.pbf），写死就会全部取到空瓦片。
    """
    status, body, ctype = tileproxy._fetch(origin, "planet")
    if status < 400 and body:
        try:
            tj = json.loads(tileproxy._rewrite(body, ctype, origin, prefix).decode())
            tpl = tj["tiles"][0]
            if tpl.startswith(prefix):
                tpl = tpl[len(prefix):]
            return tpl.lstrip("/")
        except Exception:
            pass
    return "planet/{z}/{x}/{y}.pbf"


def fetch_one(up, origin, prefix, rest, host):
    """取一块瓦片并落缓存。失败不影响其它块。"""
    try:
        if host:
            import urllib.request
            url = f"{host.rstrip('/')}/tiles/{up}/{rest}"
            req = urllib.request.Request(url, headers={"User-Agent": tileproxy.UA})
            with urllib.request.urlopen(req, timeout=tileproxy.TIMEOUT) as r:
                return r.status == 200 and len(r.read()) > 0
        status, body, ctype = tileproxy._fetch(origin, rest)
        if status >= 400 or not body:
            return False
        tileproxy._write_cache(up, rest, ctype,
                               tileproxy._rewrite(body, ctype, origin, prefix))
        return True
    except Exception:
        return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bbox", required=True, help="minlon,minlat,maxlon,maxlat")
    ap.add_argument("--minz", type=int, default=3)
    ap.add_argument("--maxz", type=int, default=14)
    ap.add_argument("--up", default="ofm", help="上游名，默认 ofm")
    ap.add_argument("--host", default="", help="留空=本地直接写缓存；否则走该地址的 /tiles")
    ap.add_argument("--workers", type=int, default=8)
    args = ap.parse_args()

    bbox = [float(x) for x in args.bbox.split(",")]
    if len(bbox) != 4:
        ap.error("--bbox 需要四个数字")

    ups = tileproxy.upstreams()
    if args.up not in ups:
        print(f"未知上游 {args.up}，可选：{', '.join(ups)}")
        return 1
    origin = ups[args.up]["origin"]
    prefix = (config.TILE_PROXY or "/tiles") + "/" + args.up

    total = total_tiles(bbox, args.minz, args.maxz)
    print(f"待预热 {total} 块：zoom {args.minz}-{args.maxz}，上游 {args.up}（{origin}）")
    if total > 200000:
        print("块数太多（>20 万），先缩小范围或降低 maxz 再跑")
        return 1

    tpl = tile_url_template(args.up, origin, prefix)
    print(f"瓦片路径模板：{tpl}")

    jobs = []
    for z in range(args.minz, args.maxz + 1):
        xs, ys = tile_range(bbox, z)
        for x in xs:
            for y in ys:
                jobs.append(tpl.replace("{z}", str(z))
                               .replace("{x}", str(x))
                               .replace("{y}", str(y)))

    t0 = time.time()
    ok = 0
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = {ex.submit(fetch_one, args.up, origin, prefix, j, args.host): j
                for j in jobs}
        for i, f in enumerate(as_completed(futs), 1):
            ok += 1 if f.result() else 0
            if i % 200 == 0 or i == len(jobs):
                print(f"  {i}/{len(jobs)}，成功 {ok}，耗时 {time.time()-t0:.0f}s")

    print(f"完成：{ok}/{len(jobs)} 块已缓存，用时 {time.time()-t0:.0f}s")
    st = tileproxy.stats()
    print(f"当前缓存：{st['files']} 块 / {st['mb']}MB")
    return 0


if __name__ == "__main__":
    sys.exit(main())
