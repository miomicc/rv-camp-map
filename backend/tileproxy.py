"""自建瓦片代理：把底图请求收敛到自己的域名下，并落盘缓存。

这一层解决四个问题：

  1. 统一出口 —— 源站只看到我们自己服务器的 IP，而不是几十个用户各自的高频
     请求；哪天要换源站，前端一行都不用改，改环境变量就行。
  2. 落盘缓存 —— 每块瓦片只回源一次，之后永久从本地磁盘读。跑得越久本地瓦片
     库越完整，对外部源的依赖越低；最终可以整体换成离线 mbtiles（见
     deploy/selfhost-tiles/），那时这一层连网都不用上了。
  3. 零 Key —— 默认上游 OpenFreeMap：免费、无配额、不用注册任何 Key、明确允许
     商用（样式 MIT，数据 ODbL）。全程不花一分钱。
  4. 可控 —— 防盗链、并发上限、超时重试、404 负缓存都在自己手里，不会半夜被
     源站限流打穿。

路由形态：  /tiles/{upstream}/{path}
  例：/tiles/ofm/styles/liberty          -> https://tiles.openfreemap.org/styles/liberty
      /tiles/ofm/planet/5/26/12.pbf      -> https://tiles.openfreemap.org/planet/5/26/12.pbf

样式 JSON 里的绝对 URL 会被改写成同源的 /tiles/ofm/...，否则 MapLibre 还是会
直连源站，代理就白做了。

同步阻塞 IO 全部放在线程池里执行（路由用 def 而不是 async def），不会卡住
事件循环。生产如果量很大，前面再套一层 nginx proxy_cache 即可，两者不冲突。
"""

import hashlib
import json
import os
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from fastapi import HTTPException, Request
from fastapi.responses import Response

import config
from logsetup import log

# ------------------------------------------------------------------ 上游

# 默认上游。全部免费、无 Key、无配额申请：
#   ofm —— OpenFreeMap 公开实例（OSM 派生矢量瓦片，允许商用）
#   osm —— OSM 官方栅格，仅作矢量组件挂掉时的救急底图，默认关闭回源开关
DEFAULT_UPSTREAMS = {
    "ofm": {
        "origin": "https://tiles.openfreemap.org",
        "enabled": True,
        "note": "OpenFreeMap 公开实例：免费、无 Key、允许商用",
    },
    "osm": {
        "origin": "https://tile.openstreetmap.org",
        "enabled": True,
        "note": "OSM 官方栅格：仅救急，政策不建议商用站点依赖",
    },
}


def upstreams() -> dict:
    """读配置里的上游。允许用环境变量整体替换成自建服务：

        RVCAMP_TILE_UPSTREAM_OFM=http://127.0.0.1:7800   # 自建 martin / tileserver-gl
        RVCAMP_TILE_UPSTREAM_OSM=http://127.0.0.1:7801

    换成自建服务后，这个模块就退化成"本地瓦片服务的缓存与防盗链层"，
    对外完全不再依赖任何第三方。
    """
    out = {}
    for name, d in DEFAULT_UPSTREAMS.items():
        origin = config.env_str(f"RVCAMP_TILE_UPSTREAM_{name.upper()}", d["origin"]).rstrip("/")
        off = config.env_bool(f"RVCAMP_TILE_UPSTREAM_{name.upper()}_OFF", False)
        out[name] = {"origin": origin, "enabled": d["enabled"] and not off,
                     "note": d["note"]}
    return out


# ------------------------------------------------------------------ 缓存目录

CACHE_DIR = config.DATA_DIR / "tiles"
CACHE_DIR.mkdir(parents=True, exist_ok=True)

# 回源并发上限。瓦片一个视野就是几十块，不放闸的话瞬间就是几百个并发连接，
# 源站不封你封谁。
MAX_INFLIGHT = max(2, config.TILE_INFLIGHT)
_inflight = threading.Semaphore(MAX_INFLIGHT)

# 超时与重试
TIMEOUT = config.env_int("RVCAMP_TILE_TIMEOUT", 10)
RETRIES = config.env_int("RVCAMP_TILE_RETRIES", 2)

# 404 负缓存（秒）。地形/海洋这类请求永远没有瓦片，不记住就会反复回源。
NEG_TTL = config.env_int("RVCAMP_TILE_NEG_TTL", 600)

# 源站会挡掉 python-urllib 这类默认 UA（实测 OpenFreeMap 直接 403），给一个正常标识
UA = config.env_str(
    "RVCAMP_TILE_UA",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36 rv-camp-map/1.0")

# 缓存有效期：瓦片内容基本不变，缓存越久越好，只按"最后一次访问"淘汰
CACHE_MAX_AGE = config.TILE_CACHE_AGE

# ------------------------------------------------------------------ 单飞与负缓存

_guard = threading.Lock()
_locks: dict = {}
_neg: dict = {}
_stats = {"hit": 0, "miss": 0, "neg": 0, "fail": 0, "bytes_up": 0}
_stats_lock = threading.Lock()


def _bump(k: str, n: int = 1, size: int = 0):
    with _stats_lock:
        _stats[k] = _stats.get(k, 0) + n
        if size:
            _stats["bytes_up"] += size


def _lock_for(key: str) -> threading.Lock:
    """同一块瓦片同时来了 N 个请求，只让第一个去回源，其余等它写完缓存。"""
    with _guard:
        lk = _locks.get(key)
        if lk is None:
            lk = threading.Lock()
            _locks[key] = lk
        return lk


# ------------------------------------------------------------------ 缓存读写

_ALLOWED_PATH = set(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~/ ")


def _safe_rest(rest: str) -> str:
    """只允许瓦片路径该有的字符。挡掉 ../ 之类的目录穿越和奇怪的查询串。

    字体路径里带空格（/fonts/Noto Sans Regular/0-255.pbf，浏览器会编码成 %20），
    所以先解码再校验，回源时再按标准编码回去——否则中文地名和带空格的字体
    会被自己的安全校验误杀掉。
    """
    if not rest or "\\" in rest:
        raise HTTPException(400, "非法的瓦片路径")
    rest = urllib.parse.unquote(rest)
    if ".." in rest:
        raise HTTPException(400, "非法的瓦片路径")
    for ch in rest:
        if ch not in _ALLOWED_PATH:
            raise HTTPException(400, "非法的瓦片路径")
    return rest.strip("/")


def _cache_files(up: str, rest: str):
    """缓存落盘位置。用路径哈希做文件名，避免长路径和大小写问题。"""
    h = hashlib.sha256(f"{up}/{rest}".encode()).hexdigest()
    d = CACHE_DIR / up / h[:2]
    return d / (h + ".bin"), d / (h + ".hdr")


def _read_cache(up: str, rest: str):
    body_f, hdr_f = _cache_files(up, rest)
    if not body_f.is_file():
        return None
    try:
        ctype = "application/octet-stream"
        if hdr_f.is_file():
            ctype = json.loads(hdr_f.read_text("utf-8")).get("ctype", ctype)
        data = body_f.read_bytes()
    except Exception:
        return None
    # 更新 atime，清理任务据此判断"多久没人看这块瓦片了"
    try:
        st = body_f.stat()
        os.utime(body_f, (time.time(), st.st_mtime))
    except Exception:
        pass
    return data, ctype


def _write_cache(up: str, rest: str, ctype: str, data: bytes):
    body_f, hdr_f = _cache_files(up, rest)
    try:
        body_f.parent.mkdir(parents=True, exist_ok=True)
        tmp = str(body_f) + ".tmp"
        with open(tmp, "wb") as f:
            f.write(data)
        os.replace(tmp, body_f)          # 原子替换，避免读到写了一半的文件
        hdr_f.write_text(json.dumps({"ctype": ctype, "ts": int(time.time())}),
                         encoding="utf-8")
    except Exception as e:
        log.warning("瓦片缓存写入失败 %s/%s: %s", up, rest, e)


# ------------------------------------------------------------------ 回源

def _fetch(origin: str, rest: str):
    """回源取一块瓦片。返回 (status, body, ctype)。"""
    # rest 可能是"解码后"的路径（含空格、中文），按标准百分号编码拼回 URL
    url = origin + "/" + urllib.parse.quote(rest, safe="/-._~")
    req = urllib.request.Request(url, headers={
        "User-Agent": UA,
        # 不要二次压缩：瓦片本身已是压缩数据，gzip 只会让改写 JSON 更麻烦
        "Accept-Encoding": "identity",
        "Accept": "*/*",
    })
    last = None
    for i in range(RETRIES + 1):
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
                body = r.read()
                ctype = r.headers.get("Content-Type", "application/octet-stream")
                return r.status, body, ctype.split(";")[0].strip()
        except urllib.error.HTTPError as e:
            # 404 是正常的（海洋、无数据区域），不要当成错误打成 error 级
            return e.code, b"", e.headers.get("Content-Type", "text/plain")
        except Exception as e:
            last = e
            if i < RETRIES:
                time.sleep(0.3 * (i + 1))
    raise RuntimeError(f"回源失败 {url}: {last}")


def _rewrite(body: bytes, ctype: str, origin: str, prefix: str) -> bytes:
    """把样式 JSON 里的绝对 URL 改成我们的代理路径。

    不做这一步的话，MapLibre 拿到 style 之后会照着里面的 https://tiles...
    自己去源站取 tiles / fonts / sprite，代理形同虚设。

    注意这里写的是**相对**路径（/tiles/ofm/...），落盘缓存时也存相对版本——
    这样同一份缓存换域名访问（localhost / 正式域名 / 内网 IP）都能用。
    真正发给浏览器时会由 _abs_urls 补齐成绝对地址，原因见下。
    """
    if "json" not in ctype:
        return body
    try:
        txt = body.decode("utf-8")
    except UnicodeDecodeError:
        return body
    txt = txt.replace(origin + "/", prefix + "/").replace(origin, prefix)
    return txt.encode("utf-8")


# 代理地址的版本参数。改一次这个值，全世界浏览器里的旧样式/旧 tilejson
# 立刻全部失效，不用等它们缓存过期。（瓦片和字体不带这个参数，让它们继续
# 享受浏览器缓存——那些内容不会变。）
URL_TOKEN = config.env_str("RVCAMP_TILE_URL_TOKEN", "20261008a")

# 瓦片与字形模板：内容不变，保留浏览器缓存，不加版本参数
_SKIP_TOKEN_SUFFIX = (".pbf", ".png", ".jpg", ".webp")


def _abs_urls(body: bytes, ctype: str, base: str) -> bytes:
    """把 JSON 里的 /tiles/... 补成绝对 URL。

    ⚠️ 这一步不能省，也不只是"好看"的问题：MapLibre 在 **Web Worker** 里
    fetch 矢量瓦片，而 worker 没有 document base URL，相对路径 '/tiles/...'
    会直接抛 "Failed to parse URL"，表现为整张矢量底图不渲染——
    只剩低缩放的栅格底色，放大后彻底空白。栅格瓦片由主线程 <img> 加载，
    相对路径能用，所以这个 bug 只会让"路和地名"消失，特别容易误判成
    "源站挂了"或"数据里没路"。
    """
    if "json" not in (ctype or "") or not base:
        return body
    try:
        obj = json.loads(body.decode("utf-8"))
    except Exception:
        return body

    def fix(s):
        if not isinstance(s, str) or not s.startswith("/tiles/"):
            return s
        url = base + s
        if not url.endswith(_SKIP_TOKEN_SUFFIX):
            url += ("&" if "?" in url else "?") + "tv=" + URL_TOKEN
        return url

    obj = _walk_obj(obj, fix)
    _boost_lowzoom_roads(obj)
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _walk_obj(v, fix):
    if isinstance(v, str):
        return fix(v)
    if isinstance(v, list):
        return [_walk_obj(x, fix) for x in v]
    if isinstance(v, dict):
        return {k: _walk_obj(x, fix) for k, x in v.items()}
    return v


def _boost_lowzoom_roads(obj) -> None:
    """低缩放级别把主干道画粗画亮。

    OpenMapTiles 的道路数据是按级别分层给的：z4 以下几乎没有路，z5-z8
    也只有寥寥几条高速/国道，再按默认线宽画出来缩略图上一片空白，
    用户会以为"地图没加载出来"。这里追加一个只在 z3-z9 生效的高亮图层，
    缩到全国视图时也能看到路网骨架；放大后（z10+）交回原生样式，不添乱。

    只在 style（带 layers 的 JSON）上生效，tilejson 会自动跳过。
    任何异常都吞掉：宁可不增强，也不能把样式改坏导致白板。
    """
    try:
        layers = obj.get("layers")
        if not isinstance(layers, list) or not layers:
            return
        src = next((k for k, v in (obj.get("sources") or {}).items()
                    if isinstance(v, dict) and v.get("type") == "vector"), None)
        if not src:
            return
        if any(isinstance(l, dict) and l.get("id") == "rv_road_boost" for l in layers):
            return
        layer = {
            "id": "rv_road_boost",
            "type": "line",
            "source": src,
            "source-layer": "transportation",
            "minzoom": 3,
            "maxzoom": 10,
            "filter": ["match", ["get", "class"],
                       ["motorway", "trunk", "primary"], True, False],
            "layout": {"line-cap": "round", "line-join": "round"},
            "paint": {
                "line-color": "#f08a4b",
                "line-opacity": 0.85,
                "line-width": {
                    "base": 1.5,
                    "stops": [[4, 0.9], [6, 1.6], [8, 2.6], [10, 4.0]],
                },
            },
        }
        # 插到第一个注记图层之前，免得把地名压住
        idx = next((i for i, l in enumerate(layers)
                    if isinstance(l, dict) and l.get("type") == "symbol"), len(layers))
        layers.insert(idx, layer)
    except Exception:
        pass


def _host_base(request: Request) -> str:
    """当前访问的绝对根地址。nginx 后面要认 X-Forwarded-Proto，否则会退化成 http。"""
    scheme = request.headers.get("x-forwarded-proto") or request.url.scheme
    host = request.headers.get("host") or request.url.netloc
    return f"{scheme}://{host}"


# ------------------------------------------------------------------ 防盗链

def _hotlink_ok(request: Request) -> bool:
    """生产环境只允许本站页面引用瓦片。

    瓦片是最容易被"蹭"的资源：别人把你的瓦片地址贴到他自己的站上，
    流量和源站配额都算在你头上。开发环境关掉，方便 curl 调试。
    """
    if config.DEV or config.env_bool("RVCAMP_TILE_HOTLINK", False):
        return True
    host = (request.headers.get("host") or "").split(":")[0]
    for h in (request.headers.get("referer"), request.headers.get("origin")):
        if not h:
            continue
        try:
            from urllib.parse import urlparse
            p = urlparse(h)
        except Exception:
            continue
        if p.hostname and p.hostname.split(":")[0] == host:
            return True
    # 直接敲地址/无 Referer 的请求：只在明确允许时放行
    return not (request.headers.get("referer") or request.headers.get("origin"))


# ------------------------------------------------------------------ 路由

def handle(request: Request, up: str, rest: str) -> Response:
    ups = upstreams()
    if up not in ups or not ups[up]["enabled"]:
        raise HTTPException(404, "未启用的瓦片上游")

    if not _hotlink_ok(request):
        log.info("瓦片盗链被拒 up=%s ref=%s", up, request.headers.get("referer"))
        raise HTTPException(403, "瓦片仅限本站使用")

    rest = _safe_rest(rest)
    origin = ups[up]["origin"]
    prefix = (config.TILE_PROXY or "/tiles") + "/" + up
    base = _host_base(request)
    key = f"{up}/{rest}"

    # 1) 命中磁盘缓存
    hit = _read_cache(up, rest)
    if hit:
        data, ctype = hit
        _bump("hit")
        return Response(content=_abs_urls(data, ctype, base), media_type=ctype,
                        headers=_headers("HIT", ctype))

    # 2) 负缓存：这块刚确认过没有，别再回源
    exp = _neg.get(key, 0)
    if exp > time.time():
        _bump("neg")
        return Response(content=b"", status_code=404, headers=_headers("NEG"))

    # 3) 单飞回源：同一块只发一个请求，其余等锁
    with _lock_for(key):
        hit = _read_cache(up, rest)          # 双重检查：等锁期间可能已被写入
        if hit:
            data, ctype = hit
            _bump("hit")
            return Response(content=_abs_urls(data, ctype, base), media_type=ctype,
                            headers=_headers("HIT", ctype))

        with _inflight:
            try:
                status, body, ctype = _fetch(origin, rest)
            except Exception as e:
                _bump("fail")
                log.warning("瓦片回源失败 %s: %s", key, e)
                return Response(content=b"", status_code=502, headers=_headers("FAIL"))

        _bump("miss", size=len(body))
        if status >= 400:
            _neg[key] = time.time() + NEG_TTL
            return Response(content=b"", status_code=404, headers=_headers("MISS", ctype))

        # 空响应也当成"这块没有数据"，别把空白瓦片存进缓存
        if not body:
            _neg[key] = time.time() + NEG_TTL
            return Response(content=b"", status_code=404, headers=_headers("MISS", ctype))

        body = _rewrite(body, ctype, origin, prefix)
        _write_cache(up, rest, ctype, body)

    return Response(content=_abs_urls(body, ctype, base), media_type=ctype,
                    headers=_headers("MISS", ctype))


def _headers(state: str, ctype: str = "") -> dict:
    # 瓦片内容基本不变，可以长缓存；但样式 JSON / tilejson 不一样：
    #   1. 里面写着"数据版本目录"（形如 /planet/20261004_113936_pt/...），
    #      上游一换版路径就变，缓存太久会把用户钉死在旧数据上
    #   2. 更要命的是：一旦我们这边修过样式改写逻辑（比如把 URL 改成绝对地址），
    #      用户浏览器里缓存的旧样式会用旧规则取瓦片，服务端修好了他那边也是坏的，
    #      只能干等缓存过期。所以 JSON 只缓存 5 分钟。
    # 真要立刻全网生效，改前端的 STYLE_VER 常量（会拼出新的 URL，直接绕过缓存）。
    age = 60 if "json" in (ctype or "") else CACHE_MAX_AGE
    return {
        "Cache-Control": f"public, max-age={age}",
        "X-Tile-Cache": state,
        "X-Content-Type-Options": "nosniff",
    }


# ------------------------------------------------------------------ 统计与清理

def stats() -> dict:
    """缓存占用与命中情况，后台运维页会展示。"""
    files, total = 0, 0
    for root, _dirs, names in os.walk(str(CACHE_DIR)):
        for n in names:
            if not n.endswith(".bin"):
                continue
            files += 1
            try:
                total += os.path.getsize(os.path.join(root, n))
            except OSError:
                pass
    with _stats_lock:
        st = dict(_stats)
    hit, miss = st.get("hit", 0), st.get("miss", 0)
    return {
        "files": files,
        "bytes": total,
        "mb": round(total / 1048576, 1),
        "hit": hit, "miss": miss, "neg": st.get("neg", 0), "fail": st.get("fail", 0),
        "hit_rate": round(hit / (hit + miss) * 100, 1) if (hit + miss) else 0.0,
        "upstreams": {k: {"origin": v["origin"], "enabled": v["enabled"],
                          "note": v["note"]} for k, v in upstreams().items()},
    }


def purge(max_days: int = None, max_mb: int = None) -> dict:
    """清理瓦片缓存：先删长期没人看的，再按体积上限删最旧的。

    瓦片缓存是"有便宜就占"的东西，不设上限迟早吃光磁盘。
    """
    max_days = max_days if max_days is not None else config.TILE_CACHE_DAYS
    max_mb = max_mb if max_mb is not None else config.TILE_CACHE_MB
    cut = time.time() - max_days * 86400

    entries = []
    for root, _dirs, names in os.walk(str(CACHE_DIR)):
        for n in names:
            if not n.endswith(".bin"):
                continue
            p = os.path.join(root, n)
            try:
                st = os.stat(p)
            except OSError:
                continue
            entries.append((max(st.st_atime, st.st_mtime), st.st_size, p))

    removed, freed = 0, 0
    for last, size, p in entries:
        if last >= cut:
            continue
        try:
            os.remove(p)
            hdr = p[:-4] + ".hdr"
            if os.path.isfile(hdr):
                os.remove(hdr)
            removed += 1
            freed += size
        except OSError:
            pass

    total = sum(e[1] for e in entries) - freed
    limit = max_mb * 1048576
    if total > limit:
        for last, size, p in sorted(e for e in entries if e[0] >= cut):
            if total <= limit:
                break
            try:
                os.remove(p)
                hdr = p[:-4] + ".hdr"
                if os.path.isfile(hdr):
                    os.remove(hdr)
                removed += 1
                freed += size
                total -= size
            except OSError:
                pass

    if removed:
        log.info("瓦片缓存清理：删除 %d 块，释放 %.1fMB", removed, freed / 1048576)
    return {"removed": removed, "freed_mb": round(freed / 1048576, 2), "kept_mb": round(total / 1048576, 2)}
