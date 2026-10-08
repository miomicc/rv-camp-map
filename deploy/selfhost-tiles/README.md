# 自建瓦片的两种形态（都是零 Key、零授权费）

这一目录解决一个诉求：**底图这件事，既不花钱，也不看别人脸色。**

先看清楚"自建"有两种程度，成本差一个数量级，按需选：

| | 形态 A：自建代理 + 本地缓存 | 形态 B：完全离线瓦片 |
|---|---|---|
| 外部依赖 | 首次访问某块瓦片时回源一次 | 无，断网也能跑 |
| 一次性投入 | 0（已实现，后端自带） | CPU + 磁盘（见下） |
| Key / 费用 | 无 | 无 |
| 源站封禁风险 | 低（只有我们一台机器在请求，且有缓存） | 不存在 |
| 数据时效 | 跟随上游 | 自己决定何时重跑 |

**推荐路径：先 A，跑一段时间，等缓存命中率上来了再决定要不要 B。**
后台 `/api/admin/tile-cache` 能看到命中率——如果稳定在 90% 以上，
说明常看的区域已经全在本地了，B 的边际收益就很小。

---

## 形态 A：自建代理（当前默认，已上线）

后端 `backend/tileproxy.py` 提供 `/tiles/{上游}/{路径}`：

```
浏览器 -> 我们的域名 /tiles/ofm/... -> 上游（默认 OpenFreeMap）
                                   ↓
                        落盘缓存 data/tiles/（每块只回源一次）
```

它做了五件事，每一件都是"自建"该有的样子：

1. **统一出口**——源站只看到服务器一个 IP，不会因为几十个用户各自高频请求而被判定异常。
2. **磁盘缓存**——第一块瓦片回源一次，之后永久本地读；样式 JSON 里的绝对 URL
   会被改写成 `/tiles/ofm/...`，否则 MapLibre 会绕过代理直连源站，代理就白做了。
3. **单飞回源**——同一块瓦片并发来了 N 个请求，只发一个上游请求，其余等锁。
4. **并发闸 + 超时重试 + 404 负缓存**——不会瞬间对源站打出几百个连接。
5. **防盗链**——生产环境只认本站 Referer/Origin，瓦片不被别人白嫖。

相关配置（都在 `backend/config.py`，可用环境变量覆盖）：

```
RVCAMP_TILE_PROXY=/tiles            # 置空才退回浏览器直连（不建议）
RVCAMP_TILE_UPSTREAM_OFM=...        # 换上游，例如指到形态 B 的本地服务
RVCAMP_TILE_INFLIGHT=8              # 同时回源的最大并发
RVCAMP_TILE_CACHE_DAYS=180          # 多久没人看就淘汰
RVCAMP_TILE_CACHE_MB=4096           # 磁盘占用上限，超了按最旧的删
```

### 预热：把常看的区域提前搬到本地

用户第一次打开某块区域才有回源延迟。热门城市可以提前预热：

```bash
cd backend
# 北京五环一带 z10~z14，约几千块
python ../deploy/selfhost-tiles/warm_cache.py --bbox 116.0,39.6,116.8,40.2 --minz 10 --maxz 14
# 全国概览 z3~z9，块数很少，几秒就完
python ../deploy/selfhost-tiles/warm_cache.py --bbox 73,18,135,54 --minz 3 --maxz 9
```

脚本直接调后端函数写缓存，不需要服务在跑；也可以 `--host http://127.0.0.1:8000`
走 HTTP（适合预热一台远程机器）。

---

## 形态 B：完全离线（自己生成瓦片）

用 OSM 的原始数据自己切片，从此和任何第三方瓦片服务没有关系。
三个组件全是开源免费：**Geofabrik 数据 + tilemaker 切片 + martin 发布**。

### 资源账（先算清楚再动手）

| 范围 | 输入 pbf | 内存 | 耗时 | 输出 mbtiles |
|---|---|---|---|---|
| 单个省（如广东） | ~200MB | 4~8GB | 十几分钟 | ~0.6GB |
| 全国 z0–z14 | ~1GB | 16GB+（不够就加 `--store` 走 SSD） | 半小时~数小时 | ~3.5GB |
| 全球 | ~80GB | 100GB+ | 别在个人机器上试 | — |

> 数据来自 tilemaker 官方 README 与社区实测：内存大约需要输入文件的 2 倍，
> 用 `--store <ssd目录>` 可以把临时数据放到磁盘，内存压力大幅下降。
> 官方文档建议的处理顺序就是"按国家/地区分片，再用 `--merge` 合并"。

### 步骤

```bash
cd deploy/selfhost-tiles

# 1) 下数据（Geofabrik，免费，ODbL 协议；按省更小更快）
curl -L -o china-latest.osm.pbf https://download.geofabrik.de/asia/china-latest.osm.pbf

# 2) 切片（tilemaker 官方镜像，单进程，不需要数据库）
./build-offline.sh china-latest.osm.pbf china.mbtiles

# 3) 发布（martin，Rust 写的，很轻）
docker compose -f docker-compose.tiles.yml up -d
# 现在 http://127.0.0.1:7800 就是你的瓦片服务

# 4) 把后端指过去（改 .env 或 docker-compose 的环境变量）
RVCAMP_TILE_UPSTREAM_OFM=http://127.0.0.1:7800
```

第 4 步之后，前端一行都不用改。`/tiles/ofm/...` 会转成请求本机 martin，
缓存层继续照常工作，只是回源对象变成了 localhost。

⚠️ **换成本地源要注意一件事**：样式 JSON 也得住本地。OpenFreeMap 的
`styles/liberty` 指向的是它自己的 `/planet`，数据源不一样路径就对不上。
最省事的做法是用 tilemaker 自带的 demo server（它会生成配套样式）：

```bash
docker run --rm -p 8080:8080 -v $PWD:/data ghcr.io/systemed/tilemaker:master \
    tilemaker-server /data/china.mbtiles
```

然后把 `RVCAMP_TILE_UPSTREAM_OFM=http://127.0.0.1:8080`，
并把前端 `TILE_PROVIDERS` 里的 `path` 改成该服务给出的样式路径。

### 合规提醒（这一段别跳过）

OSM 派生底图在中国大陆面向公众提供服务，仍需要走有审图号的地图。
自托管解决的是"成本与依赖"，不解决"审图号"。
真要正式商用，还是得接有资质的底图（天地图有免费额度，只是要注册拿 Key）。
用户明确不想用 Key 的话，就先把这一层当作**开发与内网环境**的方案。
