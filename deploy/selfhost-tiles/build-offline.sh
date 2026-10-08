#!/usr/bin/env bash
# 用 OSM 原始数据自己切片，生成离线 mbtiles。全程开源免费，不需要任何 Key。
#
# 用法：
#   ./build-offline.sh china-latest.osm.pbf china.mbtiles      # 正式跑
#   ./build-offline.sh --check china-latest.osm.pbf            # 只评估资源，不跑
#
# 依赖：docker（推荐）或本机编译的 tilemaker。
# 内存不够就加 --store 走 SSD（脚本默认已开），代价是慢一些、需要额外磁盘。

set -euo pipefail

TILEMAKER_IMAGE="${TILEMAKER_IMAGE:-ghcr.io/systemed/tilemaker:master}"
MINZOOM="${MINZOOM:-0}"
MAXZOOM="${MAXZOOM:-14}"      # 再往上细节收益很小，体积却指数增长
STORE_DIR="${STORE_DIR:-$PWD/.tilemaker-store}"

check_only=0
if [[ "${1:-}" == "--check" ]]; then
  check_only=1
  shift
fi

INPUT="${1:-}"
OUTPUT="${2:-china.mbtiles}"

if [[ -z "$INPUT" ]]; then
  echo "用法: $0 [--check] <input.osm.pbf> [output.mbtiles]"
  exit 1
fi
if [[ ! -f "$INPUT" ]]; then
  echo "找不到输入文件: $INPUT"
  echo "先下数据（免费，ODbL）："
  echo "  curl -L -o china-latest.osm.pbf https://download.geofabrik.de/asia/china-latest.osm.pbf"
  exit 1
fi

size_gb=$(awk -v s=$(stat -f%z "$INPUT" 2>/dev/null || stat -c%s "$INPUT") 'BEGIN{printf "%.1f", s/1073741824}')

echo "================ 资源评估 ================"
echo "输入文件 : $INPUT（${size_gb}GB）"
echo "输出     : $OUTPUT（z${MINZOOM}-z${MAXZOOM}）"
# 经验值：内存约为输入的 2 倍；用了 --store 可以压到 1 倍左右但仍需有余量
echo "建议内存 : 纯内存模式约 $(awk -v s=$size_gb 'BEGIN{printf "%.0f", s*2}')GB，--store 模式约 $(awk -v s=$size_gb 'BEGIN{printf "%.0f", s*1.2+2}')GB"
echo "建议磁盘 : 输出约 $(awk -v s=$size_gb 'BEGIN{printf "%.0f", s*3.5}')GB，另加临时目录约 $(awk -v s=$size_gb 'BEGIN{printf "%.0f", s*4}')GB"
echo "==========================================="

if [[ $check_only -eq 1 ]]; then
  echo "（--check 模式，到此为止）"
  exit 0
fi

mkdir -p "$STORE_DIR"

if command -v docker >/dev/null 2>&1; then
  echo "使用 docker 镜像: $TILEMAKER_IMAGE"
  docker run --rm \
    -v "$PWD:/data" -v "$STORE_DIR:/store" \
    "$TILEMAKER_IMAGE" \
    --input "/data/$(basename "$INPUT")" \
    --output "/data/$(basename "$OUTPUT")" \
    --config /app/resources/config-openmaptiles.json \
    --process /app/resources/process-openmaptiles.lua \
    --store /store \
    --threads "$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)"
elif command -v tilemaker >/dev/null 2>&1; then
  echo "使用本机 tilemaker"
  tilemaker --input "$INPUT" --output "$OUTPUT" --store "$STORE_DIR"
else
  cat <<'EOF'
没找到 docker 也没有 tilemaker。两条路：

  1) 装 docker（最省事）
  2) 源码编译（macOS 先 brew install boost lua@5.4 sqlite shapelib rapidjson）:
       git clone https://github.com/systemed/tilemaker.git
       cd tilemaker && make && sudo make install
EOF
  exit 1
fi

echo
echo "切片完成：$OUTPUT"
echo "发布它（martin，免费开源）："
echo "  docker compose -f docker-compose.tiles.yml up -d"
echo "然后把后端指过去： RVCAMP_TILE_UPSTREAM_OFM=http://127.0.0.1:7800"
