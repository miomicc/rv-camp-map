#!/usr/bin/env bash
# 营地地图 · 一键启动
#
# 开发：  ./start.sh
# 生产：  RVCAMP_DEV=0 RVCAMP_PEPPER=xxx ./start.sh
#
# 以前这个脚本写死了本地 venv 的绝对路径（换台机器就跑不起来），
# 而且每次都把管理员账号密码明文打印到终端——上线后用它启动，
# 等于把管理员密码贴进日志。现在凭据一律不打印。
set -euo pipefail
cd "$(dirname "$0")"

PORT=${PORT:-8000}
HOST=${HOST:-127.0.0.1}
export RVCAMP_DEV=${RVCAMP_DEV:-1}

# 依次找：项目内 venv -> 环境变量 PYTHON -> 系统 python3
if [ -x "backend/.venv/bin/python" ]; then
  PY="backend/.venv/bin/python"
elif [ -n "${PYTHON:-}" ]; then
  PY="$PYTHON"
else
  PY="$(command -v python3)"
fi

if ! "$PY" -c "import fastapi, multipart, PIL" 2>/dev/null; then
  echo "[1/3] 安装依赖…"
  "$PY" -m pip install -q -r requirements.txt
fi

# 生产模式强制校验 PEPPER：不设就拒绝启动，避免带着"假 pepper"上线
if [ "$RVCAMP_DEV" != "1" ] && [ -z "${RVCAMP_PEPPER:-}" ]; then
  echo "错误：生产模式必须设置 RVCAMP_PEPPER"
  echo "生成： $PY -c \"import secrets;print(secrets.token_hex(32))\""
  exit 1
fi

if [ ! -f data/rvcamp.db ]; then
  echo "[2/3] 初始化数据库与示例数据…"
  (cd backend && "$PY" seed.py)
fi

echo "[3/3] 启动服务  http://$HOST:$PORT"
echo "      后台入口：$HOST:$PORT${RVCAMP_ADMIN_PATH:-/admin}"
echo "      日志：    data/logs/rvcamp.log"
echo "      按 Ctrl+C 停止"
cd backend && exec "$PY" -m uvicorn app:app --host "$HOST" --port "$PORT"
