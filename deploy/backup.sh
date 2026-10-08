#!/usr/bin/env bash
# 备份脚本：数据库热备 + 上传目录打包，可挂 crontab
#
#   0 4 * * * /opt/rv-camp-map/deploy/backup.sh >> /var/log/rvcamp-backup.log 2>&1
#
# 用 SQLite 的 VACUUM INTO 做在线快照，不需要停服务。
# 只保留最近 14 份，否则备份自己会先撑爆磁盘。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT/backend"

PY="$(command -v python3)"
if [ -x "$ROOT/backend/.venv/bin/python" ]; then
  PY="$ROOT/backend/.venv/bin/python"
fi

KEEP=${KEEP:-14}
"$PY" maintenance.py --backup

echo "$(date '+%F %T') 备份完成，保留最近 $KEEP 份 -> $ROOT/data/backups"

# 有远程存储就把备份同步出去（配置后自动生效）
if [ -n "${BACKUP_REMOTE:-}" ]; then
  rsync -az --delete "$ROOT/data/backups/" "$BACKUP_REMOTE"
  echo "$(date '+%F %T') 已同步到 $BACKUP_REMOTE"
fi
