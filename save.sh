#!/usr/bin/env bash
# 一键存档：把当前改动提交并推送到 GitHub
#
# 用法：
#   ./save.sh "修复了底图白板 bug"
#   ./save.sh                 # 不带说明时先看一眼改了什么，再决定是否提交
#
# 数据安全：data/ 目录（数据库、上传、日志、瓦片缓存、演示凭证）已被 .gitignore
# 排除，无论怎么存档都不会把用户数据传到 GitHub。
set -euo pipefail
cd "$(dirname "$0")"

if ! git rev-parse --git-dir >/dev/null 2>&1; then
  echo "当前目录还不是 git 仓库"; exit 1
fi

if [ -z "$(git status --porcelain)" ]; then
  echo "没有需要提交的改动。"; exit 0
fi

echo "── 本次改动 ─────────────────────────────"
git status --short
echo "─────────────────────────────────────────"

MSG=${1:-}
if [ -z "$MSG" ]; then
  read -r -p "输入本次改动说明（直接回车取消）： " MSG
  [ -z "$MSG" ] && { echo "已取消。"; exit 0; }
fi

git add -A
git commit -m "$MSG"
BRANCH=$(git branch --show-current)
git push origin "$BRANCH"

echo
echo "✓ 已存档到 GitHub：$(git remote get-url origin) ($BRANCH)"
echo "  提交：$(git log --oneline -1)"
