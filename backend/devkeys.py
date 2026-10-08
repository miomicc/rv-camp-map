"""读取 seed.py 生成的本地演示凭证。

仓库是公开的，测试脚本不能再把密钥写死在源码里——
否则每个克隆仓库的人都会拿到同一把可以登录后台的钥匙。

凭证由 seed.py 随机生成后写入 data/dev_keys.json（该目录已 gitignore）。
本模块统一负责读取，缺文件时给出明确的操作提示。
"""

import json
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
DEV_KEYS_PATH = DATA_DIR / "dev_keys.json"


def load() -> dict:
    """返回 {"user_key":..., "admin_key":..., "admin_password":..., ...}"""
    try:
        return json.loads(DEV_KEYS_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise SystemExit(
            f"未找到演示凭证 {DEV_KEYS_PATH}。\n"
            "请先跑一次：python seed.py --reset\n"
            "它会随机生成密钥/密码并写入该文件；\n"
            "想用固定凭证可设环境变量 RVCAMP_SEED_ADMIN_KEY / RVCAMP_SEED_USER_KEY / "
            "RVCAMP_SEED_ADMIN_PASSWORD。")
