# zlib_opds_launcher.py

import subprocess, os, sys, time
from dotenv import load_dotenv

load_dotenv("config.env")  # 明确指定路径

ZLIB_EMAIL = os.getenv("ZLIB_EMAIL")
ZLIB_PASSWORD = os.getenv("ZLIB_PASSWORD")

def check_env():
    if not ZLIB_EMAIL or not ZLIB_PASSWORD:
        print("❌ Please set ZLIB_EMAIL and ZLIB_PASSWORD in config.env")
        sys.exit(1)

def playwright_login() -> bool:
    print("🔐 Logging in to Z-Lib via Playwright...")
    result = subprocess.run([sys.executable, "playwright_login.py"])
    if result.returncode != 0:
        print("⚠️ 登录步骤未成功：OPDS 目录（搜索 / 分类 / 热门）不受影响，")
        print("   但下载接口可能返回 403（无登录 cookie）。常见原因与处理：")
        print("   • 镜像把客户端跳到了官方域名（本机 DNS 污染）→ 在 config.env 里配置 ZLIB_PROXY 走代理")
        print("   • 入口地址不对 → 修改 ZLIB_BASE_URL（默认 https://z-lib.gl）")
        print("   • 无头浏览器被校验拦截 → 设 ZLIB_LOGIN_HEADLESS=0 后重跑，观察页面报错")
        return False
    return True

def launch_fastapi():
    print("🚀 Starting FastAPI at http://localhost:8000/opds")
    subprocess.run(["uvicorn", "main:app", "--reload", "--host", "0.0.0.0", "--port", "8000"])

if __name__ == "__main__":
    check_env()
    playwright_login()
    launch_fastapi()

