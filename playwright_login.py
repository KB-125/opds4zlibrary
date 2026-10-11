# playwright_login.py
"""Z-Library 登录，并把 cookie 存到 zlib_cookies.json（给 main.py 的下载接口用）。

两条路，按顺序尝试（都不需要人工看管）：
1. 快路（默认，约 5~15 秒）：httpx 直接 POST /login。z-lib.gl 的登录表单没有 CSRF，
   先解 SHA1 工作量证明（与 main.py 同算法），再 POST email/password。
2. 慢路（兜底，最多约 90 秒）：Playwright 真实浏览器。等待已刻意缩短，
   所有输出实时刷新（print 都带 flush=True），不会再出现“卡住没反应”。

三个要点（都是踩过的坑）：
1. cookie 必须属于浏览器/请求真正落地的镜像域名；写死域名会导致 main.py
   请求的 host 与 cookie domain 不一致，下载接口一直被判为未登录。
2. 镜像前端有 JS 浏览器校验（SHA1 工作量证明），快路自己解，慢路由浏览器自动跳过。
3. 本机网络对部分域名存在 DNS 污染，直连超时；配置 ZLIB_PROXY 后两条路都会走代理。
"""

from playwright.sync_api import sync_playwright, Error as PlaywrightError
import hashlib
import httpx
import json
import os
import re
import sys
import time
from urllib.parse import urlparse

from dotenv import load_dotenv

load_dotenv("config.env")  # 明确指定路径

BASE_URL = (os.getenv("ZLIB_BASE_URL") or "https://z-lib.gl").rstrip("/")
ZLIB_EMAIL = os.getenv("ZLIB_EMAIL")
ZLIB_PASSWORD = os.getenv("ZLIB_PASSWORD")
ZLIB_PROXY = (os.getenv("ZLIB_PROXY") or "").strip()
COOKIE_FILE = "zlib_cookies.json"

# 快路单次请求的超时（秒）。代理正常时整个快路约 5~15 秒结束。
FAST_TIMEOUT = float(os.getenv("ZLIB_LOGIN_TIMEOUT") or "15")

# 慢路（浏览器）默认无头；如需观察页面可设 ZLIB_LOGIN_HEADLESS=0
HEADLESS = (os.getenv("ZLIB_LOGIN_HEADLESS") or "1").strip().lower() not in ("0", "false", "no")

FAST_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9,zh-CN;q=0.8",
    "Upgrade-Insecure-Requests": "1",
}

EMAIL_SELECTORS = ['input[name="email"]', 'input[type="email"]', '#email', 'input[name="login"]']
PASSWORD_SELECTORS = ['input[name="password"]', 'input[type="password"]', '#password']
SUBMIT_SELECTORS = [
    'button[type="submit"]', 'input[type="submit"]',
    'button:has-text("Sign in")', 'button:has-text("Log in")',
    'button:has-text("Login")', 'button:has-text("登录")',
]
LOGIN_LINK_SELECTORS = [
    'a[href*="login"]', 'a[href*="signin"]',
    'a:has-text("Log in")', 'a:has-text("Sign in")', 'a:has-text("登录")',
]


def log(msg: str):
    print(msg, flush=True)


def solve_pow(html: str) -> str | None:
    """解镜像的 JS 浏览器校验（SHA1 工作量证明），与 main.py.solve_browser_check 同算法。"""
    seed = ""
    m = re.search(r"const a0_0x2a54=\[([^\]]*)\]", html)
    if m:
        items = re.findall(r"'([^']*)'", m.group(1))
        if items:
            rot = 0
            m_rot = re.search(r"a0_0x2a54,\s*0x([0-9a-fA-F]+)\)", html)
            if m_rot:
                rot = int(m_rot.group(1), 16) % len(items)
            items = items[rot:] + items[:rot]
            seed = items[2] if len(items) > 2 else ""
    if not re.fullmatch(r"[0-9A-Fa-f]{40}", seed or ""):
        m_seed = re.search(r"'([0-9A-Fa-f]{40})'", html)
        seed = m_seed.group(1) if m_seed else ""
    if not seed:
        return None
    idx = int(seed[0], 16)
    for i in range(200000):
        digest = hashlib.sha1(f"{seed}{i}".encode()).digest()
        if digest[idx] == 0xB0 and digest[idx + 1] == 0x0B:
            return seed + str(i)
    return None


def dump_httpx_cookies(client: httpx.Client) -> list:
    """把 httpx cookie 存成与浏览器同格式的列表，main.py.load_cookies 可直接读取。"""
    out = []
    for c in client.cookies.jar:
        out.append({
            "name": c.name, "value": c.value or "",
            "domain": c.domain or "", "path": c.path or "/",
        })
    return out


def save_cookie_list(cookies: list, host: str) -> None:
    if not cookies:
        log(f"⚠️ 本次没有得到任何 cookie，保留原有 {COOKIE_FILE} 不变")
        return
    with open(COOKIE_FILE, "w") as f:
        json.dump(cookies, f, indent=2)
    domains = sorted({c.get("domain", "") for c in cookies})
    log(f"✅ 已保存 {len(cookies)} 个 cookie 到 {COOKIE_FILE}")
    log(f"   cookie 域名：{domains}")
    if host and not any(host.endswith(d.lstrip(".")) for d in domains if d):
        log(f"⚠️ 没有任何 cookie 属于镜像域名 {host}，下载接口可能仍被判为未登录")


def fast_login() -> int:
    """httpx 直接 POST 登录：0=成功，2=转慢路，1=硬失败（缺账号或代理不通）。

    全程约 5~15 秒：GET /login（过 PoW）→ POST 表单 → GET / 验证出现 logout。
    """
    log(f"⚡ 快路：httpx 直接 POST 登录 {BASE_URL}/login（不开浏览器）…")
    if not ZLIB_PROXY:
        log("   提示：未配置 ZLIB_PROXY，本机直连镜像多半超时；建议先配好代理再跑")
    t0 = time.time()
    try:
        with httpx.Client(headers=FAST_HEADERS, proxy=ZLIB_PROXY or None,
                           timeout=FAST_TIMEOUT, follow_redirects=False) as c:
            log("   GET /login …")
            r = c.get(BASE_URL + "/login")
            log(f"   /login → {r.status_code}（{time.time() - t0:.1f}s）")
            if r.status_code in (403, 503) and "c_token" in r.text:
                log("   命中浏览器校验，解 PoW …")
                token = solve_pow(r.text)
                if not token:
                    log("   ❌ 校验页无法解析，转浏览器慢路")
                    return 2
                host = urlparse(str(r.url)).netloc
                c.cookies.set("c_token", token, domain=host, path="/")
                c.cookies.set("c_time", "0", domain=host, path="/")
                log(f"   🧩 PoW 通过（{time.time() - t0:.1f}s），重试 /login …")
                r = c.get(BASE_URL + "/login")
                log(f"   /login → {r.status_code}（{time.time() - t0:.1f}s）")
            if r.status_code != 200 or 'name="password"' not in r.text:
                log(f"   ❌ 登录页异常（{r.status_code}，{len(r.text)} 字节），转浏览器慢路")
                return 2
            log("   POST 账号密码 …")
            data = {"email": ZLIB_EMAIL, "password": ZLIB_PASSWORD,
                    "site_mode": "books", "action": "login",
                    "redirectUrl": "", "submit": "true"}
            r2 = c.post(BASE_URL + "/login", data=data,
                        headers={"Referer": BASE_URL + "/login"})
            log(f"   POST → {r2.status_code}（{time.time() - t0:.1f}s）")
            home = c.get(BASE_URL + "/")
            logged_in = (home.status_code == 200
                         and 'name="password"' not in home.text
                         and ("/logout" in home.text or "logout" in home.text.lower()))
            host = urlparse(str(home.url)).netloc
            save_cookie_list(dump_httpx_cookies(c), host)
            if logged_in:
                log(f"🎉 快路登录成功（共 {time.time() - t0:.1f}s），落在 {home.url}")
                return 0
            log("   ❌ 首页仍是未登录态：账号密码错误、需要验证码，或站点拒绝了登录")
            return 1
    except (httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout) as e:
        log(f"   ❌ 网络不通（{type(e).__name__}）：{str(e)[:120]}")
        log("   处理办法：确认代理可用（ZLIB_PROXY），或换 ZLIB_BASE_URL")
        return 1
    except httpx.HTTPError as e:
        log(f"   ❌ 请求失败（{type(e).__name__}）：{str(e)[:120]}，转浏览器慢路")
        return 2


def first_visible(page, selectors, timeout_ms: int = 5000):
    """在若干候选选择器里找出第一个可见元素，找不到返回 None。"""
    deadline = time.time() + timeout_ms / 1000
    while time.time() < deadline:
        for sel in selectors:
            try:
                loc = page.locator(sel).first
                if loc.count() and loc.is_visible():
                    return loc
            except PlaywrightError:
                continue
        page.wait_for_timeout(300)
    return None


def wait_for_gate(page, timeout_ms: int = 30000) -> str:
    """等待镜像的 JS 校验（自动重载）结束，返回最终 URL（最多等 timeout_ms）。"""
    deadline = time.time() + timeout_ms / 1000
    last_len = -1
    stable = 0
    while time.time() < deadline:
        try:
            html = page.content()
        except PlaywrightError:
            html = ""
        challenged = "c_token" in html and "document.cookie" in html
        if not challenged:
            # 内容长度连续两次基本不变，就认为页面已经稳定
            if abs(len(html) - last_len) < 300:
                stable += 1
                if stable >= 2:
                    return page.url
            else:
                stable = 0
            last_len = len(html)
        page.wait_for_timeout(1200)
    return page.url


def goto_with_retry(page, url: str, attempts: int = 2, timeout: int = 30000):
    """打开页面并重试（单次最多等 timeout 毫秒）。"""
    last_error = None
    for i in range(attempts):
        try:
            return page.goto(url, timeout=timeout, wait_until="domcontentloaded")
        except PlaywrightError as e:
            last_error = e
            first = str(e).splitlines()[0]
            log(f"↻ 打开 {url} 第 {i + 1} 次失败：{first[:140]}")
            if "ERR_CERT" in first or "ERR_CONNECTION" in first or "TIMED_OUT" in first:
                log("   （疑似 DNS 污染 / 网络拦截；若持续失败请配置 ZLIB_PROXY）")
            page.wait_for_timeout(1500)
    raise last_error


def launch_browser(p, headless: bool):
    """优先用自带 chromium，失败则回落到本机 Chrome / Edge。"""
    kwargs = {"headless": headless}
    if ZLIB_PROXY:
        kwargs["proxy"] = {"server": ZLIB_PROXY}
    errors = []
    for extra in ({}, {"channel": "chrome"}, {"channel": "msedge"}):
        try:
            return p.chromium.launch(**{**kwargs, **extra})
        except PlaywrightError as e:
            errors.append(str(e).splitlines()[0][:120])
    log("❌ 无法启动浏览器：")
    for msg in errors:
        log(f"   - {msg}")
    log("   提示：执行 `playwright install chromium`，或安装 Chrome / Edge 后重试。")
    return None


def browser_login() -> int:
    """Playwright 慢路兜底：全程上限约 90 秒，每一步都实时输出。"""
    log(f"🐢 慢路：Playwright 浏览器登录（headless={HEADLESS}"
        f"{'，走代理 ' + ZLIB_PROXY if ZLIB_PROXY else ''}）…")
    with sync_playwright() as p:
        browser = launch_browser(p, HEADLESS)
        if browser is None:
            return 1
        context = browser.new_context(locale="en-US")
        page = context.new_page()
        try:
            log(f"🌐 打开入口 {BASE_URL}")
            goto_with_retry(page, BASE_URL)
            final_url = wait_for_gate(page)
            host = urlparse(final_url).netloc
            log(f"🔁 浏览器最终落在 {final_url}（{len(page.content())} 字节）")

            if len(page.content()) < 800:
                log(f"❌ 镜像没有返回内容（地址 {page.url}）")
                save_cookie_list([{"name": c["name"], "value": c["value"],
                                   "domain": c.get("domain", ""), "path": c.get("path", "/")}
                                  for c in context.cookies()], host)
                return 1

            # 1) 先看当前页面有没有登录表单
            email_input = first_visible(page, EMAIL_SELECTORS, 5000)
            # 2) 没有就点「登录」入口
            if email_input is None:
                link = first_visible(page, LOGIN_LINK_SELECTORS, 3000)
                if link is not None:
                    link.click()
                    page.wait_for_timeout(2500)
                    email_input = first_visible(page, EMAIL_SELECTORS, 8000)
            # 3) 再不行就直接访问 /login
            if email_input is None:
                login_url = final_url.rstrip("/") + "/login"
                log(f"↪️ 未发现登录表单，直接访问 {login_url}")
                goto_with_retry(page, login_url, attempts=1, timeout=30000)
                wait_for_gate(page, 20000)
                email_input = first_visible(page, EMAIL_SELECTORS, 8000)

            if email_input is None:
                log("❌ 找不到登录表单：页面结构可能已变化")
                log(f"   当前地址 {page.url}，页面长度 {len(page.content())}")
                save_cookie_list([{"name": c["name"], "value": c["value"],
                                   "domain": c.get("domain", ""), "path": c.get("path", "/")}
                                  for c in context.cookies()], host)
                return 1

            email_input.fill(ZLIB_EMAIL)
            password_input = first_visible(page, PASSWORD_SELECTORS, 5000)
            if password_input is None:
                log("❌ 登录页里没有密码输入框，页面结构可能已变化")
                return 1
            password_input.fill(ZLIB_PASSWORD)

            submit = first_visible(page, SUBMIT_SELECTORS, 5000)
            if submit is not None:
                submit.click()
            else:
                password_input.press("Enter")

            # 等待登录完成：密码框消失即认为跳转成功（最多 15 秒）
            for _ in range(15):
                page.wait_for_timeout(1000)
                if first_visible(page, PASSWORD_SELECTORS, 300) is None:
                    break

            still_login = first_visible(page, PASSWORD_SELECTORS, 500) is not None
            save_cookie_list([{"name": c["name"], "value": c["value"],
                               "domain": c.get("domain", ""), "path": c.get("path", "/")}
                              for c in context.cookies()], host)
            if still_login:
                log(f"⚠️ 登录表单仍在（{page.url}）：账号密码错误、需要验证码，或镜像拒绝登录")
                return 1
            log(f"🎉 登录成功，当前地址 {page.url}")
            return 0
        except PlaywrightError as e:
            log(f"❌ 浏览器操作失败：{str(e).splitlines()[0][:200]}")
            return 1
        finally:
            browser.close()


def main() -> int:
    if not ZLIB_EMAIL or not ZLIB_PASSWORD:
        log("❌ config.env 里缺少 ZLIB_EMAIL / ZLIB_PASSWORD")
        return 1
    rc = fast_login()
    if rc == 0:
        return 0
    if rc == 1:
        return 1
    log("—— 快路没走通，转浏览器慢路兜底 ——")
    return browser_login()


if __name__ == "__main__":
    sys.exit(main())
