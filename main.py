from fastapi import FastAPI, Query, Request, Depends, HTTPException, status
from fastapi.responses import Response, RedirectResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from bs4 import BeautifulSoup
from datetime import datetime
import httpx, os, json, logging, secrets, re, hashlib
from dotenv import load_dotenv
from urllib.parse import quote_plus, quote, unquote, urlparse
from html import escape

app = FastAPI()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

load_dotenv("config.env")  # 明确指定路径

# ---------------------------------------------------------------- 配置
# 站点入口。zlib.ch 这类入口域名会把「任意路径」302 到镜像首页，
# 所以真实站点根（effective base）在运行时解析并缓存，见 resolve_base()。
BASE_URL = os.getenv("ZLIB_BASE_URL", "https://z-lib.gl").rstrip("/")
COOKIE_FILE = "zlib_cookies.json"
cookies_jar = httpx.Cookies()

USERNAME = os.getenv("OPDS_USER", "admin")
PASSWORD = os.getenv("OPDS_PASS", "password")

# /opds/new 用的过滤条件：站点没有匿名可用的「最新入库」列表（/new、newest mosaic 均 404），
# 因此用 yearFrom + order=newest 逼近「新书」。
NEW_LANG = os.getenv("ZLIB_NEW_LANG", "").strip()
NEW_YEAR_FROM = os.getenv("ZLIB_NEW_YEAR_FROM", "").strip() or str(datetime.now().year - 1)
# /opds/popular 走 /papi/book/mostpopular/mosaic/{batch}/{page} JSON 接口
MOSAIC_BATCH = os.getenv("ZLIB_MOSAIC_BATCH", "20").strip() or "20"

# 可选代理（http://host:port 或 socks5://host:port）。
# 本机网络对 Z-Library 官方镜像（z-lib.fm / z-library.sk …）存在 DNS 污染，
# 镜像把这些客户端 302 到官方域名后会一直连不上；配置代理可绕开。
PROXY = os.getenv("ZLIB_PROXY", "").strip() or None

# 镜像前端带 JS 浏览器校验（SHA1 工作量证明）：解开后按 host 缓存 cookie，避免每次请求重算
BROWSER_COOKIES: dict[str, dict[str, str]] = {}
EFFECTIVE_BASE: str | None = None

# /categories 解析结果缓存（data-name -> data-id）
CATEGORY_ITEMS: list[dict] = []
CATEGORY_IDS: dict[str, str] = {}

BROWSER_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9,zh-CN;q=0.8",
    "Upgrade-Insecure-Requests": "1",
}

EMOJI_MAP = {
    "pdf": "📕", "epub": "📚", "mobi": "📘", "djvu": "📄",
    "azw3": "📙", "txt": "📝",
}


def now_iso() -> str:
    return datetime.utcnow().isoformat() + "Z"


# 将subnail的url升级为 大图 / 生成缩略图
def cover_variants(url: str) -> tuple[str, str]:
    """返回 (大图 covers400, 缩略图 covers150)。"""
    if not url:
        return "", ""
    big = re.sub(r"/covers\d+/", "/covers400/", url, count=1)
    thumb = re.sub(r"/covers\d+/", "/covers150/", url, count=1)
    return big, thumb


# 注意一定要写 auto_error = false才能让你的http header有效
security = HTTPBasic(auto_error=False)

def verify_credentials(credentials: HTTPBasicCredentials = Depends(security)):
    if credentials is None or not credentials.username:
        # 未提供任何凭证
        logger.info(f"🚨 no credential provided")
       # logger.info(f"user {credentials.username} pass: {credentials.password}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": 'Basic realm="Login Required"'}
        )
    # 校验用户名和密码（假设正确凭证为 user/pass）
    correct_username = secrets.compare_digest(credentials.username, USERNAME)
    correct_password = secrets.compare_digest(credentials.password, PASSWORD)
    
    if not (correct_username and correct_password):
        # 凭证不匹配
        logger.info(f" 🚨  credential error")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": 'Basic realm="Login Required"'}
        )
    return True  # 验证通过


def load_cookies():
    global cookies_jar
    if os.path.exists(COOKIE_FILE) and os.path.getsize(COOKIE_FILE) > 0:
        with open(COOKIE_FILE, "r") as f:
            cookies_list = json.load(f)
            for c in cookies_list:
                # 保留浏览器写入的原始 domain（登录发生在镜像域名上，不能硬编码成 z-lib.fm）
                cookies_jar.set(c["name"], c["value"], domain=c.get("domain") or "", path=c.get("path") or "/")
        domains = sorted({c.get("domain") or "(未指定)" for c in cookies_list})
        logger.info(f"✅ Loaded {len(cookies_list)} cookies from {COOKIE_FILE}，域名：{domains}")

@app.on_event("startup")
async def startup_event():
    load_cookies()


# ---------------------------------------------------------------- 浏览器校验 / 站点定位

def solve_browser_check(html: str) -> str | None:
    """解镜像的 JS 浏览器校验（SHA1 工作量证明），返回应写入 c_token 的值。

    站点脚本形如：
        const a0_0x2a54=['<40位十六进制种子>','c_token=','array'];
        (...,a0_0x2a54,0x178)   // 数组左移 376 % 3 = 1 位 -> 种子落在索引 2
        循环 i：SHA1(种子 + i) 的字节满足 digest[seed[0]] == 0xb0 且下一个字节 == 0x0b
        命中后 document.cookie='c_token=' + 种子 + i
    """
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


async def _get_following(client: httpx.AsyncClient, url, params: dict | None = None,
                        max_redirects: int = 5) -> httpx.Response:
    """手动跟随跳转。

    镜像把「不可接受的客户端」踢走时会回 302 + `x-redirect-type`，这种跳转不能跟：
    目标通常是本机 DNS 被污染的官方域名（z-library.sk 之类），跟过去只会一直等到超时。
    """
    resp = await client.get(url, params=params)
    for _ in range(max_redirects):
        if resp.status_code not in (301, 302, 303, 307, 308):
            return resp
        if resp.headers.get("x-redirect-type"):
            return resp
        loc = resp.headers.get("location")
        if not loc:
            return resp
        resp = await client.get(resp.url.join(loc))
    return resp


def _bounce_detail(resp: httpx.Response) -> str:
    """镜像把客户端踢到别的域名时的可读说明。"""
    target = resp.headers.get("location") or "未知地址"
    kind = resp.headers.get("x-redirect-type") or "redirect"
    return (
        f"镜像 {resp.url.host} 拒绝了当前客户端（x-redirect-type: {kind}），要求改用 {target}。"
        f"该域名在本机网络下不可访问（DNS 污染），请在 config.env 里配置 ZLIB_PROXY 走代理，"
        f"或把 ZLIB_BASE_URL 换成可访问的镜像地址。"
    )


def _raise_bounce(resp: httpx.Response):
    detail = _bounce_detail(resp)
    logger.error(f"🚧 {detail}")
    raise HTTPException(status_code=502, detail=detail)


async def handle_browser_check(client: httpx.AsyncClient, resp: httpx.Response) -> httpx.Response:
    """命中浏览器校验页时解出 c_token 并重试一次。

    注意：cookie 必须写在「最终 host」（镜像域名）上；写在入口域名上会一直循环拿到校验页。
    """
    if resp.status_code not in (403, 503) or "c_token" not in resp.text:
        return resp
    token = solve_browser_check(resp.text)
    if not token:
        logger.warning(f"⚠️ 浏览器校验页无法解析：{resp.url}")
        return resp
    host = resp.url.host
    BROWSER_COOKIES[host] = {"c_token": token, "c_time": "0"}
    logger.info(f"🧩 浏览器校验通过 host={host} c_token={token[:12]}…")
    for name, value in BROWSER_COOKIES[host].items():
        client.cookies.set(name, value, domain=host, path="/")
    return await _get_following(client, resp.url)


def inject_cookies(client: httpx.AsyncClient, host: str) -> None:
    """把登录 cookie 与已解出的浏览器校验 cookie 注入到镜像 host。

    zlib_cookies.json 里 cookie 的 domain 是「浏览器实际登录的那个域名」（镜像域名），
    与入口域名（zlib.ch）不一致，因此这里按域名后缀匹配，而不是无条件注入。
    """
    host = (host or "").lower()
    matched = 0
    for cookie in list(cookies_jar.jar):
        if not cookie.value:
            continue
        dom = (cookie.domain or "").lstrip(".").lower()
        if dom and dom != host and not host.endswith("." + dom):
            continue
        client.cookies.set(cookie.name, cookie.value, domain=host, path="/")
        matched += 1
    for name, value in BROWSER_COOKIES.get(host, {}).items():
        client.cookies.set(name, value, domain=host, path="/")
    if cookies_jar.jar and not matched:
        logger.warning(f"⚠️ zlib_cookies.json 里的 cookie 域名与镜像 {host} 不匹配，未注入登录态")


async def resolve_base(client: httpx.AsyncClient) -> str:
    """解析真实站点根：入口域名会 302 到镜像首页（路径被丢弃）。"""
    global EFFECTIVE_BASE
    if EFFECTIVE_BASE:
        return EFFECTIVE_BASE
    resp = await _get_following(client, BASE_URL)
    resp = await handle_browser_check(client, resp)
    if resp.status_code in (301, 302, 303, 307, 308):
        _raise_bounce(resp)
    if resp.status_code >= 400:
        logger.error(f"❌ 站点入口不可用：{BASE_URL} => {resp.status_code}")
        raise HTTPException(status_code=502, detail=f"Z-Library 入口不可用：{BASE_URL} => {resp.status_code}")
    parsed = urlparse(str(resp.url))
    EFFECTIVE_BASE = f"{parsed.scheme}://{parsed.netloc}"
    if EFFECTIVE_BASE != BASE_URL:
        logger.info(f"🔁 站点入口 {BASE_URL} 实际指向镜像 {EFFECTIVE_BASE}")
    return EFFECTIVE_BASE


async def zlib_get(path: str, params: dict | None = None, timeout: float = 30.0):
    """带镜像定位 + 浏览器校验 + 登录 cookie 的 GET，返回 (响应, 站点根)。"""
    global EFFECTIVE_BASE
    url_path = path if path.startswith("/") else "/" + path
    try:
        async with httpx.AsyncClient(headers=BROWSER_HEADERS, follow_redirects=False,
                                     timeout=timeout, proxy=PROXY) as client:
            base = await resolve_base(client)
            inject_cookies(client, urlparse(base).netloc)
            resp = await _get_following(client, base + url_path, params)
            resp = await handle_browser_check(client, resp)
            if resp.status_code in (301, 302, 303, 307, 308):
                _raise_bounce(resp)
            if resp.status_code >= 500:
                # 镜像可能已经切换：丢掉缓存重新定位一次
                logger.warning(f"⚠️ {base + url_path} => {resp.status_code}，重新解析站点根后重试")
                EFFECTIVE_BASE = None
                base = await resolve_base(client)
                inject_cookies(client, urlparse(base).netloc)
                resp = await _get_following(client, base + url_path, params)
                resp = await handle_browser_check(client, resp)
                if resp.status_code in (301, 302, 303, 307, 308):
                    _raise_bounce(resp)
            logger.info(f"🌐 {resp.request.method} {resp.request.url} => {resp.status_code}")
            return resp, base
    except httpx.HTTPError as e:
        detail = f"访问 Z-Library 失败：{type(e).__name__}: {e}（可配置 ZLIB_PROXY 走代理后重试）"
        logger.error(f"🚧 {detail}")
        raise HTTPException(status_code=502, detail=detail)


# ---------------------------------------------------------------- OPDS 渲染辅助

def page_href(path: str, params: dict, page: int) -> str:
    """拼出带参数的目录地址（空值参数会被丢弃）。"""
    merged = {k: v for k, v in {**params, "page": page}.items() if v not in (None, "")}
    query = "&".join(f"{k}={quote_plus(str(v))}" for k, v in merged.items())
    return f"{path}?{query}" if query else path


def pagination_links(path: str, params: dict, page: int, total: int | None, next_page: int | None) -> str:
    links = []
    if next_page:
        links.append(f"<link rel='next' type='application/atom+xml' href='{escape(page_href(path, params, next_page))}'/>")
    if page > 1:
        links.append(f"<link rel='previous' type='application/atom+xml' href='{escape(page_href(path, params, page - 1))}'/>")
        links.append(f"<link rel='first' type='application/atom+xml' href='{escape(page_href(path, params, 1))}'/>")
    if total and total > 1:
        links.append(f"<link rel='last' type='application/atom+xml' href='{escape(page_href(path, params, total))}'/>")
    return "\n  ".join(links)


def nav_entry(*, title: str, entry_id: str, href: str, content: str = "",
              author: str = "", cover: str = "", updated: str = "") -> str:
    """OPDS 导航条目（subsection 链接），可选封面。"""
    links = [f"<link rel='subsection' href='{escape(href)}' type='application/atom+xml'/>"]
    if cover:
        big, thumb = cover_variants(cover)
        links.append(f"<link type='image/jpeg' href='{escape(big)}' rel='http://opds-spec.org/image'/>")
        links.append(f"<link type='image/jpeg' href='{escape(thumb)}' rel='http://opds-spec.org/image/thumbnail'/>")
    return f"""  <entry>
    <title>{escape(title)}</title>
    <author><name>{escape(author or 'Z-Library')}</name></author>
    <id>{escape(entry_id)}</id>
    <updated>{updated or now_iso()}</updated>
    <content type='text'>{escape(content or title)}</content>
    {"".join(links)}
  </entry>"""


def render_book_entries(soup: BeautifulSoup, base: str) -> str:
    """把检索/分类页的 <z-bookcard> 渲染成 OPDS acquisition 条目。

    展示约定（作者前缀 emoji、publisher 行、cover/thumbnail 四种 rel）沿用原有实现，
    避免影响已调好的 Moon+ Reader / KyBook 3 显示效果。
    """
    entries = ""
    for item in soup.select("z-bookcard"):
        if (item.get("deleted") or "0") == "1":
            continue  # 已删除的书没有下载链接
        title_el = item.select_one("div[slot=title]")
        author_el = item.select_one("div[slot=author]")
        img_el = item.select_one("img")
        title = escape((title_el.text.strip() if title_el else "") or "Untitled")
        author = escape((author_el.text.strip() if author_el else "") or "Unknown")
        publisher = escape(item.get("publisher", ""))
        book_id = item.get("id", "")
        detail_path = item.get("href", "")
        download_path = item.get("download", "")
        extension = escape(item.get("extension", ""))
        filesize = escape(item.get("filesize", ""))
        year = escape(item.get("year", ""))
        language = escape(item.get("language", ""))
        rating = escape(item.get("rating", ""))
        cover_raw = (img_el.get("data-src") or img_el.get("src") or "") if img_el else ""
        big_cover_raw, thumb_cover_raw = cover_variants(cover_raw)

        published_date = f"{year}-01-01T00:00:00Z" if year.isdigit() else ""

        emoji = EMOJI_MAP.get(extension.lower(), "📦")
        summary_parts = [f"{emoji} {extension.upper()}".strip()]
        if filesize:
            summary_parts.append(filesize)
        if year:
            summary_parts.append(year)
        if language:
            summary_parts.append(language)
        if rating:
            summary_parts.append(f"⭐{rating}")
        summary = ", ".join(summary_parts)

        entry_id = f"urn:zlib:book:{book_id}" if book_id else f"urn:zlib:book:{quote(title)}"
        links = []
        if download_path:
            token = quote(f"{book_id}:{download_path}", safe="")
            book_url = f"/download?token={token}"
            links.append(f"<link rel='http://opds-spec.org/acquisition' href='{escape(book_url)}' type='application/octet-stream'/>")
        else:
            # 没有下载链接时退化为「按标题搜索」，条目仍然可用
            links.append(f"<link rel='subsection' href='/opds/search?q={quote_plus(title)}' type='application/atom+xml'/>")
        if detail_path:
            links.append(f"<link rel='alternate' type='text/html' href='{escape(base + detail_path)}'/>")
        if cover_raw:
            links.append(f"<link type='image/jpeg' href='{escape(big_cover_raw)}' rel='http://opds-spec.org/cover'  />")
            links.append(f"<link type='image/jpeg' href='{escape(thumb_cover_raw)}' rel='http://opds-spec.org/thumbnail'   />")
            links.append(f"<link type='image/jpeg' href='{escape(big_cover_raw)}' rel='http://opds-spec.org/image'  />")
            links.append(f"<link type='image/jpeg' href='{escape(thumb_cover_raw)}' rel='http://opds-spec.org/image/thumbnail' />")

        entries += f"""
        <entry>
            <title>{title}</title>
            <author><name>{emoji}{author}</name></author>
            <publisher><name>🏛️ {publisher}/{extension},{filesize}</name></publisher>
            <published>{published_date}</published>
            <id>{escape(entry_id)}</id>
            <updated>{now_iso()}</updated>
            <content type='text'>{escape(summary)}</content>
            {"".join(links)}
        </entry>
        """
    return entries


def parse_pagination(html: str, soup: BeautifulSoup) -> tuple[int, int | None, int | None]:
    """解析分页信息，返回 (当前页, 总页数, 下一页)。"""
    current = None
    total = None
    m = re.search(r"pageCurrent:\s*(\d+)", html)
    if m:
        current = int(m.group(1))
    m = re.search(r"pagesTotal:\s*(\d+)", html)
    if m:
        total = int(m.group(1))
    if current is None:
        current = 1

    next_page = current + 1 if (total and current < total) else None
    if next_page is None:
        next_link_tag = soup.select_one("div.paginator noscript a")
        if next_link_tag:
            m = re.search(r"page=(\d+)", next_link_tag.get("href", "") or "")
            if m:
                next_page = int(m.group(1))
    return current, total, next_page


def build_feed(*, feed_id: str, title: str, self_href: str, entries: str,
               extra_links: str = "", start_href: str = "/opds/root.xml") -> Response:
    feed = f"""<?xml version='1.0' encoding='utf-8'?>
<feed xmlns='http://www.w3.org/2005/Atom'
      xmlns:opds='http://opds-spec.org/2010/catalog'>
  <title>{escape(title)}</title>
  <id>{escape(feed_id)}</id>
  <updated>{now_iso()}</updated>
  <author><name>Z-Lib Proxy</name></author>
  <link rel='self' type='application/atom+xml' href='{escape(self_href)}'/>
  <link rel='start' type='application/atom+xml' href='{escape(start_href)}'/>
  <link rel='search' type='application/opensearchdescription+xml' href='/opds/opensearch.xml'/>
  <link rel='http://opds-spec.org/search' type='application/atom+xml' href='/opds/search?q={{searchTerms}}'/>
  {extra_links}
{entries}
</feed>"""
    return Response(content=feed.strip(), media_type="application/atom+xml")


async def book_list_feed(*, feed_id: str, title: str, path: str, params: dict, page: int,
                         self_path: str, self_params: dict | None = None,
                         start_href: str = "/opds/root.xml") -> Response:
    """检索/分类/作者/新书共用的「书籍列表 feed」构建流程。"""
    self_params = self_params or {}
    resp, base = await zlib_get(path, params={**params, "page": page})
    if resp.status_code != 200:
        raise HTTPException(status_code=502, detail=f"Z-Library 返回 {resp.status_code}")

    soup = BeautifulSoup(resp.text, "html.parser")
    entries = render_book_entries(soup, base)
    if not entries.strip():
        logger.warning(f"⚠️ {path} 没有解析到任何 <z-bookcard>")
        entries = nav_entry(
            title="没有找到结果",
            entry_id=f"urn:zlib:empty:{quote(title)}",
            href="/opds",
            content="换个关键词或分类再试一次",
        )

    current, total, next_page = parse_pagination(resp.text, soup)
    extra_links = pagination_links(self_path, self_params, page, total, next_page)
    return build_feed(
        feed_id=feed_id,
        title=title,
        self_href=page_href(self_path, self_params, page),
        entries=entries,
        extra_links=extra_links,
        start_href=start_href,
    )


async def ensure_categories() -> None:
    """解析 /categories 页并缓存 (data-name -> data-id)。"""
    global CATEGORY_ITEMS, CATEGORY_IDS
    if CATEGORY_ITEMS:
        return
    resp, _ = await zlib_get("/categories")
    if resp.status_code != 200:
        raise HTTPException(status_code=502, detail=f"分类页不可用：{resp.status_code}")

    soup = BeautifulSoup(resp.text, "html.parser")
    seen = set()
    items = []
    ids = {}
    for node in soup.select("h3.category-name, li.subcategory-name"):
        link = node.select_one("a")
        href = (link.get("href") if link else "") or ""
        name_attr = (node.get("data-name") or "").strip()
        cat_id = (node.get("data-id") or "").strip()
        if not cat_id:
            m = re.search(r"/category/(\d+)", href)
            cat_id = m.group(1) if m else ""
        if not cat_id or cat_id in seen:
            continue
        seen.add(cat_id)
        label = re.sub(r"\(\d+\)\s*$", "", (link.get_text(" ", strip=True) if link else "")).strip()
        label = label or name_attr or cat_id
        items.append({"id": cat_id, "name": name_attr, "label": label, "top": node.name == "h3"})
        if name_attr:
            ids[name_attr.lower()] = cat_id

    CATEGORY_ITEMS = items
    CATEGORY_IDS = ids
    logger.info(f"🗂️ 解析到 {len(items)} 个分类（顶层 {sum(1 for i in items if i['top'])} 个）")


# ---------------------------------------------------------------- 路由

@app.get("/")
async def homepage():
    return RedirectResponse(url="/opds")

@app.get("/opds")
async def opds_index(request: Request, credentials: HTTPBasicCredentials = Depends(verify_credentials)):
    entries = "\n".join([
        nav_entry(title="Root Directory", entry_id="urn:zlib:opds:root",
                  href="/opds/root.xml", content="OPDS 根目录"),
        nav_entry(title="🔍 Search（示例：python）", entry_id="urn:zlib:opds:search:python",
                  href="/opds/search?q=python", content="把 q= 换成任意关键词，如 /opds/search?q=C%2B%2B 或 ?q=三体"),
        nav_entry(title="🔥 Popular Recommendations", entry_id="urn:zlib:opds:popular",
                  href="/opds/popular", content="Z-Library 热门推荐榜"),
        nav_entry(title="🆕 New Books", entry_id="urn:zlib:opds:new",
                  href="/opds/new", content=f"{NEW_YEAR_FROM} 年以来入库的新书"),
        nav_entry(title="🗂️ Categories", entry_id="urn:zlib:opds:categories",
                  href="/opds/categories", content="按 Z-Library 分类目录浏览"),
        nav_entry(title="✍️ Author: Stephen King", entry_id="urn:zlib:opds:author:stephen-king",
                  href="/opds/author/Stephen%20King", content="通过作者名搜索作品"),
        nav_entry(title="NYT Bestsellers", entry_id="urn:zlib:opds:nyt-bestsellers",
                  href="/opds/nyt-bestsellers", content="纽约时报畅销书榜（Hardcover Nonfiction）"),
    ])
    return build_feed(feed_id="urn:zlib:opds:index", title="Z-Library OPDS Proxy Directory",
                      self_href="/opds", entries=entries, start_href="/opds/root.xml")

@app.get("/opds/root.xml")
async def opds_root(credentials: HTTPBasicCredentials = Depends(verify_credentials)):
    entries = "\n".join([
        nav_entry(title="Search: Python", entry_id="urn:zlib:opds:search:python",
                  href="/opds/search?q=python", content="Search for books about Python"),
        nav_entry(title="Search: Deep Learning", entry_id="urn:zlib:opds:search:deep-learning",
                  href="/opds/search?q=deep%20learning", content="Search for books about Deep Learning"),
        nav_entry(title="Popular Recommendations", entry_id="urn:zlib:opds:popular",
                  href="/opds/popular", content="Recommended books from Z-Library"),
        nav_entry(title="New Books", entry_id="urn:zlib:opds:new",
                  href="/opds/new", content=f"Books added since {NEW_YEAR_FROM}"),
        nav_entry(title="Browse Categories", entry_id="urn:zlib:opds:categories",
                  href="/opds/categories", content="Browse Z-Library categories"),
        nav_entry(title="Browse by Author: Stephen King", entry_id="urn:zlib:opds:author:stephen-king",
                  href="/opds/author/Stephen%20King", content="Browse books by author name"),
        nav_entry(title="NYT Bestsellers", entry_id="urn:zlib:opds:nyt-bestsellers",
                  href="/opds/nyt-bestsellers", content="NYT Hardcover Nonfiction list"),
    ])
    return build_feed(feed_id="urn:uuid:zlib-root-feed", title="Z-Library OPDS Root",
                      self_href="/opds/root.xml", entries=entries, start_href="/opds")

@app.get("/opds/opensearch.xml")
async def opensearch_description(request: Request):
    base_url = str(request.base_url).rstrip("/")
    xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<OpenSearchDescription xmlns="http://a9.com/-/spec/opensearch/1.1/">
  <ShortName>Z-Lib Search</ShortName>
  <Description>Search Z-Library via OPDS</Description>
  <InputEncoding>UTF-8</InputEncoding>
  <Url type="application/atom+xml" template="{base_url}/opds/search?q={{searchTerms}}"/>
</OpenSearchDescription>"""
    return Response(content=xml.strip(), media_type="application/opensearchdescription+xml")

@app.get("/opds/search")
async def search_books(q: str = Query(...), page: int = Query(1, ge=1), credentials: HTTPBasicCredentials = Depends(verify_credentials)):
    keywords = " ".join(q.strip().split())
    return await book_list_feed(
        feed_id=f"urn:zlib:opds:search:{keywords.replace(' ', '-')}",
        title=f"Z-Library Search: {keywords}",
        path="/s/",
        params={"q": keywords},
        page=page,
        self_path="/opds/search",
        self_params={"q": keywords},
    )

@app.get("/opds/new")
async def new_books(q: str = Query(""), page: int = Query(1, ge=1), credentials: HTTPBasicCredentials = Depends(verify_credentials)):
    """新书推荐：站点没有匿名可用的「最新入库」页，用 yearFrom + order=newest 逼近。"""
    keywords = " ".join(q.strip().split())
    params: dict = {"order": "newest", "yearFrom": NEW_YEAR_FROM}
    if keywords:
        params["q"] = keywords
    if NEW_LANG:
        params["languages"] = NEW_LANG
    title = f"🆕 Z-Library New Books ({NEW_YEAR_FROM}+)"
    if keywords:
        title += f": {keywords}"
    return await book_list_feed(
        feed_id=f"urn:zlib:opds:new:{NEW_YEAR_FROM}",
        title=title,
        path="/s/",
        params=params,
        page=page,
        self_path="/opds/new",
        self_params={"q": keywords},
    )

@app.get("/opds/popular")
async def popular_books(page: int = Query(1, ge=1), credentials: HTTPBasicCredentials = Depends(verify_credentials)):
    """热门推荐：走站点 mosaic JSON 接口（只有 mostpopular 这个 source 可用）。"""
    resp, base = await zlib_get(f"/papi/book/mostpopular/mosaic/{MOSAIC_BATCH}/{page}")
    if resp.status_code != 200:
        raise HTTPException(status_code=502, detail=f"热门榜接口返回 {resp.status_code}")
    try:
        data = resp.json()
    except Exception:
        logger.exception("热门榜返回了非 JSON 内容")
        raise HTTPException(status_code=502, detail="热门榜返回了非 JSON 内容")

    books = data.get("books") or []
    entries = ""
    for book in books:
        title = escape((book.get("title") or "Untitled").strip())
        author = escape((book.get("author") or "Unknown").strip())
        cover = book.get("cover") or ""
        detail_path = book.get("url") or ""
        book_id = book.get("id") or quote(title)
        search_href = f"/opds/search?q={quote_plus(title)}"
        links = [f"<link rel='subsection' href='{escape(search_href)}' type='application/atom+xml'/>"]
        if detail_path:
            links.append(f"<link rel='alternate' type='text/html' href='{escape(base + detail_path)}'/>")
        if cover:
            big, thumb = cover_variants(cover)
            links.append(f"<link type='image/jpeg' href='{escape(big)}' rel='http://opds-spec.org/image'/>")
            links.append(f"<link type='image/jpeg' href='{escape(thumb)}' rel='http://opds-spec.org/image/thumbnail'/>")
        entries += f"""
        <entry>
            <title>{title}</title>
            <author><name>{author}</name></author>
            <id>urn:zlib:popular:{escape(str(book_id))}</id>
            <updated>{now_iso()}</updated>
            <content type='text'>🔥 热门推荐 · 点击进入搜索下载</content>
            {"".join(links)}
        </entry>
        """

    if not entries.strip():
        entries = nav_entry(title="热门榜没有更多内容", entry_id=f"urn:zlib:popular:empty:{page}",
                            href="/opds", content="已经翻到最后一页")

    next_page = data.get("nextPage") if isinstance(data.get("nextPage"), int) else None
    extra_links = pagination_links("/opds/popular", {}, page, None, next_page)
    return build_feed(
        feed_id=f"urn:zlib:opds:popular:{page}",
        title="🔥 Z-Library Popular",
        self_href=page_href("/opds/popular", {}, page),
        entries=entries,
        extra_links=extra_links,
    )

@app.get("/opds/categories")
async def categories(credentials: HTTPBasicCredentials = Depends(verify_credentials)):
    """分类导航 feed（为 /opds/category/{subject} 提供入口）。"""
    await ensure_categories()
    entries = "\n".join(
        nav_entry(
            title=("📁 " if item["top"] else "└ ") + item["label"],
            entry_id=f"urn:zlib:category:{item['id']}",
            href=f"/opds/category/{item['id']}",
            content=item["label"],
        )
        for item in CATEGORY_ITEMS
    )
    if not entries.strip():
        entries = nav_entry(title="分类列表为空", entry_id="urn:zlib:category:empty",
                            href="/opds", content="分类页没有解析到内容")
    return build_feed(feed_id="urn:zlib:opds:categories", title="🗂️ Z-Library Categories",
                      self_href="/opds/categories", entries=entries)

@app.get("/opds/category/{subject}")
async def category_books(subject: str, page: int = Query(1, ge=1), credentials: HTTPBasicCredentials = Depends(verify_credentials)):
    """分类检索：subject 可以是分类 ID、分类名（data-name）或站点 slug。"""
    subject = unquote(subject).strip()
    if subject.isdigit():
        cat_id = subject
        path = f"/category/{subject}"
    else:
        await ensure_categories()
        cat_id = CATEGORY_IDS.get(subject.lower())
        if cat_id:
            path = f"/category/{cat_id}"
        else:
            logger.info(f"ℹ️ 分类 {subject} 不在分类索引里，按 slug 直接请求")
            path = f"/category/{quote(subject)}"
            cat_id = subject
    return await book_list_feed(
        feed_id=f"urn:zlib:opds:category:{cat_id}",
        title=f"🗂️ Z-Library Category: {subject}",
        path=path,
        params={},
        page=page,
        self_path=f"/opds/category/{quote(subject)}",
        self_params={},
    )

@app.get("/opds/author/{author}")
async def author_books(author: str, page: int = Query(1, ge=1), credentials: HTTPBasicCredentials = Depends(verify_credentials)):
    """作者浏览：站点没有独立的作者页，用作者名做关键词检索。"""
    keywords = " ".join(unquote(author).strip().split())
    return await book_list_feed(
        feed_id=f"urn:zlib:opds:author:{keywords.replace(' ', '-')}",
        title=f"✍️ Z-Library Author: {keywords}",
        path="/s/",
        params={"q": keywords},
        page=page,
        self_path=f"/opds/author/{quote(keywords)}",
        self_params={},
    )

def safe_content_disposition(upstream: str, content_type: str, book_id: str) -> str:
    """把上游的 Content-Disposition 转成 Starlette 可发的 ASCII 头。

    上游 filename 常带中文原文（如 filename="嵌入式C语言…"），Starlette 会按 latin-1
    编码响应头，直接转发必炸（UnicodeEncodeError → 500）。按 RFC 5987/6266 重写：
    ASCII 兜底 filename + filename*=UTF-8'' 百分比编码，浏览器两边都能正确显示中文名。
    """
    disp = upstream or ""
    filename = ""
    m = re.search(r"filename\*\s*=\s*(?:UTF-8|utf-8)''([^;\s]+)", disp)
    if m:
        filename = unquote(m.group(1))
    if not filename:
        m = re.search(r'filename\s*=\s*"([^"]+)"', disp) or re.search(r"filename\s*=\s*([^;\s]+)", disp)
        if m:
            filename = m.group(1).strip()
            if re.search(r"%[0-9A-Fa-f]{2}", filename):
                filename = unquote(filename)
    # 去掉头注入字符与路径分隔符（文件名来自上游，不可信）
    filename = (filename.replace("\\", "").replace('"', "").replace("/", "_")
                .replace("\r", "").replace("\n", "").strip())
    ext = ""
    if "." in filename:
        cand = filename.rsplit(".", 1)[-1][:10]
        if re.fullmatch(r"[A-Za-z0-9]{1,10}", cand):
            ext = cand.lower()
    if not ext:
        ext = {"application/epub+zip": "epub", "application/pdf": "pdf",
               "application/x-mobipocket-ebook": "mobi"}.get(
                   (content_type or "").lower().split(";")[0].strip(), "")
    tokens = re.findall(r"[A-Za-z0-9]+", filename)
    if tokens and ext and tokens[-1].lower() == ext:
        tokens = tokens[:-1]
    ascii_base = "_".join(tokens)[:60].strip("_") or f"book_{book_id}"
    ascii_name = ascii_base + (f".{ext}" if ext else "")
    header = f'attachment; filename="{ascii_name}"'
    if filename:
        header += f"; filename*=UTF-8''{quote(filename, safe='')}"
    return header


@app.get("/download")
async def download(token: str):
    try:
        book_id, path = token.split(":", 1)
        path = unquote(path)
    except ValueError:
        raise HTTPException(status_code=400, detail="无效的下载 token")

    logger.info(f"📥 Downloading {path} (book {book_id})")
    try:
        resp, _ = await zlib_get(path, timeout=120.0)
    except HTTPException:
        raise
    except Exception:
        logger.exception("Download failed")
        raise HTTPException(status_code=502, detail="下载请求失败（网络或站点错误）")

    logger.info(f"📦 Download response status: {resp.status_code}, content-type: {resp.headers.get('content-type')}")
    if resp.status_code != 200:
        raise HTTPException(status_code=resp.status_code, detail=f"Download failed with status {resp.status_code}")

    content_type = resp.headers.get("content-type", "")
    if "text/html" in content_type.lower():
        # 登录 cookie 失效时站点会返回登录页，直接保存会把 HTML 当成电子书
        logger.warning("⚠️ 下载返回了 HTML（登录 cookie 可能已失效）")
        raise HTTPException(
            status_code=403,
            detail="需要有效的 Z-Library 登录 cookie：请先运行 python zlib_opds_launcher.py 完成登录",
        )

    headers = {"Content-Disposition": safe_content_disposition(
        resp.headers.get("content-disposition", ""), content_type, book_id)}
    return Response(content=resp.content,
                    media_type=content_type or "application/octet-stream",
                    headers=headers)

@app.get("/opds/nyt-bestsellers")
async def nyt_bestsellers(request: Request, credentials: HTTPBasicCredentials = Depends(verify_credentials)):
    api_key = os.getenv("NYT_API_KEY")
    url = f"https://api.nytimes.com/svc/books/v3/lists/current/hardcover-nonfiction.json?api-key={api_key}"
    async with httpx.AsyncClient() as client:
        resp = await client.get(url)
        data = resp.json()

    books = data.get("results", {}).get("books", [])
    updated = datetime.utcnow().isoformat() + "Z"
    entries = ""
    for book in books:
        title = escape(book.get("title", "Untitled").strip())
        author = escape(book.get("author", "Unknown").strip())
        desc = escape(book.get("description", ""))
        img = escape(book.get("book_image", ""))
        search_url = escape(f"/opds/search?q={quote_plus(title)}")

        entries += f"""
        <entry>
            <title>{title}</title>
            <author><name>{author}</name></author>
            <id>{search_url}</id>
            <updated>{updated}</updated>
            <link rel='subsection' href='{search_url}' type='application/atom+xml'/>
            <content type='text'>{desc}</content>
            <link rel='http://opds-spec.org/image' href='{img}' type='image/jpeg'/>
            <link rel='http://opds-spec.org/image/thumbnail' href='{img}' type='image/jpeg'/>
        </entry>
        """

    feed = f"""<?xml version='1.0' encoding='utf-8'?>
<feed xmlns='http://www.w3.org/2005/Atom'>
  <title>NYT Bestsellers: Hardcover Nonfiction</title>
  <id>urn:zlib:opds:nyt-bestsellers</id>
  <updated>{updated}</updated>
  <link rel='self' href='/opds/nyt-bestsellers' type='application/atom+xml'/>
  <link rel='start' href='/opds/root.xml' type='application/atom+xml'/>
  {entries}
</feed>"""
    return Response(content=feed.strip(), media_type="application/atom+xml")
