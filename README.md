 

# 📖 Z-Library OPDS Proxy

本项目将 Z-Library 的内容包装为标准 OPDS Catalog，可以被各类阅读器（如 Marvin、Lithium、Aldiko、Moon+ Reader等）直接浏览和下载。

---

## 🛠 安装与环境初始化

### 1. 克隆项目

略，进入项目目录

### 2. 创建虚拟环境（推荐）

```bash
python3 -m venv .venv
source .venv/bin/activate  # macOS/Linux
# 或
.venv\Scripts\activate     # Windows
```

### 3. 安装依赖

```bash
pip install -r requirements.txt
```

*必要依赖包括：* `fastapi`, `httpx`, `beautifulsoup4`, `python-dotenv`, `uvicorn` 等。


###  **Playwright 安装浏览器引擎**

Playwright 是用来自动化登录 Z-Library 的，它需要额外安装浏览器驱动：


安装 Playwright Python SDK：

```bash
   pip install playwright
```

安装 playwright 浏览器驱动
```bash
playwright install
```

（此命令会下载 Chromium / Firefox / WebKit 三个浏览器的无头版本）

如果你只需要 Chromium，可以指定安装：

```bash
playwright install chromium
```

⚡ 注意：必须执行 playwright install，否则无法进行自动化登录操作。

> 若本机已安装 Chrome 或 Edge，脚本会自动回落到它们（`channel="chrome"` / `"msedge"`），
> 此时可以跳过 `playwright install`。

### 4. 配置 ` config.env `  # 明确指定路径
`

在项目根目录创建 `config.env` 文件，内容示例：

```bash
ZLIB_EMAIL= "your@email.com"
ZLIB_PASSWORD= "your_password"
 
NYT_API_KEY="仅当你需要使用NewYorkTimes功能时使用"

OPDS_USER="yourname"
OPDS_PASS="yourpass"

# ---- 以下为可选配置，不填则使用默认值 ----
ZLIB_BASE_URL="https://z-lib.gl"     # 站点入口（登录与抓取都用它）；启动时自动跟随 302 定位到当前可用镜像
ZLIB_PROXY=""                      # 可选代理，如 http://127.0.0.1:7890 或 socks5://127.0.0.1:1080
ZLIB_LOGIN_HEADLESS="1"            # 登录时是否无头运行浏览器；设 0 可看到页面（排查问题时很有用）
ZLIB_NEW_LANG=""                    # /opds/new 的语言过滤，留空=不过滤
ZLIB_NEW_YEAR_FROM=""               # /opds/new 的起始年份，留空=当前年份-1
ZLIB_MOSAIC_BATCH="20"              # /opds/popular 每页数量
```

用于Playwright自动登录提取Z-Lib登录cookie。

> ⚡ **注意：首次登录需要执行 playwright 自动登录工具，后续将使用本地缓存cookie，无需重复登录。**

---

## 🚀 启动服务

```bash
uvicorn main:app --host 0.0.0.0 --port 8000
```

启动后访问：

- OPDS Catalog根目录： `http://localhost:8000/opds`
- 示例搜索（如Python相关书籍）： `http://localhost:8000/opds/search?q=python`

可以在 OPDS 客户端添加 `http://your-server-ip:8000/opds` 作为书库源！

---

## 📚 OPDS 端点一览

| 端点 | 类型 | 说明 |
|:---- |:---- |:---- |
| `/opds` | 导航 | Catalog 入口（客户端填这个地址） |
| `/opds/root.xml` | 导航 | OPDS 根目录 |
| `/opds/search?q=python&page=1` | 书籍 | 关键词检索，带 `next/previous/first/last` 分页 |
| `/opds/popular?page=1` | 导航 | 热门推荐（站点 `mostpopular` 榜单，点击条目进入搜索下载） |
| `/opds/new?q=&page=1` | 书籍 | 新书推荐（`yearFrom` + `order=newest` 逼近「最新入库」，`q` 可选） |
| `/opds/categories` | 导航 | 分类目录索引（841 个分类，供下面两个端点导航） |
| `/opds/category/{subject}?page=1` | 书籍 | 分类检索：`subject` 可填分类 ID（`40`）、分类名（`architecture`）或 slug |
| `/opds/author/{author}?page=1` | 书籍 | 作者浏览：`/opds/author/Stephen%20King`（站点无独立作者页，实为按作者名检索） |
| `/opds/nyt-bestsellers` | 导航 | NYT 畅销榜（需要 `NYT_API_KEY`） |
| `/opds/opensearch.xml` | — | OpenSearch 描述，供客户端内置搜索框使用 |
| `/download?token=...` | — | 中转下载（书条目里的 acquisition 链接） |

---

## 🔑 第一次使用？登录并提取 Z-Lib Cookie

执行一次以下命令，自动登录并保存 cookie：

```bash
python zlib_opds_launcher.py
```

登录成功后，会生成 `zlib_cookies.json` 文件，供本地OPDS代理读取使用。

> 登录用的地址取自 `ZLIB_BASE_URL`（默认 `https://z-lib.gl`），脚本先用 httpx 直接 POST 登录（快路，约 5~15 秒），
> 并把 cookie 按**镜像域名**保存；`main.py` 再按域名后缀把 cookie 注入到镜像请求上，
> 两者域名一致，下载才会被认作已登录。

---

## 💡 注意事项

- **站点镜像与浏览器校验**：`z-lib.gl` 是当前默认入口（经实测可访问；`zlib.ch` 这类入口域名会把任意路径 302 到镜像首页，且常把客户端踢去 DNS 被污染的官方域名）。镜像前端还有一段 JS 工作量证明（SHA1）校验。本项目在首次请求时自动定位真实镜像并解出 `c_token` cookie，之后按 host 缓存复用，无需人工干预。若镜像失效，把 `ZLIB_BASE_URL` 换成其他入口即可。
- **被镜像「踢走」怎么办（重要）**：镜像会对它不认可的客户端回 `302` + 响应头 `x-redirect-type: unacceptable-client-type`，把请求转去官方域名（如 `zh.z-lib.sk`）。这些官方域名在部分网络下 **DNS 被污染**（解析到 Facebook / Dropbox 等无关 IP），根本连不上。此时本服务会**立即**返回 502 并说明原因，而不是干等超时。解决办法：在 `config.env` 里配置 `ZLIB_PROXY`（VPN/机场的本地代理端口）后重启，登录脚本与抓取都会走代理。
- **登录 cookie 与域名**：`zlib_cookies.json` 里的 `domain` 是浏览器实际登录的镜像域名（例如 `zh.swe101.ru`）。`main.py` 启动时会打印加载到的 cookie 域名；若打印的域名与当前镜像不一致，会出现「目录能看、下载 403」，重跑一次 `python zlib_opds_launcher.py` 即可。
- **`/opds/new` 的由来**：站点没有匿名可用的「最新入库」页面（`/new`、newest mosaic 均 404），因此用 `yearFrom`（默认当前年份-1）+ `order=newest` 组合逼近新书；匿名状态下站点的排序并不严格，结果仅供参考。
- **下载需要登录 cookie**：未登录或 cookie 失效时，站点会返回登录页 HTML，本服务会直接回 403 并提示重新登录，避免把 HTML 当成电子书保存。
- 本项目为教育研究用途，请勿用于商业行为。
- 访问Z-Lib需要有效账号，请妥善保管自己的账户信息。
- 请遵守所在地区法律法规，对于使用本代码所产生的后果，请自行评估并承担。

---

## 🛣 Roadmap

| 状态 | 任务 | 说明 |
|:------- |:---- |:---- |
| ✅ 完成 | 基础OPDS目录 | 兼容常见OPDS客户端 |
| ✅ 完成 | 搜索+分页功能（/opds/search） | 支持多关键词检索 |
| ✅ 完成 | Popular推荐（/opds/popular） | 走站点 `mostpopular` mosaic JSON，带分页与封面 |
| ✅ 完成 | 带登录cookie的中转下载 | 保证大部分文件能顺利下载 |
| ✅ 完成 | HTTP BasicAuth for OPDS | 防止被爬虫滥用 |
| ✅ 完成 | 支持Moon reader, 支持 KyBook 3 | 多客户端支持 |
| ✅ 完成 | support new york times best seller ranking list |  multiple sourcing |
| ✅ 完成 | `/opds/new` 新书推荐目录 | 站点无匿名新书列表，用 `yearFrom`+`order=newest` 逼近 |
| ✅ 完成 | `/opds/category/{subject}` 分类检索 | 支持分类 ID / 分类名 / slug，另有 `/opds/categories` 索引 |
| ✅ 完成 | `/opds/author/{author}` 作者浏览 | 通过作者名搜索 |
| 🆕 计划 | 基于 sertraline/zlibrary API 的搜索加速模式 | 高速但不稳定 |
| 🆕 计划 | 登录Cookie定时刷新 | 通过Playwright后台刷新登录状态 |
| ✅ 完成 | 镜像跳转/网络受限的容错 | 识别 `x-redirect-type` 踢人跳转，明确提示配置 `ZLIB_PROXY`，不再卡在超时 |
| 🆕 计划 | Docker打包 | 支持NAS/VPS一键部署 |
| ✅ 完成 | 下载异常容错 | 非 200 原样返回、登录失效明确提示、120s 超时与错误提示 |


---

> 💬 当前已支持常见OPDS客户端如 Marvin, Moon+ Reader, Librera等兼容访问。

