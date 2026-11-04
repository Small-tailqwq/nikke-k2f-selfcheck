"""本地 HTML 报告：仅渲染脱敏元信息和聚合计数。"""

from html import escape


SCANNER_URL = "https://github.com/Sheisback/nikke_malware_scanner"
CATEGORIES = (
    "浏览器", "AI 工具", "云服务与运维", "软件包与 CI", "Git 与代码托管",
    "SSH、GPG 与密钥", "数据库与数据存储", "编辑器与插件", "Shell 历史与配置",
    "其他开发工具", "普通目录", "程序与辅助文件",
)
KINDS = {
    "credential": "鉴权数据位置", "key_material": "可能含密钥的目录或匹配项",
    "config": "可能含鉴权信息的配置或存储", "browser": "浏览器资料目录",
    "general": "普通目录", "program": "程序与辅助文件",
}
STATUS = {
    "present": "存在", "absent": "未发现", "unreadable": "无法检查",
    "skipped": "未检查（非本地路径、重解析点或环境变量缺失）",
    "partial": "检查不完整", "read": "已读取主库快照",
}
AUTH_KINDS = {"credential", "key_material", "config"}
ROTATE = "如怀疑设备曾被入侵，请检查相关服务的登录活动，并撤销或轮换该位置可能涉及的凭据；配置文件和历史记录中是否存在凭据需自行核实。"
ACTIONS = {
    "AI 工具": "撤销 AI 服务的登录会话、OAuth 授权和 API Key，重新生成所需密钥并更新工具配置。",
    "云服务与运维": "撤销访问令牌、云访问密钥和服务账号凭据，轮换部署及集群访问凭据。",
    "软件包与 CI": "撤销包仓库发布令牌和 CI 凭据，更新构建、部署与容器仓库使用的密钥。",
    "Git 与代码托管": "撤销个人访问令牌和 CLI 登录授权，检查代码托管平台的登录活动。",
    "SSH、GPG 与密钥": "替换可能暴露的密钥对，并在服务器或服务端移除旧公钥、撤销旧凭据；仅修改本地口令不足以撤销已复制的密钥。",
    "数据库与数据存储": "轮换数据库密码、访问令牌及连接凭据，检查相关账号的访问记录。",
    "编辑器与插件": "撤销编辑器、插件及 MCP 服务的令牌和授权，更新相关配置中的凭据。",
    "Shell 历史与配置": "自行核对历史命令和启动配置中是否写入过密码或令牌，撤销或轮换涉及的凭据。",
    "其他开发工具": "检查对应服务的登录活动，撤销或轮换可能存放于这些位置的令牌、密码和密钥。",
}


def e(value):
    return escape(str(value), quote=True)


def number(value):
    return value if type(value) is int and value >= 0 else 0


def hit(item):
    return item.get("status") in ("present", "matched") or number(item.get("matches")) > 0


def status(item):
    if item.get("status") == "matched":
        return "匹配 %d 项" % number(item.get("matches"))
    if item.get("status") == "partial":
        return "检查不完整（已匹配 %d 项）" % number(item.get("matches"))
    return STATUS.get(item.get("status"), "未检查")


def badge(label, tone="neutral"):
    return '<span class="badge ' + tone + '">' + e(label) + "</span>"


def target_table(items, registry=False):
    rows = []
    for item in sorted(items, key=lambda x: (not hit(x), x.get("template", x.get("key", "")))):
        kind = item.get("kind", "config")
        privacy = "未读取（已隐藏）" if kind in AUTH_KINDS else "不适用"
        label = item.get("key", "") if registry else item.get("template", "")
        state = status(item)
        if registry:
            hives = [h for h in item.get("hives", []) if h in ("HKCU", "HKLM")]
            state += (" · " + "/".join(hives)) if hives else ""
            if item.get("partial"):
                state += " · 部分根键无法检查"
        tone = "warn" if kind in AUTH_KINDS and hit(item) else "neutral"
        rows.append('<tr><td><code>' + e(label) + '</code><small>' + e(KINDS.get(kind, KINDS["config"]))
                    + '</small></td><td>' + badge(state, tone) + '</td><td class="privacy">' + e(privacy) + '</td></tr>')
    return ('<div class="table-scroll"><table><thead><tr><th>目标模板</th><th>检查结果</th>'
            '<th>鉴权内容</th></tr></thead><tbody>' + "".join(rows) + '</tbody></table></div>')


def render_browsers(report):
    databases = report.get("databases", [])
    counted = [d for d in databases if "counts" in d]
    totals = {name: sum(number(d["counts"].get(name)) for d in counted)
              for name in ("total", "v10", "v20", "other", "empty", "plain")}
    alerts = []
    if totals["v10"]:
        alerts.append('<div class="alert danger"><strong>最高优先级 · v10 高风险</strong><p>检测到 '
                      + str(totals["v10"]) + ' 条 v10 浏览器密码或 Cookie。若恶意程序曾以当前用户身份运行，'
                      '这类数据可能被解密并用于访问账号。请优先检查受影响账号，在可信设备退出其他会话、'
                      '修改密码，并启用或检查多因素认证。</p></div>')
    if totals["plain"]:
        alerts.append('<div class="alert danger"><strong>高风险 · 未加密 Cookie</strong><p>检测到 '
                      + str(totals["plain"]) + ' 条以未加密形式存放的 Cookie。请优先检查相关账号并撤销可疑会话。</p></div>')
    if totals["v20"]:
        alerts.append('<div class="alert info"><strong>v20 · 相对较低，仍需关注</strong><p>检测到 '
                      + str(totals["v20"]) + ' 条 v20 浏览器密码或 Cookie。应用绑定保护提高了窃取门槛；相对 v10，'
                      '这类数据通常更难解密或利用，但仍可能受其他攻击方式影响。若怀疑发生入侵，'
                      '请检查账号活动并撤销可疑会话。</p></div>')
    if totals["other"]:
        alerts.append('<p class="notice">有 ' + str(totals["other"]) + ' 条记录使用未识别或旧格式，'
                      '无法据此判断保护强度；请按可能暴露的数据核查。</p>')
    if report.get("skip_counts"):
        alerts.append('<p class="notice">未检查浏览器数据库：本次运行跳过了加密版本统计。</p>')
    elif not counted:
        alerts.append('<p class="notice">没有可统计的浏览器数据库结果。请查看下方覆盖范围及无法检查的项目。</p>')
    if any(d.get("status") == "partial" for d in databases):
        alerts.append('<p class="notice">部分数据库有 WAL 或读取期间发生变化，统计不完整。表格仅表示已读主库快照；'
                      '可在正常关闭浏览器后重新运行。</p>')
    if counted and not totals["v10"]:
        alerts.append('<p class="muted">已读主库快照未统计到 v10；请同时查看未检查、无法检查和不完整项。</p>')
    rows = []
    missing = 0
    for item in databases:
        if item.get("status") == "absent":
            missing += 1
            continue
        title = e(item.get("browser", "")) + ' · ' + e(item.get("profile", ""))
        store = "密码" if item.get("store") == "passwords" else "Cookie"
        state = STATUS.get(item.get("status"), "未检查")
        counts = item.get("counts")
        cells = "".join('<td class="num ' + ("red" if k in ("v10", "plain") and counts and number(counts.get(k)) else "") + '">'
                        + (str(number(counts.get(k))) if counts else "—") + '</td>'
                        for k in ("total", "v10", "v20", "plain", "other", "empty"))
        rows.append('<tr><td><b>' + title + '</b><small>' + store + ' · ' + e(item.get("database", ""))
                    + '</small><small>' + e(state) + '</small></td>' + cells + '</tr>')
    if rows:
        alerts.append('<div class="table-scroll"><table class="browser-table"><thead><tr><th>浏览器 / 数据类型</th>'
                      '<th>总数</th><th>v10</th><th>v20</th><th>未加密</th><th>未知 / 旧格式</th><th>空值</th></tr></thead><tbody>'
                      + "".join(rows) + '</tbody></table></div>')
    if missing:
        alerts.append('<details><summary>未发现的数据库位置 · ' + str(missing) + ' 项</summary><ul>'
                      + "".join('<li>' + e(d["browser"]) + ' · ' + e(d["profile"]) + ' · '
                                + e(d["database"]) + '</li>' for d in databases if d.get("status") == "absent")
                      + '</ul></details>')
    alerts.append('<div class="coverage">' + "".join('<span>' + e(c.get("browser", "")) + '：'
                  + e("已发现标准配置" if c.get("status") == "present" else
                      "未发现标准配置" if c.get("status") == "absent" else "无法检查") + '</span>'
                  for c in report.get("coverage", [])) + '</div>')
    alerts.append('<p class="muted">仅统计 Windows Chromium 的密码和 Cookie 数据；每条记录只归入一类，'
                  '未加密 Cookie 优先计数。空值表示对应记录没有可统计的鉴权值。Firefox 仅检查资料目录，'
                  '不检查加密类型。自定义资料目录、便携版及其他浏览器未覆盖。</p>')
    return "".join(alerts), totals, bool(counted)


def render_report(report):
    results = report.get("results", [])
    registry = report.get("registry", [])
    browser_html, totals, counted = render_browsers(report)
    auth_count = sum(hit(r) and r.get("kind", "config") in AUTH_KINDS for r in results) + sum(hit(r) for r in registry)
    incomplete = sum(r.get("status") in ("unreadable", "skipped", "partial") for r in results + registry + report.get("databases", []) + report.get("coverage", []) + report.get("wallets", []))
    incomplete += sum(bool(r.get("partial")) for r in registry)
    nav = ['<a href="#browser-risk">浏览器风险<span>01</span></a>', '<a href="#wallets">钱包<span>02</span></a>']
    sections = []
    categories = list(CATEGORIES)
    if any(r.get("report_category") not in CATEGORIES for r in results):
        # 未标注的自定义清单使用保守分类，不按来源索引猜测鉴权类型。
        results = [dict(r, report_category=r.get("report_category") if r.get("report_category") in CATEGORIES else "其他开发工具") for r in results]
    for index, category in enumerate(categories, 3):
        items = [r for r in results if r.get("report_category") == category]
        if not items and not (category == "SSH、GPG 与密钥" and registry):
            continue
        found = [r for r in items if hit(r)]
        rest = [r for r in items if not hit(r)]
        section_id = "category-" + str(index)
        nav.append('<a href="#' + section_id + '">' + e(category) + '<span>' + str(len(found)) + '</span></a>')
        body = '<div class="section-head"><h2>' + e(category) + '</h2><span>' + str(len(found)) + ' / ' + str(len(items)) + ' 模板命中</span></div>'
        if any(r.get("kind", "config") in AUTH_KINDS for r in found):
            body += '<div class="action"><b>鉴权信息 · 建议核查与轮换</b><p>' + e(ROTATE) + '</p>'
            if category in ACTIONS:
                body += '<p>' + e(ACTIONS[category]) + '</p>'
            body += '</div>'
        elif category == "普通目录":
            body += '<p class="muted">普通目录可能包含各类文件，目录存在不代表发现鉴权信息。</p>'
        elif category == "程序与辅助文件":
            body += '<p class="muted">这是程序或辅助位置，存在不代表发现鉴权信息。</p>'
        elif category == "浏览器":
            body += '<p class="muted">资料目录存在性与上方数据库统计分开呈现；目录存在不能说明加密版本。</p>'
        body += target_table(found) if found else '<p class="empty">本类没有已命中的目标模板。</p>'
        if rest:
            body += '<details><summary>其余检查结果 · ' + str(len(rest)) + ' 项</summary>' + target_table(rest) + '</details>'
        if category == "SSH、GPG 与密钥" and registry:
            body += '<h3>注册表中的配置位置</h3><p class="muted">检查 HKCU / HKLM；仅判断键是否存在，不读取键值。' + e(ROTATE) + '</p>' + target_table(registry, registry=True)
        sections.append('<section id="' + section_id + '">' + body + '</section>')

    wallets = report.get("wallets", [])
    if report.get("skip_wallets"):
        wallet_html = '<p class="empty">未检查钱包扩展：本次使用快速模式。</p>'
    elif wallets:
        wallet_html = '<p>检测到钱包扩展位置或无法检查的项目。如怀疑发生入侵，请在可信设备检查钱包及近期交易，并按钱包提供方指引处理。</p><ul class="wallet-list">'
        wallet_html += "".join('<li><b>' + e(w.get("browser", "")) + ' · ' + e(w.get("profile", "")) + '</b> '
                               + badge(status(w)) + '<code>' + e(w.get("id", "")) + '</code></li>' for w in wallets) + '</ul>'
    else:
        wallet_html = '<p class="empty">在已完成检查的标准配置中，未匹配到清单内的钱包扩展目录。</p>'
    wallet_html += '<p class="muted">覆盖上方列出的 Chromium 浏览器标准配置。仅检查扩展目录，不读取钱包内容；目录匹配不表示存在资产或已泄露。</p>'
    metrics = ((str(totals["v10"]) if counted else "—", "v10 记录", "danger"),
               (str(totals["v20"]) if counted else "—", "v20 记录", ""),
               (str(auth_count), "需核查的鉴权目标", ""), (str(incomplete), "未完成检查项", ""))
    return '''<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<meta name="referrer" content="no-referrer"><title>K2F 泄露面模拟报告</title>
<style>''' + CSS + '''</style></head><body>
<a class="skip" href="#main">跳转到报告内容</a>
<aside><div class="brand">K2F<span>本地自查</span></div><div class="nav-title">报告目录</div><nav>''' + "".join(nav) + '''
<a href="#scope">检查范围<span>↗</span></a></nav><div class="aside-note">本地生成<br>无外部资源 · 无数据上传</div></aside>
<main id="main"><header><div class="eyebrow"><span>本地报告</span></div>
<h1>K2F 泄露面模拟报告</h1><p class="timestamp">生成于 ''' + e(report.get("generated_at", "")) + '''</p>
<p class="scope-intro">本工具根据已知采集目标模拟本机可能暴露的数据位置，仅供了解风险。目标存在不代表数据已被读取或外传。本工具不排查或担保真实泄露。</p>
<a class="scanner-link" href="''' + SCANNER_URL + '''" target="_blank" rel="noopener noreferrer">另行检查运行痕迹：nikke_malware_scanner ↗</a></header>
<div class="metrics">''' + "".join('<div class="metric ' + tone + '"><span>' + label + '</span><strong>' + value + '</strong></div>' for value, label, tone in metrics) + '''</div>
<p class="metric-note">浏览器数量来自已读主库；“—”表示未获得统计。鉴权目标按命中的模板或注册表键计数，并非凭据数量；模板之间可能重叠。</p>
<section id="browser-risk"><div class="section-head"><h2>浏览器风险</h2><span>密码 / Cookie</span></div>''' + browser_html + '''</section>
<section id="wallets"><div class="section-head"><h2>钱包</h2><span>扩展位置</span></div>''' + wallet_html + '''</section>''' + "".join(sections) + '''
<section id="scope"><h2>检查范围与隐私</h2><p>脚本在本机读取浏览器数据库以统计加密版本，不解密、不展示鉴权值。其他目标仅检查路径或键是否存在；报告不包含鉴权明文，不向外发送数据。</p>
<ul><li>浏览器统计覆盖 Chrome、Edge、Brave、Vivaldi、Opera 的 Default 和 Profile N 配置，另含 Opera 根配置。仅检查当前用户的已知位置。</li>
<li>数据库只在内存中分析主库快照，不复制到磁盘、不读取 Local State 中的密钥。WAL 或并发变化会标记为统计不完整；超过 512 MiB、锁定或不支持的数据库标为无法检查。</li>
<li>网络路径、映射网络驱动器和重解析点不在检查范围内。权限不足、跳过和不支持的项目不能当作零条数据。</li>
<li>鉴权文件内容不会被打开、预览或嵌入报告；报告只显示模板和固定隐藏标记，不包含主机名、账号、域名、Cookie 名称、令牌或私钥。</li>
<li>HTML 不含脚本、远程字体、图片或自动请求。外部项目链接仅在主动点击时访问；请勿把报告放在同步目录或公开位置。</li></ul>
<p>需要另行检查运行痕迹时，可参考 <a href="''' + SCANNER_URL + '''" target="_blank" rel="noopener noreferrer">Sheisback/nikke_malware_scanner</a>。本报告不判断真实泄露，也不提供未感染或未泄露担保。</p></section>
<footer>K2F · 本地泄露面模拟<span>请在可信设备上处理凭据和账号授权。</span></footer></main></body></html>'''


CSS = r"""
:root{color-scheme:light;--bg:#f5f4f0;--card:#fff;--ink:#222a32;--muted:#69727b;--line:#e4e6e7;--red:#b52c35;--blue:#264f6d}
*{box-sizing:border-box}html{scroll-behavior:smooth;scroll-padding-top:24px}body{margin:0;background:var(--bg);color:var(--ink);font-family:"Segoe UI","Microsoft YaHei",sans-serif;font-size:14px;line-height:1.7}a{color:var(--blue);text-underline-offset:4px}a:focus-visible,summary:focus-visible{outline:3px solid #276c9e;outline-offset:4px}.skip{position:absolute;left:12px;top:-80px;background:white;padding:10px;z-index:10}.skip:focus{top:12px}
aside{position:fixed;inset:0 auto 0 0;width:242px;background:#eef0ed;border-right:1px solid #dedfdc;padding:36px 24px;display:flex;flex-direction:column;overflow:auto}.brand{font-size:28px;font-weight:800;letter-spacing:-1.5px}.brand span{font-size:12px;font-weight:500;letter-spacing:1px;margin-left:12px;color:var(--muted)}.nav-title{font-size:11px;color:var(--muted);letter-spacing:2px;margin:36px 0 12px}nav{display:grid;gap:3px}nav a{display:flex;justify-content:space-between;color:#4b555c;text-decoration:none;padding:7px 10px;border-radius:6px;font-size:13px}nav a:hover{background:#e0e4e0;color:#152b3a}nav a span{color:#7c858a;font-variant-numeric:tabular-nums}.aside-note{margin-top:auto;padding-top:30px;font-size:11px;color:#77817c}
main{max-width:1390px;margin-left:242px;padding:46px 52px 28px}header{max-width:940px}.eyebrow{font-size:11px;letter-spacing:2px;color:#6b7479;font-weight:600;display:flex;align-items:center;gap:16px}.eyebrow span{letter-spacing:0;border:1px solid #ced7d2;border-radius:30px;padding:3px 10px;color:#496257;font-weight:400}h1{font-size:clamp(30px,3.5vw,46px);line-height:1.3;letter-spacing:-1px;font-weight:650;margin:22px 0 14px}.subtitle{font-size:17px;margin:0;color:#5d6870}.timestamp{font-size:12px;color:#7c858b;margin:8px 0 22px}.scope-intro{max-width:800px;color:#515d64;margin:0 0 12px}.scanner-link{display:inline-block;font-size:13px}.metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-top:32px}.metric{border:1px solid var(--line);border-radius:10px;background:var(--card);padding:17px 22px;display:flex;flex-direction:column}.metric span{font-size:12px;color:#657079}.metric strong{font-size:36px;font-weight:600;line-height:1.4;font-variant-numeric:tabular-nums}.metric.danger{background:#fff5f4;border-color:#efc7c7}.metric.danger strong{color:var(--red)}.metric-note{font-size:11px;color:var(--muted);margin:10px 0 28px}
section{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:28px;margin-bottom:20px;scroll-margin-top:20px}.section-head{display:flex;align-items:center;justify-content:space-between;gap:20px;margin-bottom:18px}.section-head>span{color:var(--muted);font-size:12px;white-space:nowrap}h2{font-size:21px;letter-spacing:-.4px;margin:0;font-weight:650}h3{font-size:16px;margin:24px 0 8px}p{margin:10px 0}.alert{border-radius:8px;border-left:4px solid;padding:16px 20px;margin:12px 0}.alert strong{font-size:16px}.alert p{margin:6px 0 0}.alert.danger{background:#fff1ef;border-color:#c0393f;color:#84282d}.alert.info{background:#f0f5f8;border-color:#6a92ae;color:#37576e}.notice{background:#fff8e9;border:1px solid #eadbb7;border-radius:6px;padding:12px 16px;color:#79602a}.muted,.empty{color:var(--muted);font-size:13px}.empty{padding:6px 0}.action{border-left:3px solid #bf9a5a;background:#fcf8ee;padding:12px 16px;color:#715c36;margin-bottom:20px}.action p{font-size:13px;margin:5px 0}
.table-scroll{overflow-x:auto;margin-top:14px}table{border-collapse:collapse;width:100%;text-align:left;font-size:12px}th{font-weight:500;color:#6b747b;background:#f7f8f7;padding:11px 12px;border-bottom:1px solid var(--line);white-space:nowrap}td{padding:13px 12px;border-bottom:1px solid #eef0ef;vertical-align:top}td:first-child{width:53%}code{font-family:Consolas,"Cascadia Code",monospace;font-size:12px;overflow-wrap:anywhere;color:#364a58}small{display:block;font-size:11px;color:#7c858b;margin-top:5px}.privacy{color:#899198;white-space:nowrap}.badge{display:inline-block;border-radius:4px;background:#eff1f2;color:#69747b;font-size:11px;padding:3px 7px;white-space:normal}.badge.warn{background:#faf0d9;color:#806229}.browser-table{min-width:690px}.browser-table td:first-child{width:36%}.num{text-align:right;font-variant-numeric:tabular-nums;font-size:14px}.red{color:var(--red);font-weight:700}details{margin-top:14px}summary{cursor:pointer;color:#58656f;font-size:12px;padding:10px 0}details[open]>summary{margin-bottom:5px}.coverage{display:flex;flex-wrap:wrap;gap:6px 16px;border-top:1px solid var(--line);margin-top:20px;padding-top:14px;font-size:11px;color:var(--muted)}ul{padding-left:21px}li{margin:8px 0}.wallet-list{list-style:none;padding:0}.wallet-list li{border-bottom:1px solid var(--line);padding:10px 0}.wallet-list code{display:block;margin-top:5px}#scope p,#scope li{font-size:13px;color:#637079}#scope h2{margin-bottom:16px}footer{display:flex;justify-content:space-between;gap:20px;color:#8a9399;font-size:11px;padding:8px 0 20px}
@media(min-width:1600px){main{margin-left:calc(242px + (100vw - 1600px)/2)}}
@media(max-width:1100px){aside{width:205px;padding:30px 18px}main{margin-left:205px;padding:32px 24px}.metric{padding:14px}section{padding:22px}}
@media(max-width:760px){aside{position:static;width:auto;padding:18px 20px;border-right:0;border-bottom:1px solid var(--line)}.brand{font-size:24px}.nav-title,.aside-note{display:none}nav{display:flex;overflow:auto;margin-top:12px;padding-bottom:2px}nav a{white-space:nowrap;gap:12px;background:#e4e8e4;font-size:11px}nav a span{display:none}main{margin:0;padding:26px 16px}.eyebrow{font-size:9px;gap:10px}h1{font-size:32px}.metrics{grid-template-columns:repeat(2,1fr);gap:10px;margin-top:24px}.metric strong{font-size:30px}section{padding:18px 14px;border-radius:9px}.section-head{gap:10px}.section-head>span{font-size:10px}h2{font-size:19px}table{min-width:600px}.alert{padding:13px 14px}footer{display:block}footer span{display:block;margin-top:5px}}
@media(prefers-reduced-motion:reduce){html{scroll-behavior:auto}}
@media print{aside,.skip{display:none}main{margin:0;padding:0;max-width:none}body{background:white;font-size:11px}section{border-radius:0;break-inside:avoid;padding:16px}.metrics{margin-top:16px}.table-scroll{overflow:visible}table,.browser-table{min-width:0}h1{font-size:30px}a{color:inherit}}
"""
