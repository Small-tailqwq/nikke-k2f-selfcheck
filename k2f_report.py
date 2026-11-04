"""本地 HTML 报告：渲染脱敏定位元信息、聚合计数和可展开明细。页面不含脚本和外部资源。"""

from html import escape


REPORT_ICON = 'data:image/jpeg;base64,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'
SCANNER_URL = "https://github.com/Sheisback/nikke_malware_scanner"
CATEGORIES = (
    "浏览器", "AI 工具", "云服务与运维", "软件包与 CI", "Git 与代码托管",
    "SSH、GPG 与密钥", "数据库与数据存储", "编辑器与插件", "Shell 历史与配置",
    "其他开发工具", "普通目录", "程序与辅助文件",
)
KINDS = {
    "credential": "凭据文件", "key_material": "密钥", "config": "配置",
    "browser": "浏览器资料", "general": "普通目录", "program": "程序文件",
}
STATUS = {
    "present": "存在", "absent": "未发现", "unreadable": "无法检查",
    "skipped": "未检查", "partial": "不完整", "read": "已读取",
}
REASONS = {
    "unreadable": "无法检查：权限不足、文件被锁定或格式不支持",
    "skipped": "未检查：网络路径、重解析点或缺少环境变量",
}
AUTH_KINDS = {"credential", "key_material", "config"}
ACTIONS = {
    "AI 工具": "在各 AI 工具中退出并重新登录，到服务后台撤销 OAuth 授权，删除并重新生成 API Key。",
    "云服务与运维": "撤销云平台访问密钥、令牌和服务账号密钥，重新生成 kubeconfig 等集群凭据。",
    "软件包与 CI": "撤销 npm、PyPI 等包仓库的发布令牌和 CI 密钥，更新构建与部署中使用的凭据。",
    "Git 与代码托管": "撤销个人访问令牌和 CLI 授权，检查代码托管平台的登录记录与已登记的 SSH 密钥。",
    "SSH、GPG 与密钥": "生成新密钥对，在服务器和代码平台上删除旧公钥，吊销旧 GPG 密钥。只修改私钥口令无法让已复制的密钥失效。",
    "数据库与数据存储": "修改数据库密码，轮换连接串和访问令牌。",
    "编辑器与插件": "退出编辑器账号和插件登录，撤销插件与 MCP 服务使用的令牌。",
    "Shell 历史与配置": "检查历史记录和启动脚本中是否出现过密码或令牌；出现过的全部轮换，再删除对应记录。",
    "其他开发工具": "逐个工具重新登录，并撤销旧令牌。",
}
# (计数键, 色调, 名称, 等级, 处理建议)；顺序即页面优先级。
RISKS = (
    ("v10", "crit", "v10", "高风险",
     "以当前用户身份运行的程序可直接解密。逐个处理下列站点：在可信设备上修改密码、退出其他设备的登录、开启两步验证。"),
    ("plain", "crit", "未加密 Cookie", "高风险",
     "Cookie 以明文保存，复制后即可使用。在对应站点退出登录，使这些会话失效。"),
    ("other", "warn", "未知格式", "待核实",
     "加密前缀不是 v10 或 v20，无法判断保护方式，按 v10 处理。"),
    ("v20", "info", "v20", "较低",
     "受应用绑定加密保护，需提权或注入浏览器进程才能解密。处理完 v10 后，再退出重要站点的登录。"),
    ("empty", "none", "空值", "无需处理", "记录中没有保存密码或 Cookie 值。"),
)
COUNT_KEYS = ("total", "v10", "v20", "other", "empty", "plain")
# 长列表按固定行高分块，离屏分块由 content-visibility 跳过样式、布局和绘制。
CHUNK = 100
ROW_HEIGHT = 34


def e(value):
    return escape(str(value), quote=True)


def number(value):
    return value if type(value) is int and value >= 0 else 0


def fmt(value):
    return "{:,}".format(number(value))


def hit(item):
    return item.get("status") in ("present", "matched") or number(item.get("matches")) > 0


def status(item):
    if item.get("status") == "matched":
        return "匹配 %s 项" % fmt(item.get("matches"))
    if item.get("status") == "partial":
        return "不完整，已匹配 %s 项" % fmt(item.get("matches"))
    return STATUS.get(item.get("status"), "未检查")


def where(database):
    return (str(database.get("browser", "")) + " " + str(database.get("profile", ""))).strip()


def store_name(database):
    return "密码" if database.get("store") == "passwords" else "Cookie"


def row(*cells):
    return '<div class="row"><span>' + "</span><span>".join(cells) + "</span></div>"


def rows(columns, head, body):
    out = ['<div class="list ', columns, '"><div class="row head"><span>', "</span><span>".join(head), "</span></div>"]
    for start in range(0, len(body), CHUNK):
        part = body[start:start + CHUNK]
        out.append('<div class="chunk" style="contain-intrinsic-size:auto %dpx">' % (len(part) * ROW_HEIGHT))
        out.extend(part)
        out.append("</div>")
    out.append("</div>")
    return "".join(out)


def state(label, tone):
    return '<i class="st ' + tone + '">' + e(label) + "</i>"


def record_lists(pairs):
    passwords = sorted((r.get("site") or "站点未知", r.get("identifier") or "未填写", where(d))
                       for d, r in pairs if d.get("store") == "passwords")
    cookies = {}
    for database, record in pairs:
        if database.get("store") == "passwords":
            continue
        entry = cookies.setdefault(record.get("site") or "站点未知", [0, []])
        entry[0] += 1
        if where(database) not in entry[1]:
            entry[1].append(where(database))
    html = ""
    if passwords:
        html += ('<h4>已保存的密码<span>' + fmt(len(passwords)) + ' 条</span></h4>'
                 + rows("cols-pw", ("站点", "账号（脱敏）", "浏览器"),
                        [row(e(site), "<code>" + e(account) + "</code>", e(browser)) for site, account, browser in passwords]))
    if cookies:
        ordered = sorted(cookies.items(), key=lambda item: (-item[1][0], item[0]))
        html += ('<h4>Cookie<span>' + fmt(sum(c for c, _ in cookies.values())) + ' 条 · '
                 + fmt(len(ordered)) + ' 个站点</span></h4>'
                 + rows("cols-ck", ("站点", "数量", "浏览器"),
                        [row(e(site), fmt(count), e("、".join(browsers))) for site, (count, browsers) in ordered]))
    return html


def database_state(database):
    if database.get("status") == "partial":
        return "不完整（WAL）" if database.get("wal") else "不完整"
    return STATUS.get(database.get("status"), "未检查")


def render_browsers(report):
    databases = report.get("databases", [])
    counted = [d for d in databases if isinstance(d.get("counts"), dict)]
    totals = {key: sum(number(d["counts"].get(key)) for d in counted) for key in COUNT_KEYS}
    records = {key: [] for key in COUNT_KEYS}
    for database in databases:
        for record in database.get("records", []):
            if record.get("encryption") in records:
                records[record["encryption"]].append((database, record))
    sites = {key: len({r.get("site") for _, r in pairs}) for key, pairs in records.items()}

    parts = []
    if report.get("skip_counts"):
        parts.append('<p class="note">未检查浏览器数据库：本次使用了 --quick 或 --no-browser-count。</p>')
    elif not counted:
        parts.append('<p class="note">没有读到浏览器数据库，原因见<a href="#incomplete">未完成检查</a>。</p>')
    elif not any(totals[key] for key in ("v10", "plain", "other", "v20")):
        parts.append('<p class="clear">已读取的数据库中没有 v10、v20、未加密或未知格式的记录。</p>')
    if any(d.get("status") == "partial" for d in databases):
        parts.append('<p class="note">统计不完整：部分数据库有未合并的 WAL 或在读取时被写入，数量可能偏少。'
                     '关闭浏览器后重新运行可得到完整结果。</p>')
    for key, tone, name, level, action in RISKS:
        if not totals[key]:
            continue
        meta = fmt(totals[key]) + " 条" + (" · " + fmt(sites[key]) + " 个站点" if records[key] else "")
        parts.append('<div class="risk ' + tone + '" id="risk-' + key + '"><div class="risk-head"><b>' + e(name)
                     + '</b><span class="level">' + e(level) + '</span><span class="n">' + meta + '</span></div><p>'
                     + e(action) + '</p>'
                     + ('<details><summary>查看明细</summary>' + record_lists(records[key]) + '</details>' if records[key] else '')
                     + '</div>')

    listed = [d for d in databases if d.get("status") != "absent"]
    if listed:
        body = []
        for database in listed:
            counts = database.get("counts") if isinstance(database.get("counts"), dict) else None
            cells = []
            for key in ("total", "v10", "v20", "plain", "other", "empty"):
                value = number(counts.get(key)) if counts else None
                text = "—" if value is None else fmt(value)
                cells.append('<b class="hot">' + text + '</b>' if key in ("v10", "plain") and value else text)
            body.append(row(e(where(database)), store_name(database), e(database_state(database)), *cells))
        missing = len(databases) - len(listed)
        parts.append('<details class="databases"><summary>按数据库查看 · ' + fmt(len(listed)) + ' 个'
                     + ('，另有 ' + fmt(missing) + ' 个不存在' if missing else '') + '</summary>'
                     + rows("cols-db", ("浏览器", "类型", "状态", "总数", "v10", "v20", "未加密", "未知", "空值"), body)
                     + '</details>')
    coverage = report.get("coverage", [])
    if coverage:
        labels = {"present": "已检查", "absent": "未找到资料"}
        parts.append('<p class="coverage">' + " · ".join(
            e(c.get("browser", "")) + " " + labels.get(c.get("status"), "无法检查") for c in coverage) + '</p>')
    return "".join(parts), totals, bool(counted), sites, records


def target_items(report):
    items = []
    for result in report.get("results", []):
        category = result.get("report_category")
        # 未标注的自定义清单使用保守分类，不按来源索引猜测鉴权类型。
        items.append({"label": result.get("template", ""), "kind": result.get("kind", "config"),
                      "category": category if category in CATEGORIES else "其他开发工具",
                      "status": status(result), "hit": hit(result), "source": result,
                      "incomplete": result.get("status") in ("unreadable", "skipped", "partial")})
    for entry in report.get("registry", []):
        label = status(entry)
        hives = [h for h in entry.get("hives", []) if h in ("HKCU", "HKLM")]
        if hives:
            label += " · " + "/".join(hives)
        items.append({"label": entry.get("key", ""), "kind": entry.get("kind", "config"), "registry": True,
                      "category": "SSH、GPG 与密钥", "status": label, "hit": hit(entry), "source": entry,
                      "incomplete": entry.get("status") in ("unreadable", "skipped") or bool(entry.get("partial"))})
    return items


def target_rows(items):
    ordered = sorted(items, key=lambda i: (not i["hit"], not i["incomplete"], i["label"]))
    return rows("cols-t", ("位置", "类型", "结果"), [
        row("<code>" + e(i["label"]) + "</code>", "注册表键" if i.get("registry") else e(KINDS.get(i["kind"], KINDS["config"])),
            state(i["status"], "hit" if i["hit"] else "inc" if i["incomplete"] else "none"))
        for i in ordered])


def render_targets(items):
    auth = [i for i in items if i["kind"] in AUTH_KINDS]
    groups, quiet = [], []
    for category in CATEGORIES:
        members = [i for i in auth if i["category"] == category]
        if not members:
            continue
        found = [i for i in members if i["hit"]]
        rest = [i for i in members if not i["hit"]]
        count = '<span class="count">' + fmt(len(found)) + ' / ' + fmt(len(members)) + '</span>'
        if found:
            groups.append('<div class="group"><div class="group-head"><h3>' + e(category) + '</h3>' + count + '</div>'
                          + ('<p class="todo">' + e(ACTIONS[category]) + '</p>' if category in ACTIONS else '')
                          + target_rows(found)
                          + ('<details><summary>其余 ' + fmt(len(rest)) + ' 项</summary>' + target_rows(rest) + '</details>' if rest else '')
                          + '</div>')
        else:
            quiet.append('<details><summary>' + e(category) + count + '</summary>' + target_rows(members) + '</details>')
    found_total = sum(i["hit"] for i in auth)
    html = '<p class="lead">这些位置可能保存登录凭据、令牌或密钥。只检查了是否存在，没有打开文件。</p>' if auth else ''
    if auth and not found_total:
        html += '<p class="clear">清单内的凭据位置均未发现。</p>'
    html += "".join(groups)
    if quiet:
        html += '<div class="quiet"><h3>未发现</h3>' + "".join(quiet) + '</div>'
    other = [i for i in items if i["kind"] not in AUTH_KINDS]
    if other:
        html += ('<div class="quiet"><h3>非凭据位置</h3><details><summary>浏览器资料、普通目录与程序文件<span class="count">'
                 + fmt(sum(i["hit"] for i in other)) + ' / ' + fmt(len(other)) + '</span></summary><p class="lead">'
                 '浏览器资料中的密码和 Cookie 已在上方统计；用户目录和程序目录不是凭据位置，列出仅供对照。</p>'
                 + target_rows(other) + '</details></div>')
    if not items:
        html += '<p class="note">目标清单为空。</p>'
    return html, found_total, len({i["category"] for i in auth if i["hit"]})


def render_wallets(report):
    wallets = report.get("wallets", [])
    found = [w for w in wallets if hit(w)]
    if report.get("skip_wallets"):
        return '<p class="note">未检查钱包扩展：本次使用了 --quick。</p>', None
    html = ""
    if found:
        html += ('<p class="todo">扩展数据被复制后，可离线暴力破解钱包密码。钱包内有资产时，'
                 '新建钱包（新助记词）并转移资产。</p>')
    else:
        html += '<p class="clear">已检查的浏览器配置中没有清单内的钱包扩展。</p>'
    if wallets:
        html += rows("cols-w", ("浏览器", "扩展 ID", "结果"), [
            row(e(where(w)), "<code>" + e(w.get("id", "")) + "</code>",
                state(status(w), "hit" if hit(w) else "inc")) for w in wallets])
    return html, len(found)


def incomplete_items(report, items):
    out = []
    for item in items:
        if not item["incomplete"]:
            continue
        source = item["source"]
        if source.get("status") == "partial":
            reason = "不完整：遍历时出错，已匹配 " + fmt(source.get("matches")) + " 项"
        elif item.get("registry") and source.get("partial"):
            reason = "不完整：部分根键无法打开"
        else:
            reason = REASONS.get(source.get("status"), "未检查")
        out.append(("<code>" + e(item["label"]) + "</code>", reason))
    for database in report.get("databases", []):
        if database.get("status") == "partial":
            reason = "不完整：WAL 未合并或读取时被写入"
        elif database.get("status") in REASONS:
            reason = REASONS[database["status"]]
        else:
            continue
        out.append((e(where(database)) + " · " + e(database.get("database", store_name(database))), reason))
    for entry in report.get("coverage", []):
        if entry.get("status") not in ("present", "absent"):
            out.append((e(entry.get("browser", "")) + " 资料目录", REASONS["unreadable"]))
    for wallet in report.get("wallets", []):
        if wallet.get("status") in ("unreadable", "skipped", "partial"):
            out.append((e(where(wallet)) + " · 钱包 <code>" + e(wallet.get("id", "")) + "</code>",
                        REASONS.get(wallet["status"], "不完整")))
    return out


def summary_row(tone, label, value, meta, href):
    zero = value == 0
    return ('<a class="sum-row ' + ("zero" if zero or value is None else tone) + '" href="' + href + '"><span class="sum-label">'
            + e(label) + '</span><span class="sum-n">' + ("—" if value is None else fmt(value)) + '</span><span class="sum-meta">'
            + e("未检查" if value is None else meta) + '</span></a>')


def render_report(report):
    browser_html, totals, counted, sites, records = render_browsers(report)
    items = target_items(report)
    target_html, target_hits, target_groups = render_targets(items)
    wallet_html, wallet_hits = render_wallets(report)
    pending = incomplete_items(report, items)

    def browser_meta(key):
        return "条" + (" · " + fmt(sites[key]) + " 个站点" if records[key] else "")

    summary = [
        summary_row("crit", "v10 密码与 Cookie", totals["v10"] if counted else None, browser_meta("v10"),
                    "#risk-v10" if totals["v10"] else "#browser"),
        summary_row("crit", "未加密 Cookie", totals["plain"] if counted else None, browser_meta("plain"),
                    "#risk-plain" if totals["plain"] else "#browser"),
    ]
    if totals["other"]:
        summary.append(summary_row("warn", "未知格式记录", totals["other"], browser_meta("other"), "#risk-other"))
    summary += [
        summary_row("warn", "可能含凭据的位置", target_hits, "处" + (" · " + fmt(target_groups) + " 个分类" if target_hits else ""), "#auth"),
        summary_row("warn", "钱包扩展", wallet_hits, "个", "#wallets"),
        summary_row("info", "v20 密码与 Cookie", totals["v20"] if counted else None, browser_meta("v20"),
                    "#risk-v20" if totals["v20"] else "#browser"),
        summary_row("info", "未完成检查", len(pending), "项", "#incomplete"),
    ]
    pending_html = (rows("cols-inc", ("项目", "原因"), [row(name, e(reason)) for name, reason in pending])
                    if pending else '<p class="clear">所有项目均已完成检查。</p>')

    return '''<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'">
<meta name="referrer" content="no-referrer"><title>K2F 泄露面自查报告</title>
<link rel="icon" type="image/jpeg" href="''' + REPORT_ICON + '''">
<style>''' + CSS + '''</style></head><body>
<input type="checkbox" id="ack" class="ack" aria-label="我知道了，查看报告">
<div class="gate" role="dialog" aria-modal="true" aria-labelledby="gate-title"><div class="gate-box">
<h2 id="gate-title">关于这份报告</h2>
<p>我们分析了公开的 K2F 恶意程序样本，整理出它会扫描的文件、浏览器数据和钱包扩展，再用同样的扫描逻辑检查了这台电脑，生成了这份报告。</p>
<p>如果你确认电脑已经受到影响，请对照报告自查，尽快处理已暴露的内容：</p>
<ul><li>报告中列出站点的账号密码，以及其他用了相同密码的账号；</li>
<li>API Key、访问令牌和 SSH 密钥：撤销后重新生成；</li>
<li>AI 工具、代码托管和云服务的登录状态：退出登录并撤销旧授权。</li></ul>
<p>这份报告不能保证绝对准确，也无法判断你的数据是否已经泄露，请把它作为自查和处置的参考。</p>
<div class="gate-act"><span class="gate-wait"><span>请先阅读以上内容</span></span><label for="ack">我知道了，查看报告</label></div>
</div></div>
<a class="skip" href="#main">跳到报告内容</a>
<nav class="bar"><div><a href="#summary">摘要</a><a href="#browser">浏览器数据</a><a href="#auth">凭据位置</a><a href="#wallets">钱包</a><a href="#incomplete">未完成检查</a><a href="#about">说明</a></div></nav>
<main id="main">
<header class="head"><img class="mascot" src="''' + REPORT_ICON + '''" width="56" height="56" alt="笑脸表情"><div><h1>K2F 泄露面自查报告</h1><p class="meta">''' + e(report.get("generated_at", "")) + '''</p></div></header>
<p class="disclaimer">位置存在不等于数据已被读取或外传。检查运行痕迹请用 <a href="''' + SCANNER_URL + '''" target="_blank" rel="noopener noreferrer">nikke_malware_scanner</a>。</p>
<section id="summary" class="summary">''' + "".join(summary) + '''</section>
<section id="browser"><h2>浏览器数据<small>密码与 Cookie</small></h2>''' + browser_html + '''</section>
<section id="auth"><h2>凭据位置</h2>''' + target_html + '''</section>
<section id="wallets"><h2>钱包扩展</h2>''' + wallet_html + '''</section>
<section id="incomplete"><h2>未完成检查<small>''' + fmt(len(pending)) + ''' 项</small></h2>''' + pending_html + '''</section>
<section id="about"><h2>说明</h2><dl class="facts">
<dt>检查方式</dt><dd>普通目标只检查路径或注册表键是否存在，不打开文件，不读取键值。浏览器数据库以共享只读方式载入内存，只识别加密前缀，不解密。</dd>
<dt>报告内容</dt><dd>站点主机名、脱敏账号和 Cookie 数量。账号不超过 4 个字符时完全隐藏，否则只保留首尾字符。报告不含密码、Cookie 值、令牌或私钥，但站点列表仍属个人隐私，不要公开分享。</dd>
<dt>浏览器范围</dt><dd>Chrome、Edge、Brave、Vivaldi、Opera 的 Default 与 Profile N，Opera 另含根配置。Firefox 只检查资料目录。便携版和自定义资料目录不在范围内。</dd>
<dt>跳过的情况</dt><dd>网络路径、映射网络驱动器和重解析点不检查。超过 512 MiB 或被锁定的数据库记为无法检查；有未合并 WAL 的数据库只统计主库。</dd>
<dt>免责声明</dt><dd>本报告只反映 K2F 采集目标在本机的存在情况，不检测感染，也不能确认是否已泄露或未泄露。</dd>
</dl></section>
</main></body></html>'''


CSS = r"""
:root{color-scheme:light;--bg:#f7f7f5;--paper:#fff;--ink:#1d1f21;--sub:#5b6066;--faint:#949a9f;--line:#e4e4e0;--soft:#efefeb;--crit:#c0352b;--crit-bg:#fcefed;--warn:#95590a;--warn-bg:#fbf3e4;--link:#1d5c9a}
*{box-sizing:border-box}html{scroll-padding-top:60px}
body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.65 "Segoe UI","Microsoft YaHei UI","Microsoft YaHei",sans-serif}
a{color:var(--link);text-underline-offset:3px}:focus-visible{outline:2px solid var(--link);outline-offset:2px}
.skip{position:absolute;left:8px;top:-60px;background:var(--paper);padding:8px 12px;z-index:20}.skip:focus{top:8px}
.bar{position:sticky;top:0;z-index:10;background:var(--bg);border-bottom:1px solid var(--line)}
.bar div{max-width:1040px;margin:0 auto;padding:0 32px;height:44px;display:flex;align-items:center;gap:24px;overflow-x:auto}
.bar a{color:var(--sub);text-decoration:none;font-size:13px;white-space:nowrap}.bar a:hover{color:var(--ink)}
main{max-width:1040px;margin:0 auto;padding:36px 32px 72px}
.head{display:flex;align-items:center;gap:16px}.mascot{width:56px;height:56px;border-radius:10px;flex:none}
h1{font-size:24px;font-weight:600;line-height:1.3;margin:0}.meta{margin:2px 0 0;color:var(--faint);font-size:12.5px;font-variant-numeric:tabular-nums}
.disclaimer{max-width:780px;margin:18px 0 0;color:var(--sub);font-size:13px}
section{margin-top:44px}
h2{display:flex;align-items:baseline;gap:10px;margin:0 0 16px;padding-bottom:10px;border-bottom:1px solid var(--line);font-size:17px;font-weight:600}
h2 small{font-size:12.5px;font-weight:400;color:var(--faint)}
h3{margin:0;font-size:14.5px;font-weight:600}
h4{margin:16px 0 6px;font-size:13px;font-weight:600}h4 span{margin-left:8px;font-weight:400;color:var(--faint)}
p{margin:0 0 10px}
.summary{margin-top:28px;background:var(--paper);border:1px solid var(--line);border-radius:8px;overflow:hidden}
.sum-row{display:grid;grid-template-columns:3px minmax(0,1fr) auto 168px;align-items:center;gap:0 16px;height:46px;padding-right:18px;border-top:1px solid var(--soft);color:var(--ink);text-decoration:none}
.sum-row:first-child{border-top:0}.sum-row:hover{background:#fafaf8}
.sum-row::before{content:"";align-self:stretch}
.sum-row.crit::before{background:var(--crit)}.sum-row.warn::before{background:#d39a3c}.sum-row.info::before{background:#9db2c2}
.sum-n{font-size:19px;font-weight:600;text-align:right;font-variant-numeric:tabular-nums}
.crit .sum-n{color:var(--crit)}.warn .sum-n{color:var(--warn)}
.sum-meta{color:var(--faint);font-size:12.5px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.sum-row.zero{color:var(--faint)}.zero .sum-n{font-weight:400}
.risk{margin-bottom:10px;padding:14px 18px;background:var(--paper);border:1px solid var(--line);border-radius:8px}
.risk.crit{border-color:#eccdc8}.risk.none{background:transparent}
.risk-head{display:flex;flex-wrap:wrap;align-items:baseline;gap:10px}.risk-head b{font-size:15px}
.level{padding:0 8px;border-radius:999px;background:var(--soft);color:var(--sub);font-size:12px}
.crit .level{background:var(--crit-bg);color:var(--crit)}.warn .level{background:var(--warn-bg);color:var(--warn)}
.risk-head .n{margin-left:auto;color:var(--sub);font-variant-numeric:tabular-nums}
.risk p{margin:6px 0 0;color:var(--sub);font-size:13px}.risk details{margin-top:4px}
summary{cursor:pointer;list-style:none;padding:6px 0;color:var(--link);font-size:13px}
summary::-webkit-details-marker{display:none}
summary::before{content:"▸";display:inline-block;width:14px;color:var(--faint)}details[open]>summary::before{content:"▾"}
.list{background:var(--paper);border:1px solid var(--line);border-radius:6px;font-size:13px}
.row{display:grid;align-items:center;gap:0 14px;height:34px;padding:0 12px;border-top:1px solid var(--soft)}
.row>span{min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.row.head{position:sticky;top:44px;z-index:1;height:32px;border-top:0;border-radius:6px 6px 0 0;background:#fafaf8;color:var(--faint);font-size:12px}
.chunk{content-visibility:auto}
.cols-pw .row{grid-template-columns:minmax(0,1.4fr) minmax(0,1fr) minmax(0,1fr)}
.cols-ck .row{grid-template-columns:minmax(0,1.6fr) 72px minmax(0,1fr)}
.cols-ck .row>span:nth-child(2){text-align:right;font-variant-numeric:tabular-nums}
.cols-db .row{grid-template-columns:minmax(0,1.2fr) 56px minmax(0,1fr) repeat(6,56px)}
.cols-db .row>span:nth-child(n+4){text-align:right;font-variant-numeric:tabular-nums}
.cols-w .row{grid-template-columns:minmax(0,1fr) minmax(0,1.5fr) 96px}
.cols-inc .row{grid-template-columns:minmax(0,1.3fr) minmax(0,1fr)}
.cols-t .row{grid-template-columns:minmax(0,1fr) 72px 168px;height:auto;min-height:34px;padding-top:6px;padding-bottom:6px}
.cols-t .row>span{white-space:normal;overflow-wrap:anywhere}.cols-t .row.head{padding-top:0;padding-bottom:0;min-height:32px}
code{font:12.5px/1.5 Consolas,"Cascadia Mono",monospace;color:#34424d}
.hot{color:var(--crit)}
.st{font-style:normal;font-size:12.5px}.st.hit{color:var(--warn);font-weight:600}.st.inc{color:var(--sub)}.st.none{color:var(--faint)}
.lead{color:var(--sub);font-size:13px}.clear{color:var(--sub)}
.note{padding:8px 12px;border-radius:6px;background:var(--soft);color:var(--sub);font-size:13px}
.coverage{margin-top:12px;color:var(--faint);font-size:12.5px}
.databases{margin-top:6px}
.group{margin-bottom:24px}.group-head{display:flex;align-items:baseline;gap:10px;margin-bottom:4px}
.count{color:var(--faint);font-size:12.5px;font-weight:400;font-variant-numeric:tabular-nums;margin-left:10px}
.group-head .count{margin-left:0}
.todo{margin:0 0 10px;font-size:13px}
.group details{margin-top:4px}
.quiet{margin-top:16px}.quiet h3{margin-bottom:2px;color:var(--sub)}.quiet summary{color:var(--ink)}
.facts{display:grid;grid-template-columns:96px minmax(0,1fr);gap:8px 20px;margin:0;font-size:13px}
.facts dt{color:var(--faint)}.facts dd{margin:0;color:var(--sub)}
.ack{position:fixed;top:0;left:0;width:1px;height:1px;opacity:0;pointer-events:none}
.gate{position:fixed;inset:0;z-index:30;display:flex;align-items:center;justify-content:center;padding:24px;background:rgba(29,31,33,.45)}
.ack:checked+.gate{display:none}.ack:not(:checked)~.skip{display:none}body:has(.ack:not(:checked)){overflow:hidden}
.gate-box{width:min(520px,100%);max-height:calc(100vh - 48px);overflow:auto;padding:26px 28px 24px;background:var(--paper);border-radius:10px;box-shadow:0 16px 48px rgba(0,0,0,.2)}
.gate-box h2{display:block;margin:0 0 12px;padding:0;border:0;font-size:18px}
.gate-box p,.gate-box li{color:var(--sub);font-size:13.5px}.gate-box ul{margin:0 0 10px;padding-left:20px}.gate-box li{margin:2px 0}
.gate-act{position:relative;height:42px;margin-top:18px}
.gate-wait,.gate-act label{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;border-radius:6px;font-size:14px}
.gate-wait{overflow:hidden;background:var(--soft);color:var(--faint)}
.gate-wait::before{content:"";position:absolute;inset:0;background:#e0e0da;transform:scaleX(0);transform-origin:left;animation:gate-fill 6s linear forwards}
.gate-wait span{position:relative}
.gate-act label{background:var(--ink);color:#fff;cursor:pointer}.gate-act label:hover{background:#000}
/* 阅读限制：6 秒内按钮与复选框均为 hidden，鼠标和键盘都无法提前关闭。 */
.ack,.gate-act label{visibility:hidden;animation:gate-unlock 0s 6s forwards}
.ack:focus-visible+.gate label{outline:2px solid var(--link);outline-offset:3px}
@keyframes gate-fill{to{transform:scaleX(1)}}@keyframes gate-unlock{to{visibility:visible}}
@media(max-width:720px){
.bar div{padding:0 16px;gap:18px}main{padding:24px 16px 56px}h1{font-size:21px}.mascot{width:48px;height:48px}
.sum-row{grid-template-columns:3px minmax(0,1fr) auto;padding-right:14px}.sum-meta{display:none}
.cols-pw .row{grid-template-columns:minmax(0,1.3fr) minmax(0,1fr)}.cols-pw .row>span:nth-child(3){display:none}
.cols-ck .row{grid-template-columns:minmax(0,1fr) 56px}.cols-ck .row>span:nth-child(3){display:none}
.cols-db .row{grid-template-columns:minmax(0,1fr) 48px repeat(3,44px)}.cols-db .row>span:nth-child(3),.cols-db .row>span:nth-child(n+7){display:none}
.cols-t .row{grid-template-columns:minmax(0,1fr) 92px}.cols-t .row>span:nth-child(2){display:none}
.cols-w .row,.cols-inc .row{grid-template-columns:minmax(0,1fr) minmax(0,1fr)}.cols-w .row>span:nth-child(2){display:none}
.facts{grid-template-columns:1fr;gap:2px}.facts dd{margin-bottom:10px}}
@media print{.bar,.skip,.gate{display:none}body{background:#fff}main{max-width:none;padding:0}.chunk{content-visibility:visible}.row.head{position:static}a{color:inherit}}
"""
