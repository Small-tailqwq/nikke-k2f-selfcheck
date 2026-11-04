"""本地 HTML 报告：渲染脱敏定位元信息、聚合计数和可展开明细。页面不含脚本和外部资源。"""

from html import escape
import re

from k2f_i18n import ACTIONS, CATEGORY_NAMES, HTML_LANG, RISK_TEXT, normalize_lang, pick, t


REPORT_ICON = 'data:image/jpeg;base64,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'
SCANNER_URL = "https://github.com/Sheisback/nikke_malware_scanner"
CATEGORIES = tuple(CATEGORY_NAMES)
AUTH_KINDS = {"credential", "key_material", "config"}
# 计数键与色调；顺序即页面优先级。
RISKS = (("v10", "crit"), ("plain", "crit"), ("other", "warn"), ("v20", "info"), ("empty", "none"))
COUNT_KEYS = ("total", "v10", "v20", "other", "empty", "plain")
# 长列表按固定行高分块，离屏分块由 content-visibility 跳过样式、布局和绘制。
CHUNK = 100
ROW_HEIGHT = 34
SINGULAR = (("records", "record"), ("checks", "check"), ("sites", "site"), ("locations", "location"), ("categories", "category"),
            ("items", "item"), ("matches", "match"))


def singular(text):
    for many, one in SINGULAR:
        text = re.sub(r"\b" + many + r"\b", one, text)
    return text


class Text:
    """绑定语言的文案查询；扫描器写入的中文配置别名和占位值在这里本地化。"""

    def __init__(self, lang):
        self.lang = normalize_lang(lang)

    def __call__(self, key, **values):
        text = t(self.lang, key, **values)
        return singular(text) if self.lang == "en" and values.get("n") == "1" else text

    def unit(self, key, count):
        return singular(t(self.lang, key)) if self.lang == "en" and count == 1 else t(self.lang, key)

    def category(self, name):
        return pick(self.lang, CATEGORY_NAMES[name]) if name in CATEGORY_NAMES else str(name)

    def action(self, category):
        return pick(self.lang, ACTIONS[category]) if category in ACTIONS else ""

    def risk(self, key):
        name, level, action = RISK_TEXT[key]
        return pick(self.lang, name), pick(self.lang, level), pick(self.lang, action)

    def profile(self, value):
        value = str(value or "")
        match = re.fullmatch(r"配置 (\d+)", value)
        if match:
            return self("profile.n", n=match.group(1))
        return self("profile.main") if value == "主配置" else value

    def placeholder(self, value, fallback):
        if value in (None, "", "站点未知", "未填写"):
            return self("site.unknown" if fallback == "site" else "account.empty")
        return value

    def status(self, item):
        if item.get("status") == "matched":
            return self("status.matched", n=fmt(item.get("matches")))
        if item.get("status") == "partial":
            return self("status.partial_matched", n=fmt(item.get("matches")))
        status = item.get("status")
        return self("status." + status) if status in ("present", "absent", "unreadable", "skipped", "read") else self("status.skipped")


def e(value):
    return escape(str(value), quote=True)


def number(value):
    return value if type(value) is int and value >= 0 else 0


def fmt(value):
    return "{:,}".format(number(value))


def hit(item):
    return item.get("status") in ("present", "matched") or number(item.get("matches")) > 0


def where(database, T):
    return (str(database.get("browser", "")) + " " + T.profile(database.get("profile"))).strip()


def store_name(database, T):
    return T("store.passwords" if database.get("store") == "passwords" else "store.cookies")


def row(*cells):
    return '<div class="row"><span>' + "</span><span>".join(cells) + "</span></div>"


def rows(columns, head, body):
    out = ['<div class="list ', columns, '"><div class="row head"><span>', "</span><span>".join(e(h) for h in head), "</span></div>"]
    for start in range(0, len(body), CHUNK):
        part = body[start:start + CHUNK]
        out.append('<div class="chunk" style="contain-intrinsic-size:auto %dpx">' % (len(part) * ROW_HEIGHT))
        out.extend(part)
        out.append("</div>")
    out.append("</div>")
    return "".join(out)


def state(label, tone):
    return '<i class="st ' + tone + '">' + e(label) + "</i>"


def record_lists(pairs, T):
    passwords = sorted((T.placeholder(r.get("site"), "site"), T.placeholder(r.get("identifier"), "account"), where(d, T))
                       for d, r in pairs if d.get("store") == "passwords")
    cookies = {}
    for database, record in pairs:
        if database.get("store") == "passwords":
            continue
        entry = cookies.setdefault(T.placeholder(record.get("site"), "site"), [0, []])
        entry[0] += 1
        if where(database, T) not in entry[1]:
            entry[1].append(where(database, T))
    html = ""
    if passwords:
        html += ('<h4>' + e(T("browser.passwords")) + '<span>' + e(T("count.records", n=fmt(len(passwords)))) + '</span></h4>'
                 + rows("cols-pw", (T("col.site"), T("col.account"), T("col.browser")),
                        [row(e(site), "<code>" + e(account) + "</code>", e(browser)) for site, account, browser in passwords]))
    if cookies:
        ordered = sorted(cookies.items(), key=lambda item: (-item[1][0], item[0]))
        meta = T("count.records", n=fmt(sum(c for c, _ in cookies.values()))) + T("unit.sites", n=fmt(len(ordered)))
        html += ('<h4>' + e(T("browser.cookies")) + '<span>' + e(meta) + '</span></h4>'
                 + rows("cols-ck", (T("col.site"), T("col.count"), T("col.browser")),
                        [row(e(site), fmt(count), e((", " if T.lang in ("en", "ko") else "、").join(browsers)))
                         for site, (count, browsers) in ordered]))
    return html


def database_state(database, T):
    if database.get("status") == "partial":
        return T("status.partial_wal") if database.get("wal") else T("status.partial")
    return T.status(database)


def render_browsers(report, T):
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
        parts.append('<p class="note">' + e(T("browser.skipped")) + '</p>')
    elif not counted:
        link = '<a href="#incomplete">' + e(T("nav.incomplete")) + '</a>'
        parts.append('<p class="note">' + e(T("browser.none", link="\0")).replace("\0", link) + '</p>')
    elif not any(totals[key] for key in ("v10", "plain", "other", "v20")):
        parts.append('<p class="clear">' + e(T("browser.clear")) + '</p>')
    if any(d.get("status") == "partial" for d in databases):
        parts.append('<p class="note">' + e(T("browser.partial")) + '</p>')
    for key, tone in RISKS:
        if not totals[key]:
            continue
        name, level, action = T.risk(key)
        meta = T("count.records", n=fmt(totals[key])) + (T("unit.sites", n=fmt(sites[key])) if records[key] else "")
        parts.append('<div class="risk ' + tone + '" id="risk-' + key + '"><div class="risk-head"><b>' + e(name)
                     + '</b><span class="level">' + e(level) + '</span><span class="n">' + e(meta) + '</span></div><p>'
                     + e(action) + '</p>'
                     + ('<details><summary>' + e(T("browser.details")) + '</summary>' + record_lists(records[key], T) + '</details>'
                        if records[key] else '')
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
            body.append(row(e(where(database, T)), e(store_name(database, T)), e(database_state(database, T)), *cells))
        missing = len(databases) - len(listed)
        summary = T("browser.databases", n=fmt(len(listed))) + (T("browser.missing", n=fmt(missing)) if missing else "")
        parts.append('<details class="databases"><summary>' + e(summary) + '</summary>'
                     + rows("cols-db", (T("col.browser"), T("col.type"), T("col.status"), T("col.total"), "v10", "v20",
                                        T("col.plain"), T("col.other"), T("col.empty")), body)
                     + '</details>')
    coverage = report.get("coverage", [])
    if coverage:
        parts.append('<p class="coverage">' + " · ".join(
            e(c.get("browser", "")) + " " + e(T("coverage." + (c.get("status") if c.get("status") in ("present", "absent") else "unreadable")))
            for c in coverage) + '</p>')
    return "".join(parts), totals, bool(counted), sites, records


def target_items(report, T):
    items = []
    for result in report.get("results", []):
        category = result.get("report_category")
        # 未标注的自定义清单使用保守分类，不按来源索引猜测鉴权类型。
        items.append({"label": result.get("template", ""), "kind": result.get("kind", "config"),
                      "category": category if category in CATEGORIES else "其他开发工具",
                      "status": T.status(result), "hit": hit(result), "source": result,
                      "incomplete": result.get("status") in ("unreadable", "skipped", "partial")})
    for entry in report.get("registry", []):
        label = T.status(entry)
        hives = [h for h in entry.get("hives", []) if h in ("HKCU", "HKLM")]
        if hives:
            label += " · " + "/".join(hives)
        items.append({"label": entry.get("key", ""), "kind": entry.get("kind", "config"), "registry": True,
                      "category": "SSH、GPG 与密钥", "status": label, "hit": hit(entry), "source": entry,
                      "incomplete": entry.get("status") in ("unreadable", "skipped") or bool(entry.get("partial"))})
    return items


def target_rows(items, T):
    ordered = sorted(items, key=lambda i: (not i["hit"], not i["incomplete"], i["label"]))
    kinds = ("credential", "key_material", "config", "browser", "general", "program")
    return rows("cols-t", (T("col.location"), T("col.type"), T("col.result")), [
        row("<code>" + e(i["label"]) + "</code>",
            e(T("kind.registry") if i.get("registry") else T("kind." + (i["kind"] if i["kind"] in kinds else "config"))),
            state(i["status"], "hit" if i["hit"] else "inc" if i["incomplete"] else "none"))
        for i in ordered])


def render_targets(items, T):
    auth = [i for i in items if i["kind"] in AUTH_KINDS]
    groups, uncertain, quiet = [], [], []
    for category in CATEGORIES:
        members = [i for i in auth if i["category"] == category]
        if not members:
            continue
        found = [i for i in members if i["hit"]]
        rest = [i for i in members if not i["hit"]]
        count = '<span class="count">' + fmt(len(found)) + ' / ' + fmt(len(members)) + '</span>'
        if found:
            action = T.action(category)
            groups.append('<div class="group"><div class="group-head"><h3>' + e(T.category(category)) + '</h3>' + count + '</div>'
                          + ('<p class="todo">' + e(action) + '</p>' if action else '')
                          + target_rows(found, T)
                          + ('<details><summary>' + e(T("auth.rest", n=fmt(len(rest)))) + '</summary>' + target_rows(rest, T) + '</details>'
                             if rest else '')
                          + '</div>')
        else:
            # 无法检查、跳过或遍历不完整的目标存在性未知，不能归入“未发现”。
            pending = sum(i["incomplete"] for i in members)
            block = ('<details><summary>' + e(T.category(category)) + count
                     + ('<span class="count">' + e(T("auth.uncertain_count", n=fmt(pending))) + '</span>' if pending else '')
                     + '</summary>' + target_rows(members, T) + '</details>')
            (uncertain if pending else quiet).append(block)
    found_total = sum(i["hit"] for i in auth)
    pending_total = sum(i["incomplete"] for i in auth)
    html = '<p class="lead">' + e(T("auth.lead")) + '</p>' if auth else ''
    if auth and not found_total:
        html += ('<p class="note">' + e(T("auth.unsure", n=fmt(pending_total))) + '</p>' if pending_total
                 else '<p class="clear">' + e(T("auth.clear")) + '</p>')
    html += "".join(groups)
    if uncertain:
        html += '<div class="quiet"><h3>' + e(T("auth.uncertain")) + '</h3>' + "".join(uncertain) + '</div>'
    if quiet:
        html += '<div class="quiet"><h3>' + e(T("auth.quiet")) + '</h3>' + "".join(quiet) + '</div>'
    other = [i for i in items if i["kind"] not in AUTH_KINDS]
    if other:
        html += ('<div class="quiet"><h3>' + e(T("auth.other")) + '</h3><details><summary>' + e(T("auth.other_summary"))
                 + '<span class="count">' + fmt(sum(i["hit"] for i in other)) + ' / ' + fmt(len(other)) + '</span></summary>'
                 '<p class="lead">' + e(T("auth.other_lead")) + '</p>' + target_rows(other, T) + '</details></div>')
    if not items:
        html += '<p class="note">' + e(T("auth.empty")) + '</p>'
    return html, found_total, len({i["category"] for i in auth if i["hit"]})


def render_wallets(report, T):
    wallets = report.get("wallets", [])
    found = [w for w in wallets if hit(w)]
    if report.get("skip_wallets"):
        return '<p class="note">' + e(T("wallets.skipped")) + '</p>', None
    html = '<p class="todo">' + e(T("wallets.todo")) + '</p>' if found else '<p class="clear">' + e(T("wallets.clear")) + '</p>'
    if wallets:
        html += rows("cols-w", (T("col.browser"), T("col.extension"), T("col.result")), [
            row(e(where(w, T)), "<code>" + e(w.get("id", "")) + "</code>",
                state(T.status(w), "hit" if hit(w) else "inc")) for w in wallets])
    return html, len(found)


def incomplete_items(report, items, T):
    out = []
    for item in items:
        if not item["incomplete"]:
            continue
        source = item["source"]
        if source.get("status") == "partial":
            reason = T("reason.glob", n=fmt(source.get("matches")))
        elif item.get("registry") and source.get("partial"):
            reason = T("reason.registry")
        else:
            reason = T("reason." + (source.get("status") if source.get("status") in ("unreadable", "skipped") else "skipped"))
        out.append(("<code>" + e(item["label"]) + "</code>", reason))
    for database in report.get("databases", []):
        if database.get("status") == "partial":
            reason = T("reason.database")
        elif database.get("status") in ("unreadable", "skipped"):
            reason = T("reason." + database["status"])
        else:
            continue
        out.append((e(where(database, T)) + " · " + e(database.get("database", store_name(database, T))), reason))
    for entry in report.get("coverage", []):
        if entry.get("status") not in ("present", "absent"):
            out.append((e(T("item.profile_dir", browser=entry.get("browser", ""))), T("reason.unreadable")))
    for wallet in report.get("wallets", []):
        if wallet.get("status") in ("unreadable", "skipped", "partial"):
            reason = T("reason." + wallet["status"]) if wallet["status"] != "partial" else T("reason.partial")
            out.append((e(where(wallet, T)) + " · " + e(T("item.wallet")) + " <code>" + e(wallet.get("id", "")) + "</code>", reason))
    return out


def summary_row(tone, label, value, meta, href, T):
    zero = value == 0
    return ('<a class="sum-row ' + ("zero" if zero or value is None else tone) + '" href="' + href + '"><span class="sum-label">'
            + e(label) + '</span><span class="sum-n">' + ("—" if value is None else fmt(value)) + '</span><span class="sum-meta">'
            + e(T("sum.unchecked") if value is None else meta) + '</span></a>')


def render_report(report, lang="zh"):
    T = Text(lang)
    browser_html, totals, counted, sites, records = render_browsers(report, T)
    items = target_items(report, T)
    target_html, target_hits, target_groups = render_targets(items, T)
    wallet_html, wallet_hits = render_wallets(report, T)
    pending = incomplete_items(report, items, T)

    def browser_meta(key):
        return T.unit("unit.records", totals[key]) + (T("unit.sites", n=fmt(sites[key])) if records[key] else "")

    def browser_row(tone, label, key):
        return summary_row(tone, T(label), totals[key] if counted else None, browser_meta(key),
                           "#risk-" + key if totals[key] else "#browser", T)

    summary = [browser_row("crit", "sum.v10", "v10"), browser_row("crit", "sum.plain", "plain")]
    if totals["other"]:
        summary.append(browser_row("warn", "sum.other", "other"))
    summary += [
        summary_row("warn", T("sum.auth"), target_hits,
                    T.unit("unit.places", target_hits) + (T("unit.groups", n=fmt(target_groups)) if target_hits else ""), "#auth", T),
        summary_row("warn", T("sum.wallets"), wallet_hits, T("unit.found"), "#wallets", T),
        browser_row("info", "sum.v20", "v20"),
        summary_row("info", T("sum.pending"), len(pending), T.unit("unit.items", len(pending)), "#incomplete", T),
    ]
    pending_html = (rows("cols-inc", (T("col.item"), T("col.reason")), [row(name, e(reason)) for name, reason in pending])
                    if pending else '<p class="clear">' + e(T("pending.clear")) + '</p>')
    scanner = '<a href="' + SCANNER_URL + '" target="_blank" rel="noopener noreferrer">nikke_malware_scanner</a>'
    nav = "".join('<a href="#' + anchor + '">' + e(T("nav." + key)) + '</a>' for anchor, key in (
        ("summary", "summary"), ("browser", "browser"), ("auth", "auth"), ("wallets", "wallets"),
        ("incomplete", "incomplete"), ("about", "about")))
    facts = "".join('<dt>' + e(T("about." + key)) + '</dt><dd>' + e(T("about." + key + "_text")) + '</dd>'
                    for key in ("method", "content", "browsers", "skipped", "disclaimer"))

    return '''<!doctype html>
<html lang="''' + HTML_LANG[T.lang] + '''"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'">
<meta name="referrer" content="no-referrer"><title>''' + e(T("title")) + '''</title>
<link rel="icon" type="image/jpeg" href="''' + REPORT_ICON + '''">
<style>''' + CSS + '''</style></head><body>
<input type="checkbox" id="ack" class="ack" aria-label="''' + e(T("gate.ok")) + '''">
<div class="gate" role="dialog" aria-modal="true" aria-labelledby="gate-title"><div class="gate-box">
<h2 id="gate-title">''' + e(T("gate.title")) + '''</h2>
<p>''' + e(T("gate.p1")) + '''</p>
<p>''' + e(T("gate.p2")) + '''</p>
<ul><li>''' + e(T("gate.li1")) + '''</li>
<li>''' + e(T("gate.li2")) + '''</li>
<li>''' + e(T("gate.li3")) + '''</li></ul>
<p>''' + e(T("gate.p3")) + '''</p>
<div class="gate-act"><span class="gate-wait"><span>''' + e(T("gate.wait")) + '''</span></span><label for="ack">''' + e(T("gate.ok")) + '''</label></div>
</div></div>
<a class="skip" href="#main">''' + e(T("skip")) + '''</a>
<nav class="bar"><div>''' + nav + '''</div></nav>
<main id="main">
<header class="head"><img class="mascot" src="''' + REPORT_ICON + '''" width="56" height="56" alt="''' + e(T("alt")) + '''"><div><h1>''' + e(T("title")) + '''</h1><p class="meta">''' + e(report.get("generated_at", "")) + '''</p></div></header>
<p class="disclaimer">''' + e(T("header.note", link="\0")).replace("\0", scanner) + '''</p>
<section id="summary" class="summary">''' + "".join(summary) + '''</section>
<section id="browser"><h2>''' + e(T("nav.browser")) + '''<small>''' + e(T("browser.small")) + '''</small></h2>''' + browser_html + '''</section>
<section id="auth"><h2>''' + e(T("nav.auth")) + '''</h2>''' + target_html + '''</section>
<section id="wallets"><h2>''' + e(T("sum.wallets")) + '''</h2>''' + wallet_html + '''</section>
<section id="incomplete"><h2>''' + e(T("nav.incomplete")) + '''<small>''' + e(T("count.items", n=fmt(len(pending)))) + '''</small></h2>''' + pending_html + '''</section>
<section id="about"><h2>''' + e(T("nav.about")) + '''</h2><dl class="facts">''' + facts + '''</dl></section>
</main></body></html>'''


# 声明弹窗的阅读限制：6 秒内按钮与复选框均为 visibility:hidden，鼠标和键盘都无法提前关闭。
CSS = r"""
:root{color-scheme:light;--bg:#f7f7f5;--paper:#fff;--ink:#1d1f21;--sub:#5b6066;--faint:#949a9f;--line:#e4e4e0;--soft:#efefeb;--crit:#c0352b;--crit-bg:#fcefed;--warn:#95590a;--warn-bg:#fbf3e4;--link:#1d5c9a}
*{box-sizing:border-box}html{scroll-padding-top:60px}
body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.65 "Segoe UI","Microsoft YaHei UI","Microsoft YaHei",sans-serif}
html:lang(ja) body{font-family:"Segoe UI","Yu Gothic UI","Meiryo",sans-serif}html:lang(ko) body{font-family:"Segoe UI","Malgun Gothic",sans-serif}
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
