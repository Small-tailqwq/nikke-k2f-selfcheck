"""使用合成凭据和数据库验证本地报告，不扫描测试机的真实资料。"""

import contextlib
import io
import json
import os
from pathlib import Path
import socket
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
from html.parser import HTMLParser

import re
import k2f_i18n
import k2f_selfcheck as scanner
from k2f_report import render_report


SECRET = "SYNTHETIC-SECRET-MUST-NOT-APPEAR"


def make_database(path, store="cookies", records=None):
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(path)
    if store == "cookies":
        con.execute("CREATE TABLE cookies(encrypted_value BLOB, value TEXT, host_key TEXT, name TEXT)")
        con.executemany("INSERT INTO cookies VALUES (?, ?, ?, ?)", records or [
            (b"v10" + SECRET.encode(), "", SECRET, SECRET),
            (b"v20" + SECRET.encode(), "", SECRET, SECRET),
            (b"v99" + SECRET.encode(), "", SECRET, SECRET),
            (b"", "", SECRET, SECRET),
            (None, SECRET, SECRET, SECRET),
            (b"v10" + SECRET.encode(), SECRET, SECRET, SECRET),
        ])
    else:
        con.execute("CREATE TABLE logins(password_value BLOB, username_value TEXT, origin_url TEXT)")
        con.executemany("INSERT INTO logins VALUES (?, ?, ?)", [
            (b"v10" + SECRET.encode(), SECRET, SECRET),
            (b"v20" + SECRET.encode(), SECRET, SECRET),
            (b"legacy" + SECRET.encode(), SECRET, SECRET),
            (b"", SECRET, SECRET), (None, SECRET, SECRET),
        ])
    con.commit()
    con.close()


class LocalReportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_cookie_versions_plaintext_and_empty_are_disjoint(self):
        database = self.root / "Cookies"
        make_database(database)
        before = database.read_bytes()
        result = scanner.browser_database(str(database), "cookies")
        self.assertEqual(result["status"], "read")
        self.assertEqual(result["counts"], {"total": 6, "v10": 1, "v20": 1, "other": 1, "empty": 1, "plain": 2})
        self.assertNotIn(SECRET, repr(result))
        self.assertEqual(database.read_bytes(), before)
        self.assertEqual(list(self.root.iterdir()), [database])

    def test_password_versions_do_not_return_accounts_or_values(self):
        database = self.root / "Login Data"
        make_database(database, "passwords")
        result = scanner.browser_database(str(database), "passwords")
        self.assertEqual(result["counts"], {"total": 5, "v10": 1, "v20": 1, "other": 1, "empty": 2, "plain": 0})
        self.assertNotIn(SECRET, repr(result))

    def test_wal_is_explicitly_incomplete(self):
        database = self.root / "Cookies"
        make_database(database)
        Path(str(database) + "-wal").write_bytes(b"pending transactions")
        result = scanner.browser_database(str(database), "cookies")
        self.assertEqual(result["status"], "partial")
        self.assertTrue(result["wal"])
        html = render_report({"databases": [dict(result, browser="Chrome", profile="配置 1", store="cookies")]})
        self.assertIn("统计不完整", html)

    def test_missing_corrupt_and_locked_databases_have_distinct_statuses(self):
        database = self.root / "Cookies"
        self.assertEqual(scanner.browser_database(str(database), "cookies")["status"], "absent")
        database.write_text("not sqlite", encoding="utf-8")
        self.assertEqual(scanner.browser_database(str(database), "cookies")["status"], "unreadable")
        with patch.object(scanner, "read_shared", side_effect=PermissionError(SECRET)):
            result = scanner.browser_database(str(database), "cookies")
        self.assertEqual(result, {"status": "unreadable"})

    def test_real_wal_database_reads_main_snapshot_without_writing_source(self):
        database = self.root / "Cookies"
        make_database(database)
        connection = sqlite3.connect(database)
        try:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("INSERT INTO cookies VALUES (?, '', '', '')", (b"v10" + SECRET.encode(),))
            connection.commit()
            before = {p.name: p.read_bytes() for p in self.root.iterdir()}
            result = scanner.browser_database(str(database), "cookies")
            self.assertEqual(result["status"], "partial")
            self.assertEqual(result["counts"]["total"], 6)
            self.assertEqual(result["counts"]["v10"], 1)
            self.assertEqual({p.name: p.read_bytes() for p in self.root.iterdir()}, before)
        finally:
            connection.close()

    def test_empty_database_has_zero_counts(self):
        database = self.root / "Login Data"
        make_database(database, "passwords")
        with sqlite3.connect(database) as connection:
            connection.execute("DELETE FROM logins")
        connection.close()
        self.assertTrue(all(v == 0 for v in scanner.browser_database(str(database), "passwords")["counts"].values()))

    def test_network_and_device_paths_are_rejected_before_stat(self):
        for path in (r"\\example.invalid\share\file", r"\\?\C:\file", "//example.invalid/share/file"):
            with patch.object(scanner.os, "lstat", side_effect=AssertionError("network stat attempted")):
                self.assertEqual(scanner.check_path(path)["status"], "skipped")
                with self.assertRaises(scanner.LocalOnlyError):
                    scanner.local_path(path)

    def test_mapped_network_drive_is_rejected_before_stat(self):
        with patch.object(scanner.k32, "GetDriveTypeW", return_value=4), patch.object(scanner.os, "lstat", side_effect=AssertionError("network stat attempted")):
            self.assertEqual(scanner.check_path(r"Z:\file")["status"], "skipped")

    def test_environment_redirect_to_share_is_not_accessed(self):
        with patch.dict(os.environ, {"USERPROFILE": r"\\example.invalid\share"}), patch.object(scanner.os, "lstat", side_effect=AssertionError("network stat attempted")):
            self.assertEqual(scanner.check_path(r"~\.codex\auth.json")["status"], "skipped")

    def test_reparse_point_is_not_traversed(self):
        class Reparse:
            st_file_attributes = 0x400
        with patch.object(scanner.k32, "GetDriveTypeW", return_value=3), patch.object(scanner.os, "lstat", return_value=Reparse()) as read_stat:
            self.assertEqual(scanner.check_path(r"C:\junction\credentials")["status"], "skipped")
            self.assertEqual(read_stat.call_count, 1)

    def test_recursive_glob_and_failed_traversal(self):
        (self.root / "nested").mkdir()
        (self.root / "nested" / "one.json").write_text(SECRET)
        result = scanner.check_path(str(self.root / "**" / "*.json"))
        self.assertEqual(result, {"status": "matched", "matches": 1})
        with patch.object(scanner.os, "scandir", side_effect=PermissionError(SECRET)):
            self.assertEqual(scanner.check_path(str(self.root / "*.json"))["status"], "partial")

    def test_all_numbered_profiles_and_opera_root(self):
        for name in ("Default", "Profile 1", "Profile 29", "PRIVATE-NAME"):
            (self.root / name).mkdir()
        profiles = scanner.browser_profiles(str(self.root))
        self.assertEqual(len(profiles), 3)
        self.assertNotIn("PRIVATE-NAME", repr(profiles))
        self.assertEqual(len(scanner.browser_profiles(str(self.root), flat=True)), 4)

    def test_report_escapes_untrusted_fields_and_ignores_raw_secrets(self):
        html = render_report({"generated_at": '<script>alert("x")</script>',
                              "results": [{"template": '<img src="https://example.invalid">',
                                           "report_category": "AI 工具", "kind": "credential",
                                           "status": "present", "raw": SECRET, "path": SECRET}],
                              "databases": [{"status": "unreadable", "error": SECRET}]})
        self.assertNotIn(SECRET, html)
        self.assertNotIn("<script", html)
        self.assertNotIn('<img src="https://example.invalid">', html)
        self.assertIn("&lt;script&gt;", html)
        self.assertIn("没有打开文件", html)
        self.assertIn("default-src 'none'", html)
        self.assertNotIn('rel="stylesheet"', html)
        self.assertIn("不能确认是否已泄露", html)
        self.assertIn("https://github.com/Sheisback/nikke_malware_scanner", html)

    def test_html_resources_are_embedded_and_icon_matches_report_image(self):
        class Resources(HTMLParser):
            def __init__(self):
                super().__init__()
                self.icons, self.images, self.disallowed = [], [], []
            def handle_starttag(self, tag, attrs):
                attrs = dict(attrs)
                if tag == "img":
                    self.images.append(attrs.get("src", ""))
                elif tag == "link":
                    if attrs.get("rel") != "icon":
                        self.disallowed.append(tag)
                    self.icons.append(attrs.get("href", ""))
                elif tag in ("script", "iframe", "object", "embed", "form"):
                    self.disallowed.append(tag)
        parser = Resources()
        html = render_report({})
        parser.feed(html)
        self.assertEqual(parser.disallowed, [])
        self.assertEqual(len(parser.icons), 1)
        self.assertEqual(parser.images, parser.icons)
        self.assertTrue(parser.icons[0].startswith("data:image/jpeg;base64,"))
        self.assertIn("img-src data:", html)

    def test_v10_warns_even_with_v20_and_plaintext(self):
        html = render_report({"databases": [{"browser": "Chrome", "profile": "配置 1", "store": "cookies", "status": "read",
                                             "counts": {"total": 3, "v10": 1, "v20": 1, "plain": 1}}]})
        for key in ("v10", "plain", "v20"):
            self.assertIn('id="risk-' + key + '"', html)
        self.assertIn('<b>未加密 Cookie</b><span class="level">高风险</span>', html)
        self.assertIn('<b>v20</b><span class="level">较低</span>', html)
        self.assertLess(html.index('id="risk-v10"'), html.index('id="risk-v20"'))

    def test_password_details_strip_url_secrets_and_mask_account(self):
        database = self.root / "Login Data"
        make_database(database, "passwords")
        connection = sqlite3.connect(database)
        try:
            connection.execute("UPDATE logins SET username_value = ?, origin_url = ?",
                               ("alice@example.com", "https://user:" + SECRET + "@example.com/private/" + SECRET + "?token=" + SECRET + "#" + SECRET))
            connection.commit()
        finally:
            connection.close()
        result = scanner.browser_database(str(database), "passwords")
        self.assertEqual(result["records"][0], {"index": 1, "encryption": "v10", "site": "example.com", "identifier": "a•••m"})
        html = render_report({"databases": [dict(result, browser="Edge", profile="配置 1", store="passwords", database="Login Data")]})
        self.assertIn("1 条 · 1 个站点", html)
        self.assertIn("<span>example.com</span><span><code>a•••m</code></span><span>Edge 配置 1</span>", html)
        for hidden in (SECRET, "alice@example.com", "/private/", "?token=", "user:"):
            self.assertNotIn(hidden, html)

    def test_plain_cookie_details_do_not_embed_cookie_values_or_names(self):
        database = self.root / "Cookies"
        make_database(database, records=[(b"", SECRET, ".example.com", "session_id")])
        result = scanner.browser_database(str(database), "cookies")
        self.assertEqual(result["records"][0], {"index": 1, "encryption": "plain", "site": "example.com", "identifier": "s•••d"})
        html = render_report({"databases": [dict(result, browser="Chrome", profile="配置 1", store="cookies", database=r"Network\Cookies")]})
        self.assertIn('id="risk-plain"', html)
        self.assertIn("<span>example.com</span><span>1</span><span>Chrome 配置 1</span>", html)
        self.assertNotIn(SECRET, html)
        self.assertNotIn("session_id", html)
        self.assertEqual(scanner.masked_identifier("abcd"), "••••")
        self.assertEqual(scanner.site_label(".example.com/" + SECRET, "cookies"), "站点未知")

    def test_large_record_lists_are_chunked_and_grouped_by_site(self):
        records = [{"index": i, "encryption": "v10", "site": "site%d.example" % (i % 250), "identifier": "c•••e"}
                   for i in range(1, 5001)]
        html = render_report({"databases": [{"browser": "Chrome", "profile": "配置 1", "store": "cookies",
                                             "database": r"Network\Cookies", "status": "read", "records": records,
                                             "counts": {"total": 5000, "v10": 5000}}]})
        self.assertIn("5,000 条 · 250 个站点", html)
        # 5000 条 Cookie 聚合为 250 个站点行，按 100 行分块；不再为每条记录嵌套 details。
        risk = html[html.index('id="risk-v10"'):html.index('class="databases"')]
        self.assertEqual(risk.count('<div class="chunk"'), 3)
        self.assertEqual(html.count("<details"), 2)
        self.assertIn("contain-intrinsic-size:auto 1700px", html)
        self.assertNotIn("c•••e", html)

    def test_incomplete_items_are_listed_together(self):
        html = render_report({"results": [{"template": r"~\.aws\credentials", "report_category": "云服务与运维",
                                           "kind": "credential", "status": "unreadable"}],
                              "registry": [{"key": r"Software\GNU\GnuPG", "status": "present", "hives": ["HKCU"], "partial": True}],
                              "databases": [{"browser": "Edge", "profile": "配置 1", "store": "cookies",
                                             "database": r"Network\Cookies", "status": "unreadable"}]})
        section = html[html.index('id="incomplete"'):html.index('id="about"')]
        for text in (r"~\.aws\credentials", r"Software\GNU\GnuPG", "部分根键无法打开", r"Edge 配置 1 · Network\Cookies"):
            self.assertIn(text, section)
        self.assertIn("3 项", section)

    def test_disclaimer_gate_works_without_script_or_form(self):
        html = render_report({})
        self.assertLess(html.index('class="gate"'), html.index('id="main"'))
        self.assertIn('<input type="checkbox" id="ack" class="ack"', html)
        self.assertIn('<label for="ack">', html)
        self.assertIn(".ack:checked+.gate{display:none}", html)
        self.assertIn("不能保证绝对准确", html)
        self.assertIn(".ack,.gate-act label{visibility:hidden;animation:gate-unlock 0s 6s forwards}", html)
        self.assertNotIn("<form", html)

    def full_report(self):
        return {"generated_at": "2026-11-04 12:00:00",
                "results": [{"template": r"~\.codex\auth.json", "report_category": "AI 工具", "kind": "credential", "status": "present"},
                            {"template": r"~\.aws\credentials", "report_category": "云服务与运维", "kind": "credential", "status": "unreadable"},
                            {"template": r"~\**\*.json", "report_category": "编辑器与插件", "kind": "config", "status": "partial", "matches": 2},
                            {"template": r"~\.zsh_history", "report_category": "Shell 历史与配置", "kind": "config", "status": "absent"},
                            {"template": "%USERPROFILE%", "report_category": "普通目录", "kind": "general", "status": "present"}],
                "registry": [{"key": r"Software\GNU\GnuPG", "status": "present", "hives": ["HKCU"], "partial": True}],
                "databases": [{"browser": "Chrome", "profile": "配置 1", "store": "passwords", "database": "Login Data", "status": "partial", "wal": True,
                               "counts": {"total": 3, "v10": 1, "v20": 1, "other": 1},
                               "records": [{"index": 1, "encryption": "v10", "site": "example.com", "identifier": "a•••e"},
                                           {"index": 2, "encryption": "v20", "site": "站点未知", "identifier": "未填写"},
                                           {"index": 3, "encryption": "other", "site": "example.org", "identifier": "••••"}]},
                              {"browser": "Opera", "profile": "主配置", "store": "cookies", "database": r"Network\Cookies", "status": "read",
                               "counts": {"total": 2, "plain": 1, "empty": 1},
                               "records": [{"index": 1, "encryption": "plain", "site": "example.net", "identifier": "s•••d"},
                                           {"index": 2, "encryption": "empty", "site": "example.net", "identifier": "x•••y"}]},
                              {"browser": "Edge", "profile": "配置 2", "store": "cookies", "database": r"Network\Cookies", "status": "unreadable"},
                              {"browser": "Edge", "profile": "配置 2", "store": "passwords", "database": "Login Data", "status": "absent"}],
                "coverage": [{"browser": "Chrome", "status": "present"}, {"browser": "Brave", "status": "absent"}, {"browser": "Edge", "status": "unreadable"}],
                "wallets": [{"browser": "Chrome", "profile": "配置 1", "id": "a" * 32, "status": "present"},
                            {"browser": "Chrome", "profile": "配置 1", "id": "b" * 32, "status": "unreadable"}]}

    def test_every_text_has_four_languages_with_matching_placeholders(self):
        tables = [k2f_i18n.TEXT, k2f_i18n.CATEGORY_NAMES, k2f_i18n.ACTIONS]
        tables += [{key + str(i): value[i] for key, value in k2f_i18n.RISK_TEXT.items()} for i in range(3)]
        for table in tables:
            for key, values in table.items():
                self.assertEqual(len(values), len(k2f_i18n.LANGS), key)
                self.assertTrue(all(values), key)
                fields = {frozenset(re.findall(r"\{(\w+)\}", v)) for v in values}
                self.assertEqual(len(fields), 1, key)

    def test_english_and_korean_reports_have_no_chinese_left(self):
        for lang, attr in (("en", 'lang="en"'), ("ko", 'lang="ko"')):
            html = render_report(self.full_report(), lang)
            self.assertIn(attr, html)
            self.assertEqual(re.findall(r"[\u3400-\u9fff\u3040-\u30ff]+", html), [], lang)
        html = render_report(self.full_report(), "en")
        for text in ("Profile 1", "Main profile", "Unknown site", "Got it, view the report", "Incomplete (WAL)", "1 record · 1 site"):
            self.assertIn(text, html)

    def test_japanese_report_uses_japanese_text(self):
        html = render_report(self.full_report(), "ja")
        self.assertIn('lang="ja"', html)
        for text in ("このレポートについて", "プロファイル 1", "認証情報の場所", "不完全（WAL）"):
            self.assertIn(text, html)
        for text in ("配置 1", "关于这份报告", "未完成检查"):
            self.assertNotIn(text, html)

    def test_language_detection_and_cli_output(self):
        for langid, lang in ((0x0804, "zh"), (0x0404, "zh"), (0x0409, "en"), (0x0411, "ja"), (0x0412, "ko"), (0x040C, "en")):
            with patch.object(scanner.k32, "GetUserDefaultUILanguage", return_value=langid):
                self.assertEqual(scanner.detect_language(), lang)
        targets = self.root / "targets.json"
        targets.write_text('{"paths":[],"registry":[],"wallet_extensions":[]}', encoding="utf-8")
        output = self.root / "report.html"
        with patch.object(scanner, "scan_browsers", return_value=([], [], [])), contextlib.redirect_stdout(io.StringIO()) as stdout:
            self.assertEqual(scanner.main(["--targets", str(targets), "--out", str(output), "--no-open", "--lang", "ko"]), 0)
        self.assertIn("보고서 저장됨", stdout.getvalue())
        self.assertIn('lang="ko"', output.read_text(encoding="utf-8"))

    def test_incomplete_credential_checks_are_not_reported_as_absent(self):
        unreadable = {"template": "~/.aws/credentials", "report_category": "云服务与运维", "kind": "credential", "status": "unreadable"}
        absent = {"template": "~/.zsh_history", "report_category": "Shell 历史与配置", "kind": "config", "status": "absent"}
        html = render_report({"results": [unreadable, absent]})
        auth = html[html.index('id="auth"'):html.index('id="wallets"')]
        self.assertNotIn("清单内的凭据位置均未发现", auth)
        self.assertIn("有 1 项未能完成检查", auth)
        uncertain = auth[auth.index("未能完成检查</h3>"):auth.index("未发现</h3>")]
        self.assertIn("~/.aws/credentials", uncertain)
        self.assertNotIn("~/.zsh_history", uncertain)
        self.assertIn("~/.zsh_history", auth[auth.index("未发现</h3>"):])
        self.assertIn("but 1 check did not complete", render_report({"results": [unreadable]}, "en"))
        self.assertIn("清单内的凭据位置均未发现", render_report({"results": [absent]}))

    def test_skipped_counts_are_not_zero_or_safe(self):
        html = render_report({"skip_counts": True, "skip_wallets": True})
        self.assertIn("未检查浏览器数据库", html)
        self.assertIn('<span class="sum-n">—</span>', html)
        self.assertNotIn('<span class="sum-n">0</span><span class="sum-meta">条', html)

    def test_generic_directories_do_not_get_credential_actions(self):
        html = render_report({"results": [{"template": "%USERPROFILE%", "report_category": "普通目录", "kind": "general", "status": "present"}]})
        for actions in k2f_i18n.ACTIONS.values():
            for action in actions:
                self.assertNotIn(action, html)
        self.assertIn("不是凭据位置", html)

    def test_main_creates_report_before_opening_and_reads_no_auth_file(self):
        profile = self.root / "profile"
        auth = profile / ".codex" / "auth.json"
        auth.parent.mkdir(parents=True)
        auth.write_text(SECRET)
        local = profile / "Local"
        make_database(local / "Google" / "Chrome" / "User Data" / "Default" / "Network" / "Cookies")
        target_file = self.root / "targets.json"
        target_file.write_text(json.dumps({"paths": [{"template": r"~\.codex\auth.json", "category": "AI / LLM 工具", "report_category": "AI 工具", "kind": "credential"}], "registry": [], "wallet_extensions": []}), encoding="utf-8")
        output = self.root / "report.html"
        real_open = open

        def check_open(path, *args, **kwargs):
            self.assertNotEqual(os.fspath(path), str(auth))
            return real_open(path, *args, **kwargs)

        def launch(path, operation):
            self.assertEqual(operation, "open")
            self.assertEqual(path, str(output))
            self.assertIn('id="risk-v10"', output.read_text(encoding="utf-8"))

        with patch.dict(os.environ, {"USERPROFILE": str(profile), "LOCALAPPDATA": str(local), "APPDATA": str(profile / "Roaming")}), \
                patch("builtins.open", side_effect=check_open), patch.object(scanner.os, "startfile", side_effect=launch) as opener, \
                patch.object(socket, "socket", side_effect=AssertionError("network attempted")), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(scanner.main(["--targets", str(target_file), "--out", str(output)]), 0)
            opener.assert_called_once()
        html = output.read_text(encoding="utf-8")
        self.assertNotIn(SECRET, html)
        self.assertNotIn(str(profile), html)

    def test_no_open_and_existing_report_preservation(self):
        targets = self.root / "targets.json"
        targets.write_text('{"paths":[],"registry":[],"wallet_extensions":[]}', encoding="utf-8")
        output = self.root / "report.html"
        with patch.object(scanner, "scan_browsers", return_value=([], [], [])), patch.object(scanner.os, "startfile") as opener, contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(scanner.main(["--targets", str(targets), "--out", str(output), "--quick", "--no-open"]), 0)
            before = output.read_bytes()
            self.assertEqual(scanner.main(["--targets", str(targets), "--out", str(output), "--no-open"]), 2)
            self.assertEqual(output.read_bytes(), before)
            opener.assert_not_called()

    def test_browser_launch_failure_keeps_saved_report(self):
        targets = self.root / "targets.json"
        targets.write_text('{"paths":[],"registry":[],"wallet_extensions":[]}', encoding="utf-8")
        output = self.root / "report.html"
        with patch.object(scanner, "scan_browsers", return_value=([], [], [])), patch.object(scanner.os, "startfile", side_effect=OSError(SECRET)), contextlib.redirect_stdout(io.StringIO()) as stdout:
            self.assertEqual(scanner.main(["--targets", str(targets), "--out", str(output), "--lang", "zh"]), 0)
        self.assertTrue(output.is_file())
        self.assertIn("无法自动打开默认浏览器", stdout.getvalue())
        self.assertNotIn(SECRET, stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
