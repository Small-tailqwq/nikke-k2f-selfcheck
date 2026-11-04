#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""K2F 本地泄露面模拟：只读元信息和浏览器加密版本统计，生成脱敏 HTML。"""

import argparse
import ctypes
import ctypes.wintypes as wt
import fnmatch
import json
import ntpath
import os
from pathlib import Path
import re
import sqlite3
import stat
import sys
import winreg
from datetime import datetime
from urllib.parse import urlsplit

from k2f_report import render_report


k32 = ctypes.WinDLL("kernel32", use_last_error=True)
k32.GetDriveTypeW.argtypes = [wt.LPCWSTR]
k32.GetDriveTypeW.restype = wt.UINT
k32.CreateFileW.restype = wt.HANDLE
k32.CreateFileW.argtypes = [wt.LPCWSTR, wt.DWORD, wt.DWORD, wt.LPVOID, wt.DWORD, wt.DWORD, wt.HANDLE]
k32.GetFileSizeEx.argtypes = [wt.HANDLE, ctypes.POINTER(ctypes.c_longlong)]
k32.ReadFile.argtypes = [wt.HANDLE, wt.LPVOID, wt.DWORD, ctypes.POINTER(wt.DWORD), wt.LPVOID]
k32.CloseHandle.argtypes = [wt.HANDLE]
k32.GetConsoleProcessList.argtypes = [ctypes.POINTER(wt.DWORD), wt.DWORD]
k32.GetConsoleProcessList.restype = wt.DWORD


class LocalOnlyError(OSError):
    """该路径不能在纯本地范围内检查。"""


def ensure_environment():
    """在精简启动环境下从当前用户注册表补齐目录变量。"""
    for name in ("USERPROFILE", "APPDATA", "LOCALAPPDATA"):
        if os.environ.get(name):
            continue
        for key in (r"Volatile Environment", r"Environment"):
            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key) as handle:
                    value, _ = winreg.QueryValueEx(handle, name)
                if value:
                    os.environ[name] = str(value)
                    break
            except OSError:
                continue


def normalize(template):
    return re.sub(r"\\+", r"\\", template)


def local_path(path):
    # 在 stat / glob / open 之前拒绝 UNC、设备路径、映射盘和重解析点，避免触发网络访问。
    raw = os.fspath(path)
    if raw.startswith(("\\\\", "//")):
        raise LocalOnlyError("network_or_device_path")
    path = os.path.abspath(raw)
    drive, tail = ntpath.splitdrive(path)
    if not re.fullmatch(r"[A-Za-z]:", drive) or k32.GetDriveTypeW(drive + "\\") not in (2, 3, 6):
        raise LocalOnlyError("nonlocal_drive")
    if ":" in tail:
        raise LocalOnlyError("alternate_stream")
    current = drive + "\\"
    for part in tail.strip("\\/").split("\\"):
        if not part:
            continue
        current = os.path.join(current, part)
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            break
        if getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            raise LocalOnlyError("reparse_point")
    return path


def expand(template):
    # 先检查原模板，不能把 UNC 的双反斜杠规范化成本地根目录。
    if template.startswith(("\\\\", "//")):
        raise LocalOnlyError("network_template")
    template = normalize(template)
    if template.startswith("~"):
        profile = os.environ.get("USERPROFILE")
        if not profile:
            raise LocalOnlyError("missing_environment")
        template = profile + template[1:]
    path = os.path.expandvars(template)
    if re.search(r"%[^%]+%|\$[A-Za-z_{]", path):
        raise LocalOnlyError("missing_environment")
    return path


def local_matches(pattern):
    """按模板遍历本地路径；递归通配符不会进入链接、挂载点或共享目录。"""
    drive, tail = ntpath.splitdrive(pattern)
    root = local_path(drive + "\\")
    parts = tail.strip("\\/").split("\\")

    def walk(base, rest):
        local_path(base)
        if not rest:
            if os.path.exists(base):
                yield base
            return
        component, remaining = rest[0], rest[1:]
        if component == "**":
            yield from walk(base, remaining)
            with os.scandir(base) as entries:
                for entry in entries:
                    if entry.is_dir(follow_symlinks=False):
                        yield from walk(entry.path, rest)
        elif any(c in component for c in "*?["):
            with os.scandir(base) as entries:
                for entry in entries:
                    if fnmatch.fnmatchcase(entry.name.lower(), component.lower()):
                        yield from walk(entry.path, remaining)
        else:
            child = os.path.join(base, component)
            local_path(child)
            if os.path.exists(child):
                yield from walk(child, remaining)

    yield from walk(root, parts)


def check_path(template):
    try:
        path = expand(template)
        if any(c in path for c in "*?["):
            count = 0
            try:
                for _ in local_matches(path):
                    count += 1
            except OSError:
                return {"status": "partial", "matches": count}
            return {"status": "matched" if count else "absent", "matches": count}
        info = os.stat(local_path(path), follow_symlinks=False)
        return {"status": "present", "type": "dir" if stat.S_ISDIR(info.st_mode) else "file"}
    except FileNotFoundError:
        return {"status": "absent"}
    except LocalOnlyError:
        return {"status": "skipped"}
    except OSError:
        return {"status": "unreadable"}


def check_registry(key):
    found, incomplete = [], False
    for name, hive in (("HKCU", winreg.HKEY_CURRENT_USER), ("HKLM", winreg.HKEY_LOCAL_MACHINE)):
        try:
            with winreg.OpenKey(hive, normalize(key)):
                found.append(name)
        except FileNotFoundError:
            continue
        except OSError:
            incomplete = True
    return {"status": "present" if found else ("unreadable" if incomplete else "absent"),
            "hives": found, "partial": incomplete}


def read_shared(path):
    path = local_path(path)
    handle = k32.CreateFileW(path, 0x80000000, 0x7, None, 3, 0x80, None)
    if handle == wt.HANDLE(-1).value or not handle:
        raise OSError("database_unreadable")
    try:
        size = ctypes.c_longlong()
        if not k32.GetFileSizeEx(handle, ctypes.byref(size)):
            raise OSError("database_size_unreadable")
        # 控制共享快照的内存占用；超出范围的数据库明确标为未读取。
        if size.value > 512 * 1024 * 1024:
            raise OSError("database_too_large")
        buffer = ctypes.create_string_buffer(size.value)
        read = wt.DWORD()
        if not k32.ReadFile(handle, buffer, size.value, ctypes.byref(read), None) or read.value != size.value:
            raise OSError("database_changed_or_unreadable")
        return buffer.raw
    finally:
        k32.CloseHandle(handle)


def masked_identifier(value):
    if not isinstance(value, str) or not value:
        return "未填写"
    if len(value) <= 4:
        return "••••"
    first = value[0] if value[0].isprintable() else "•"
    last = value[-1] if value[-1].isprintable() else "•"
    return first + "•••" + last


def site_label(value, store):
    if not isinstance(value, str):
        return "站点未知"
    try:
        if store == "cookies":
            value = value.lstrip(".")
            if any(c in value for c in "/\\@?#"):
                return "站点未知"
            value = "https://" + value
        parsed = urlsplit(value)
        hostname = parsed.hostname
        if parsed.scheme not in ("http", "https") or not hostname or len(hostname) > 253:
            return "站点未知"
        if hostname != "localhost" and "." not in hostname:
            return "站点未知"
        if not all(re.fullmatch(r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?", label) for label in hostname.split(".")):
            return "站点未知"
        return hostname
    except ValueError:
        return "站点未知"


def browser_database(path, store):
    try:
        path = local_path(path)
        before = os.stat(path)
        raw = read_shared(path)
        after = os.stat(path)
        wal = local_path(path + "-wal")
        has_wal = os.path.isfile(wal) and os.path.getsize(wal) > 0
        wal_mode = raw.startswith(b"SQLite format 3\x00") and (raw[18] == 2 or raw[19] == 2)
        if wal_mode:
            # 内存快照没有 WAL 文件；仅修改内存中的日志模式以读取已检查点化的主库。
            raw = raw[:18] + b"\x01\x01" + raw[20:]
        table, column = ("logins", "password_value") if store == "passwords" else ("cookies", "encrypted_value")
        connection = sqlite3.connect(":memory:")
        try:
            connection.deserialize(raw)
            connection.execute("PRAGMA query_only=ON")
            plain = "WHEN COALESCE(length(value), 0) > 0 THEN 'plain' " if store == "cookies" else ""
            classification = (f"CASE {plain}WHEN {column} IS NULL OR length({column}) = 0 THEN 'empty' "
                              f"WHEN substr(CAST({column} AS BLOB), 1, 3) = X'763130' THEN 'v10' "
                              f"WHEN substr(CAST({column} AS BLOB), 1, 3) = X'763230' THEN 'v20' ELSE 'other' END")
            source, identifier = ("origin_url", "username_value") if store == "passwords" else ("host_key", "name")
            counts = dict.fromkeys(("total", "v10", "v20", "other", "empty", "plain"), 0)
            records = []
            # 查询只返回分类和定位元信息；密码、Cookie 值及完整密文不会进入结果对象。
            for index, (kind, origin, name) in enumerate(connection.execute(
                    f"SELECT {classification}, {source}, {identifier} FROM {table}"), 1):
                counts["total"] += 1
                counts[kind] += 1
                records.append({"index": index, "encryption": kind, "site": site_label(origin, store),
                                "identifier": masked_identifier(name)})
        finally:
            connection.close()
        changed = (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns)
        return {"status": "partial" if has_wal or wal_mode or changed else "read", "wal": has_wal or wal_mode,
                "counts": counts, "records": records}
    except FileNotFoundError:
        return {"status": "absent"}
    except LocalOnlyError:
        return {"status": "skipped"}
    except (OSError, sqlite3.Error, OverflowError):
        return {"status": "unreadable"}


def browser_roots():
    for name, template, flat in (
        ("Chrome", r"%LOCALAPPDATA%\Google\Chrome\User Data", False),
        ("Edge", r"%LOCALAPPDATA%\Microsoft\Edge\User Data", False),
        ("Brave", r"%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data", False),
        ("Vivaldi", r"%LOCALAPPDATA%\Vivaldi\User Data", False),
        ("Opera", r"%APPDATA%\Opera Software\Opera Stable", True),
    ):
        yield name, template, flat


def browser_profiles(root, flat=False):
    root = local_path(root)
    if not os.path.isdir(root):
        return []
    profiles = [("主配置", root)] if flat else []
    with os.scandir(root) as entries:
        for entry in sorted(entries, key=lambda e: e.name):
            if entry.name == "Default" or re.fullmatch(r"Profile \d+", entry.name):
                # 使用固定别名，报告不保留自定义配置名称。
                local_path(entry.path)
                if entry.is_dir(follow_symlinks=False):
                    profiles.append(("配置 " + str(len(profiles) + 1), entry.path))
    return profiles


def scan_browsers(wallet_ids, skip_counts=False, skip_wallets=False):
    databases, wallets, coverage = [], [], []
    for browser, template, flat in browser_roots():
        try:
            root = expand(template)
            profiles = browser_profiles(root, flat)
            coverage.append({"browser": browser, "status": "present" if profiles else "absent"})
            for profile, directory in profiles:
                if not skip_counts:
                    for store, filename in (("passwords", "Login Data"), ("passwords", "Login Data For Account"),
                                            ("cookies", r"Network\Cookies"), ("cookies", "Cookies")):
                        result = browser_database(os.path.join(directory, filename), store)
                        databases.append({"browser": browser, "profile": profile, "store": store,
                                          "database": filename, **result})
                if not skip_wallets:
                    for extension_id in wallet_ids:
                        if not re.fullmatch(r"[a-p]{32}", extension_id):
                            continue
                        result = check_path(os.path.join(directory, "Extensions", extension_id))
                        if result["status"] != "absent":
                            wallets.append({"browser": browser, "profile": profile, "id": extension_id, **result})
        except (OSError, ValueError):
            coverage.append({"browser": browser, "status": "unreadable"})
    return databases, wallets, coverage


def owns_console():
    """打包版双击运行时，控制台只挂着引导进程和本进程；此时退出前暂停，便于阅读输出。"""
    buffer = (wt.DWORD * 4)()
    return 0 < k32.GetConsoleProcessList(buffer, 4) <= (2 if getattr(sys, "frozen", False) else 1)


def open_report(path):
    # 仅交给系统打开已写入的本地 HTML，不启动 HTTP 服务。
    os.startfile(local_path(path), "open")


def main(argv=None):
    parser = argparse.ArgumentParser(description="K2F 本地泄露面模拟 · 只读 · 脱敏 HTML 报告")
    parser.add_argument("--targets", default=str(Path(__file__).with_name("k2f_targets.json")), help="本地目标清单")
    parser.add_argument("--out", help="本地 HTML 报告路径（.html 或 .htm）")
    parser.add_argument("--quick", action="store_true", help="只检查目标元信息，跳过浏览器数据库和钱包扩展")
    parser.add_argument("--no-browser-count", action="store_true", help="跳过浏览器数据库统计")
    parser.add_argument("--no-open", action="store_true", help="生成报告后不自动打开浏览器")
    args = parser.parse_args(argv)
    if sys.version_info < (3, 11) or not hasattr(sqlite3.Connection, "deserialize"):
        print("需要包含 SQLite deserialize 支持的 Python 3.11+。", file=sys.stderr)
        return 2
    now = datetime.now()
    try:
        output = local_path(args.out or ("K2F_selfcheck_" + now.strftime("%Y%m%d_%H%M%S_%f") + ".html"))
        if Path(output).suffix.lower() not in (".html", ".htm"):
            parser.error("--out 必须使用 .html 或 .htm 扩展名")
        with open(local_path(args.targets), encoding="utf-8") as stream:
            targets = json.load(stream)
    except (OSError, ValueError):
        print("无法读取本地目标清单或使用指定输出路径；网络位置和重解析点会被跳过。", file=sys.stderr)
        return 2

    print("\n  K2F · 本地泄露面模拟\n  不上传数据 / 不解密凭据 / 不判定感染\n")
    ensure_environment()
    results = []
    print("  [1/3] 检查应用与鉴权目标…", flush=True)
    for item in targets.get("paths", []):
        if item.get("scope") == "excluded":
            continue
        results.append({"template": normalize(item["template"]), "category": item["category"],
                        "report_category": item.get("report_category", "其他开发工具"),
                        "kind": item.get("kind", "config"), **check_path(item["template"])})
    registry = []
    for item in targets.get("registry", []):
        if item.get("scope") != "excluded":
            registry.append({"key": normalize(item["key"]), "kind": item.get("kind", "config"),
                             **check_registry(item["key"])})

    print("  [2/3] 统计浏览器加密版本与钱包扩展…", flush=True)
    skip_counts = args.quick or args.no_browser_count
    databases, wallets, coverage = scan_browsers(targets.get("wallet_extensions", []), skip_counts, args.quick)
    report = {"generated_at": now.strftime("%Y-%m-%d %H:%M:%S"), "results": results,
              "registry": registry, "databases": databases, "wallets": wallets, "coverage": coverage,
              "skip_counts": skip_counts, "skip_wallets": args.quick}
    print("  [3/3] 生成脱敏 HTML 报告…", flush=True)
    try:
        # 独占创建避免覆盖已有报告或用户文件。
        with open(local_path(output), "x", encoding="utf-8") as stream:
            stream.write(render_report(report))
    except OSError:
        print("报告未写入：请使用可写的本地目录和未使用的文件名。", file=sys.stderr)
        return 2
    print("\n  报告已保存：" + output)
    print("  仅模拟可被读取的目标，不判断真实泄露。")
    if not args.no_open:
        try:
            open_report(output)
        except OSError:
            print("  无法自动打开默认浏览器，请手动打开上面的 HTML 文件。")
    return 0


if __name__ == "__main__":
    code = main()
    if getattr(sys, "frozen", False) and owns_console():
        input("\n  按回车键退出…")
    sys.exit(code)
