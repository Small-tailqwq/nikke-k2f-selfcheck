#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""K2F 泄露面自查：只读元信息和浏览器加密版本统计，生成脱敏 HTML。"""

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

from k2f_i18n import LANGS, t
from k2f_report import render_report
from k2f_detection import environment_candidate


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
k32.GetUserDefaultUILanguage.restype = wt.WORD
SAMPLE_MAX_READ_BYTES = 4 * 1024 * 1024


class LocalOnlyError(OSError):
    """该路径不能在纯本地范围内检查。"""


class UnsetEnvironmentError(OSError):
    """目标依赖的环境变量未设置。"""


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
            raise UnsetEnvironmentError("missing_environment")
        template = profile + template[1:]
    for match in re.finditer(r"%([^%]+)%|\$\{([^}]+)\}|\$([A-Za-z_][A-Za-z0-9_]*)", template):
        name = next(group for group in match.groups() if group is not None)
        if not os.environ.get(name):
            raise UnsetEnvironmentError("missing_environment")
    path = os.path.expandvars(template)
    if re.search(r"%[^%]+%|\$[A-Za-z_{]", path):
        raise UnsetEnvironmentError("missing_environment")
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
    except UnsetEnvironmentError:
        return {"status": "unset"}
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
        # stat 后仍需复查大小，以覆盖文件在打开前增长的情况。
        if size.value > SAMPLE_MAX_READ_BYTES:
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
        if before.st_size > SAMPLE_MAX_READ_BYTES:
            return {"status": "over_cap"}
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
            empty = "CASE WHEN COALESCE(length(value), 0) > 0 THEN 'plain' ELSE 'empty' END" if store == "cookies" else "'empty'"
            classification = (f"CASE WHEN {column} IS NULL OR length({column}) = 0 THEN {empty} "
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
        ("Opera", r"%APPDATA%\Opera Software\Opera Stable", False),
    ):
        yield name, template, flat


def browser_profiles(root, flat=False, failures=None):
    root = local_path(root)
    if not os.path.isdir(root):
        return []
    profiles = [("主配置", root)] if flat else []
    with os.scandir(root) as entries:
        for entry in sorted(entries, key=lambda e: e.name):
            try:
                local_path(entry.path)
                if entry.is_dir(follow_symlinks=False):
                    profiles.append(("配置 " + str(len(profiles) + 1), entry.path))
            except OSError:
                if failures is None:
                    raise
                failures.append(entry.path)
    return profiles


def wallet_container(extension_id):
    if extension_id in ("hnfanknocfeofbddgcijnmhnfnkdnaad", "aiifbnbfobpmeekipheeijimdpnlpgpp",
                        "gjagmgiddbbciopjhllkdnddhcglnemk"):
        return r"Local Storage\leveldb"
    if extension_id == "opcgpfmipidbgpenhmajoajpbobppdil":
        return "IndexedDB\\chrome-extension_" + extension_id + "_0.indexeddb.leveldb"
    return "Local Extension Settings\\" + extension_id


def check_wallet(directory, extension_id):
    installed = check_path(os.path.join(directory, "Extensions", extension_id))
    if installed["status"] != "present":
        return installed
    container = wallet_container(extension_id)
    count = 0
    try:
        with os.scandir(local_path(os.path.join(directory, container))) as entries:
            for entry in entries:
                if entry.name.endswith((".ldb", ".sst", ".log")):
                    local_path(entry.path)
                    if entry.is_file(follow_symlinks=False):
                        count += 1
    except FileNotFoundError:
        return {"status": "absent", "container": container}
    except OSError:
        return {"status": "partial", "matches": count, "container": container}
    return {"status": "matched" if count else "absent", "matches": count, "container": container}


def scan_browsers(wallet_ids, skip_counts=False, skip_wallets=False):
    databases, wallets, coverage = [], [], []
    for browser, template, flat in browser_roots():
        try:
            root = expand(template)
            failures = []
            profiles = browser_profiles(root, flat, failures)
            coverage.append({"browser": browser, "status": "partial" if failures else "present" if profiles else "absent"})
            for profile, directory in profiles:
                if not skip_counts:
                    for store, filename in (("passwords", "Login Data"), ("passwords", "Login Data For Account"),
                                            ("cookies", r"Network\Cookies"), ("cookies", "Cookies")):
                        result = browser_database(os.path.join(directory, filename), store)
                        databases.append({"browser": browser, "profile": profile, "store": store,
                                          "database": filename, **result})
                if not skip_wallets and browser == "Chrome":
                    for extension_id in wallet_ids:
                        if not re.fullmatch(r"[a-p]{32}", extension_id):
                            continue
                        result = check_wallet(directory, extension_id)
                        if result["status"] != "absent":
                            wallets.append({"browser": browser, "profile": profile, "id": extension_id, **result})
        except (OSError, ValueError):
            coverage.append({"browser": browser, "status": "unreadable"})
    return databases, wallets, coverage


def target_result(label, category, kind, result):
    return {"template": label, "category": category, "report_category": category, "kind": kind, **result}


def project_filename(name):
    name = name.lower()
    if name.endswith((".example", ".sample", ".template")):
        return False
    return (name in (".env", "mcp.json", ".mcp.json", "docker-compose.yml", "docker-compose.yaml", "config.ini")
            or ".env." in name or name.endswith((".env", ".tfvars", ".tfvars.json"))
            or re.fullmatch(r"appsettings.*\.json|application.*\.(?:ya?ml|properties)|credentials.*\.json|service-account.*\.json|secrets\..+", name) is not None)


def scan_project_files(template):
    count, incomplete = 0, False

    def walk(directory, depth):
        nonlocal count, incomplete
        try:
            with os.scandir(local_path(directory)) as entries:
                for entry in entries:
                    try:
                        if entry.name.lower() in ("node_modules", ".git"):
                            continue
                        local_path(entry.path)
                        if entry.is_dir(follow_symlinks=False):
                            if depth < 2:
                                walk(entry.path, depth + 1)
                        elif entry.is_file(follow_symlinks=False) and project_filename(entry.name):
                            count += 1
                    except OSError:
                        incomplete = True
        except OSError:
            incomplete = True

    initial = check_path(template)
    if initial["status"] != "present":
        return initial
    walk(expand(template), 0)
    return {"status": "partial" if incomplete else "matched" if count else "absent", "matches": count}


def registry_values(hive, path):
    with winreg.OpenKey(hive, path) as key:
        for index in range(winreg.QueryInfoKey(key)[1]):
            yield winreg.EnumValue(key, index)


def scan_environment(rules):
    results = []
    scopes = [("process", ((k, v, None) for k, v in os.environ.items())),
              ("HKCU", registry_values(winreg.HKEY_CURRENT_USER, r"Environment")),
              ("HKLM", registry_values(winreg.HKEY_LOCAL_MACHINE,
                                        r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"))]
    for scope, values in scopes:
        count = 0
        try:
            for name, value, _ in values:
                if environment_candidate(name, value, rules):
                    count += 1
                    results.append(target_result("env:" + scope + ":" + name, "环境变量", "environment", {"status": "present"}))
        except FileNotFoundError:
            pass
        except OSError:
            results.append(target_result("env:" + scope, "环境变量", "config", {"status": "partial", "matches": count}))
            continue
        if not count:
            results.append(target_result("env:" + scope, "环境变量", "config", {"status": "absent"}))
    return results


def credential_manager_count():
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    advapi.CredEnumerateW.argtypes = [wt.LPCWSTR, wt.DWORD, ctypes.POINTER(wt.DWORD), ctypes.POINTER(ctypes.c_void_p)]
    advapi.CredEnumerateW.restype = wt.BOOL
    advapi.CredFree.argtypes = [ctypes.c_void_p]
    advapi.CredFree.restype = None
    count, buffer = wt.DWORD(), ctypes.c_void_p()
    if not advapi.CredEnumerateW(None, 0, ctypes.byref(count), ctypes.byref(buffer)):
        return {"status": "absent" if ctypes.get_last_error() == 1168 else "unreadable"}
    try:
        # 只取数量，不解引用任何 CredentialBlob 或目标名称。
        return {"status": "matched" if count.value else "absent", "matches": count.value}
    finally:
        advapi.CredFree(buffer)


def scan_gpg():
    label = "$GNUPGHOME"
    directory = os.environ.get("GNUPGHOME")
    if not directory:
        label = r"HKCU\Software\GNU\GnuPG:HomeDir"
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\GNU\GnuPG") as key:
                directory, _ = winreg.QueryValueEx(key, "HomeDir")
        except FileNotFoundError:
            directory = None
        except OSError:
            return [target_result(label, "SSH、GPG 与密钥", "config", {"status": "unreadable"})]
    if not directory:
        directory, label = r"%APPDATA%\gnupg", r"%APPDATA%\gnupg"
    return [target_result(label + "\\" + suffix, "SSH、GPG 与密钥", "key_material",
                          check_path(str(directory) + "\\" + suffix))
            for suffix in ("pubring.kbx", "secring.gpg", r"private-keys-v1.d\*.key")]


def scan_firefox():
    results = []
    label = r"%APPDATA%\Mozilla\Firefox\Profiles"
    try:
        failures = []
        profiles = browser_profiles(expand(label), failures=failures)
        for index, (_, directory) in enumerate(profiles, 1):
            for filename in ("key4.db", "logins.json"):
                path = os.path.join(directory, filename)
                result = check_path(path)
                if result["status"] == "present":
                    try:
                        if os.stat(local_path(path)).st_size > SAMPLE_MAX_READ_BYTES:
                            result = {"status": "over_cap"}
                    except OSError:
                        result = {"status": "unreadable"}
                results.append(target_result(label + "\\[" + str(index) + "]\\" + filename, "浏览器", "credential",
                                             result))
        if failures or not profiles:
            results.append(target_result(label, "浏览器", "credential", {"status": "partial" if failures else "absent"}))
    except UnsetEnvironmentError:
        results.append(target_result(label, "浏览器", "credential", {"status": "unset"}))
    except OSError:
        results.append(target_result(label, "浏览器", "credential", {"status": "unreadable"}))
    return results


def scan_kube():
    value = os.environ.get("KUBECONFIG")
    if not value:
        return [target_result("$KUBECONFIG", "云服务与运维", "credential", {"status": "unset"})]
    return [target_result("$KUBECONFIG[" + str(i) + "]", "云服务与运维", "credential", check_path(path))
            for i, path in enumerate(filter(None, value.split(";")), 1)]


def scan_ssh_references():
    results, seen = [], set()
    category = "SSH、GPG 与密钥"

    def read_config(template, depth):
        if depth > 3:
            return
        label = r"~\.ssh\config" if depth == 0 else "SSH Include [" + str(len(seen) + 1) + "]"
        try:
            path = local_path(expand(template))
            if os.path.normcase(path) in seen:
                return
            seen.add(os.path.normcase(path))
            # 配置只用于定位 IdentityFile；私钥文件不打开。
            with open(path, "r", encoding="utf-8-sig", errors="replace") as stream:
                content = stream.read(4 * 1024 * 1024 + 1)
            if len(content) > 4 * 1024 * 1024:
                raise OSError("config_too_large")
            active_host = False
            identity = None

            def add_identity():
                if identity:
                    results.append(target_result("SSH IdentityFile [" + str(len(results) + 1) + "]", category,
                                                 "key_material", check_path(identity)))

            for line in content.splitlines():
                match = re.match(r"^\s*([A-Za-z0-9]+)\s+(.+)$", line)
                if not match:
                    continue
                key, value = match.groups()
                value = re.sub(r"\s+#.*$|^#.*$", "", value.strip().strip("\"'"))
                key = key.lower()
                if key == "host":
                    add_identity()
                    identity = None
                    active_host = any(not re.search(r"[*?]", alias) for alias in value.split())
                elif key == "identityfile" and active_host:
                    identity = value
                elif key == "include":
                    for include in value.split():
                        if not include.startswith(("/", "~")):
                            include = "~\\.ssh\\" + include
                        read_config(include, depth + 1)
            add_identity()
        except FileNotFoundError:
            if depth:
                results.append(target_result(label, category, "config", {"status": "absent"}))
        except UnsetEnvironmentError:
            results.append(target_result(label, category, "config", {"status": "unset"}))
        except OSError:
            results.append(target_result(label, category, "config", {"status": "unreadable"}))

    read_config(r"~\.ssh\config", 0)
    return results


def scan_sessions():
    results = []
    for tool, path in (("PuTTY", r"Software\SimonTatham\PuTTY\Sessions"),
                       ("WinSCP", r"Software\Martin Prikryl\WinSCP 2\Sessions")):
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path) as root:
                for index in range(winreg.QueryInfoKey(root)[0]):
                    label = tool + " [" + str(index + 1) + "]"
                    try:
                        with winreg.OpenKey(root, winreg.EnumKey(root, index)) as session:
                            for name in ("PublicKeyFile", "Password") if tool == "WinSCP" else ("PublicKeyFile",):
                                try:
                                    value, _ = winreg.QueryValueEx(session, name)
                                except FileNotFoundError:
                                    continue
                                if isinstance(value, str) and value:
                                    result = check_path(value) if name == "PublicKeyFile" else {"status": "present"}
                                    results.append(target_result(label + ":" + name, "SSH、GPG 与密钥",
                                                                 "key_material" if name == "PublicKeyFile" else "store", result))
                    except OSError:
                        results.append(target_result(label, "SSH、GPG 与密钥", "config", {"status": "unreadable"}))
        except FileNotFoundError:
            continue
        except OSError:
            results.append(target_result(tool + " Sessions", "SSH、GPG 与密钥", "config", {"status": "unreadable"}))
    return results


def scan_additional(targets):
    results = []
    for template in targets.get("project_roots", []):
        results.append(target_result(template, "项目配置", "config", scan_project_files(template)))
    if targets.get("additional_surfaces"):
        results.extend(scan_environment(targets.get("detector_rules", [])))
        results.append(target_result("Windows Credential Manager", "Windows 凭据管理器", "store", credential_manager_count()))
        results.extend(scan_kube())
        results.extend(scan_gpg())
        results.extend(scan_firefox())
        results.extend(scan_ssh_references())
        results.extend(scan_sessions())
    return results


def owns_console():
    """打包版双击运行时，控制台只挂着引导进程和本进程；此时退出前暂停，便于阅读输出。"""
    buffer = (wt.DWORD * 4)()
    return 0 < k32.GetConsoleProcessList(buffer, 4) <= (2 if getattr(sys, "frozen", False) else 1)


def open_report(path):
    # 仅交给系统打开已写入的本地 HTML，不启动 HTTP 服务。
    os.startfile(local_path(path), "open")


def detect_language():
    """按 Windows 显示语言选择报告语言；中文、日语、韩语以外的系统使用英语。"""
    try:
        primary = k32.GetUserDefaultUILanguage() & 0x3FF
    except (AttributeError, OSError):
        return "en"
    return {0x04: "zh", 0x11: "ja", 0x12: "ko"}.get(primary, "en")


LANGUAGE = "zh"


def say(key, *, file=None, flush=False, prefix="  ", suffix=""):
    print(prefix + t(LANGUAGE, key) + suffix, file=file, flush=flush)


def main(argv=None):
    global LANGUAGE
    for stream in (sys.stdout, sys.stderr):
        # 输出被重定向到非 UTF-8 代码页（如 CI 的 cp1252）时，替换无法编码的字符而不是崩溃。
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")
    choices = ("auto",) + LANGS
    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument("--lang", choices=choices, default="auto")
    known, _ = pre.parse_known_args(argv)
    LANGUAGE = detect_language() if known.lang == "auto" else known.lang
    T = lambda key: t(LANGUAGE, key)

    parser = argparse.ArgumentParser(description=T("cli.description"))
    parser.add_argument("--targets", default=str(Path(__file__).with_name("k2f_targets.json")), help=T("cli.targets"))
    parser.add_argument("--out", help=T("cli.out"))
    parser.add_argument("--quick", action="store_true", help=T("cli.quick"))
    parser.add_argument("--no-browser-count", action="store_true", help=T("cli.no_browser_count"))
    parser.add_argument("--no-open", action="store_true", help=T("cli.no_open"))
    parser.add_argument("--lang", choices=choices, default="auto", help=T("cli.lang"))
    args = parser.parse_args(argv)
    if sys.version_info < (3, 11) or not hasattr(sqlite3.Connection, "deserialize"):
        say("cli.need_python", file=sys.stderr, prefix="")
        return 2
    now = datetime.now()
    try:
        output = local_path(args.out or ("K2F_selfcheck_" + now.strftime("%Y%m%d_%H%M%S_%f") + ".html"))
        if Path(output).suffix.lower() not in (".html", ".htm"):
            parser.error(T("cli.bad_ext"))
        with open(local_path(args.targets), encoding="utf-8") as stream:
            targets = json.load(stream)
    except (OSError, ValueError):
        say("cli.bad_input", file=sys.stderr, prefix="")
        return 2

    say("cli.banner", prefix="\n  ", suffix="\n")
    ensure_environment()
    results = []
    say("cli.step1", flush=True)
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
    results.extend(scan_additional(targets))

    say("cli.step2", flush=True)
    skip_counts = args.quick or args.no_browser_count
    databases, wallets, coverage = scan_browsers(targets.get("wallet_extensions", []), skip_counts, args.quick)
    report = {"generated_at": now.strftime("%Y-%m-%d %H:%M:%S"), "results": results,
              "registry": registry, "databases": databases, "wallets": wallets, "coverage": coverage,
              "skip_counts": skip_counts, "skip_wallets": args.quick}
    say("cli.step3", flush=True)
    try:
        # 独占创建避免覆盖已有报告或用户文件。
        with open(local_path(output), "x", encoding="utf-8") as stream:
            stream.write(render_report(report, LANGUAGE))
    except OSError:
        say("cli.write_failed", file=sys.stderr, prefix="")
        return 2
    say("cli.saved", prefix="\n  ", suffix=output)
    say("cli.note")
    if not args.no_open:
        try:
            open_report(output)
        except OSError:
            say("cli.open_failed")
    return 0


if __name__ == "__main__":
    code = main()
    if getattr(sys, "frozen", False) and owns_console():
        input("\n  " + t(LANGUAGE, "cli.press_enter"))
    sys.exit(code)
