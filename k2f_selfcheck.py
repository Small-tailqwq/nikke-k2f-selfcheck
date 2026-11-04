#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""K2F 离线自查工具。

用途：检查本机是否留有 K2F（NIKKE Launcher 供应链事件）的运行痕迹，
以及样本字符串表还原出的采集目标在本机是否存在。

特点：
- 纯离线：不联网、不上传、不执行任何样本。
- 只读：只做存在性/计数，不读取文件内容，不解析密码。
- 结果写入一份 Markdown 报告，供用户自己查看。

用法：
  python k2f_selfcheck.py
  python k2f_selfcheck.py --nikke-launcher "D:\NIKKE" --out report.md
  python k2f_selfcheck.py --quick          # 只查运行痕迹，不扫采集目标
"""

import argparse
import ctypes
import ctypes.wintypes as wt
import glob
import json
import os
import re
import sqlite3
import sys
import winreg
from datetime import datetime

GENERIC_READ = 0x80000000
FILE_SHARE_ALL = 0x7
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x80
INVALID_HANDLE_VALUE = -1

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
k32.CreateFileW.restype = wt.HANDLE
k32.CreateFileW.argtypes = [wt.LPCWSTR, wt.DWORD, wt.DWORD, wt.LPVOID, wt.DWORD, wt.DWORD, wt.HANDLE]
k32.ReadFile.argtypes = [wt.HANDLE, wt.LPVOID, wt.DWORD, ctypes.POINTER(wt.DWORD), wt.LPVOID]
k32.GetFileSize.argtypes = [wt.HANDLE, ctypes.POINTER(wt.DWORD)]
k32.GetFileSize.restype = wt.DWORD
k32.CloseHandle.argtypes = [wt.HANDLE]


def ensure_environment():
    """在精简环境里从注册表补齐 USERPROFILE/APPDATA 等变量。"""
    places = {
        "USERPROFILE": [("HKCU", r"Volatile Environment"), ("HKLM", r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment")],
        "APPDATA": [("HKCU", r"Volatile Environment"), ("HKCU", r"Environment")],
        "LOCALAPPDATA": [("HKCU", r"Volatile Environment"), ("HKCU", r"Environment")],
        "TEMP": [("HKCU", r"Environment")],
        "TMP": [("HKCU", r"Environment")],
        "COMPUTERNAME": [("HKLM", r"SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName")],
    }
    hives = {"HKCU": winreg.HKEY_CURRENT_USER, "HKLM": winreg.HKEY_LOCAL_MACHINE}
    for name, candidates in places.items():
        if os.environ.get(name):
            continue
        for hive_name, key in candidates:
            try:
                h = winreg.OpenKey(hives[hive_name], key)
                value, _ = winreg.QueryValueEx(h, "ComputerName" if name == "COMPUTERNAME" else name)
                h.Close()
                if value:
                    os.environ[name] = str(value)
                    break
            except OSError:
                continue
    if not os.environ.get("USERPROFILE"):
        os.environ["USERPROFILE"] = os.path.expanduser("~")


def read_shared(path):
    h = k32.CreateFileW(path, GENERIC_READ, FILE_SHARE_ALL, None, OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL, None)
    if h == INVALID_HANDLE_VALUE or not h:
        raise OSError(ctypes.get_last_error(), "CreateFileW")
    try:
        size = k32.GetFileSize(h, None)
        buf = ctypes.create_string_buffer(size)
        read = wt.DWORD(0)
        if not k32.ReadFile(h, buf, size, ctypes.byref(read), None):
            raise OSError(ctypes.get_last_error(), "ReadFile")
        return buf.raw[:read.value]
    finally:
        k32.CloseHandle(h)


def normalize(t):
    return t.replace("\\\\", "\\")


def expand(t):
    t = normalize(t)
    t = t.replace("~", os.environ.get("USERPROFILE", ""))
    return os.path.expandvars(t)


def check_path(template):
    p = expand(template)
    if any(c in p for c in "*?"):
        hits = glob.glob(p, recursive=True)
        return {"status": "matched" if hits else "absent", "path": p, "matches": len(hits)}
    try:
        if os.path.isdir(p):
            return {"status": "present", "path": p, "type": "dir"}
        if os.path.isfile(p):
            return {"status": "present", "path": p, "type": "file", "size": os.path.getsize(p)}
    except OSError:
        pass
    return {"status": "absent", "path": p}


def check_registry(key):
    for hive_name, hive in (("HKCU", winreg.HKEY_CURRENT_USER), ("HKLM", winreg.HKEY_LOCAL_MACHINE)):
        try:
            h = winreg.OpenKey(hive, key)
            h.Close()
            return {"status": "present", "hive": hive_name}
        except OSError:
            continue
    return {"status": "absent"}


def find_nikke_launcher(explicit=None):
    if explicit and os.path.isdir(explicit):
        return explicit
    env = os.environ.get("NIKKE_LAUNCHER")
    if env and os.path.isdir(env):
        return env
    for drive in "CDEFGHIJKLMNOPQRSTUVWXYZ":
        for name in ("NIKKE", "NIKKE_HMT", "NIKKE Launcher"):
            candidate = drive + ":\\" + name
            if os.path.isdir(os.path.join(candidate, "Launcher")):
                return candidate
    for pf in (os.environ.get("ProgramFiles"), os.environ.get("ProgramFiles(x86)")):
        if pf:
            candidate = os.path.join(pf, "NIKKE")
            if os.path.isdir(os.path.join(candidate, "Launcher")):
                return candidate
    return None


def check_traces(launcher_dir):
    traces = []
    clsid = r"Software\Classes\CLSID\{E77CC89B-7401-4C04-8CED-149DB35ADD04}"
    traces.append({"name": "HKCU CLSID 劫持键", **check_registry(clsid)})

    local = os.environ.get("LOCALAPPDATA", "")
    for label, base in (
        ("Chrome", os.path.join(local, "Google", "Chrome", "User Data", "PlatformExperienceHelper")),
        ("Edge", os.path.join(local, "Microsoft", "Edge", "User Data", "PlatformExperienceHelper")),
    ):
        found = []
        if os.path.isdir(base):
            for name in os.listdir(base):
                sub = os.path.join(base, name)
                if re.fullmatch(r"[0-9a-fA-F]{64}", name) and os.path.isdir(sub):
                    dll = os.path.join(sub, "platform_experience_helper.dll")
                    if os.path.isfile(dll):
                        found.append(dll)
        traces.append({"name": label + " PlatformExperienceHelper 64-hex DLL",
                       "status": "present" if found else "absent", "paths": found})

    temp = os.environ.get("TEMP", "")
    temp_hits = []
    if os.path.isdir(temp):
        for name in os.listdir(temp):
            if name.lower().startswith("k2f"):
                temp_hits.append(os.path.join(temp, name))
    traces.append({"name": "%TEMP% 下的 k2f-* 文件",
                   "status": "present" if temp_hits else "absent", "paths": temp_hits})

    state_hits = []
    for d in (
        os.path.join(os.environ.get("APPDATA", ""), "nikke_launcher", "tbs_cache", "Local Storage", "leveldb"),
        os.path.join(os.environ.get("APPDATA", ""), "nikke_launcher_hmt", "tbs_cache", "Local Storage", "leveldb"),
    ):
        if not os.path.isdir(d):
            continue
        for name in os.listdir(d):
            p = os.path.join(d, name)
            try:
                with open(p, "rb") as f:
                    if b"k2f.agent.state" in f.read(4 * 1024 * 1024):
                        state_hits.append(p)
            except OSError:
                pass
    traces.append({"name": "Launcher Local Storage 中的 k2f.agent.state",
                   "status": "present" if state_hits else "absent", "paths": state_hits})

    log_result = {"name": "Launcher debug.log 中的 k2f_chan", "status": "not_checked"}
    download_result = {"name": "Launcher 日志中的 insight.bundle 下载记录", "status": "not_checked"}
    if launcher_dir:
        log_path = os.path.join(launcher_dir, "Launcher", "intl_service", "debug.log")
        if os.path.isfile(log_path):
            hits = []
            with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    if re.search(r"k2f_chan|adopted|agent started as", line):
                        hits.append(line.strip()[:200])
            log_result = {"name": "Launcher debug.log 中的 k2f_chan",
                          "status": "present" if hits else "absent",
                          "path": log_path, "hits": hits[:5]}
        else:
            log_result = {"name": "Launcher debug.log 中的 k2f_chan",
                          "status": "file_missing", "path": log_path}

        tiny_dir = os.path.join(launcher_dir, "Launcher", "log", "tinyget")
        download_hits = []
        success = failed = False
        if os.path.isdir(tiny_dir):
            for name in os.listdir(tiny_dir):
                if not name.lower().endswith(".log"):
                    continue
                try:
                    with open(os.path.join(tiny_dir, name), "r", encoding="latin-1", errors="ignore") as f:
                        for line in f:
                            if "insight.bundle" in line or "analytics.insightjs.com" in line:
                                download_hits.append(name + ": " + line.strip()[:200])
                                if "lua downloaded to" in line or "total=205135" in line:
                                    success = True
                                if "curl_error=" in line or "curl perform failed" in line:
                                    failed = True
                except OSError:
                    pass
        outcome = "success" if success else ("failed" if failed else "unknown")
        download_result = {"name": "Launcher 日志中的 insight.bundle 下载记录",
                           "status": "present" if download_hits else "absent",
                           "outcome": outcome,
                           "hits": download_hits[:5]}
    traces.append(log_result)
    traces.append(download_result)
    return traces


def compute_stage(traces):
    status = {t["name"]: t.get("status") for t in traces}
    if status.get("HKCU CLSID 劫持键") == "present" or any(
        status.get(n) == "present" for n in status if n.endswith("64-hex DLL")):
        return 3, "发现持久化痕迹（CLSID 或 DLL）"
    if status.get("Launcher debug.log 中的 k2f_chan") == "present" or \
       status.get("Launcher Local Storage 中的 k2f.agent.state") == "present":
        return 2, "发现 K2F 执行痕迹（k2f_chan 或 agent.state）"
    if status.get("Launcher 日志中的 insight.bundle 下载记录") == "present":
        dl = next((t for t in traces if t["name"] == "Launcher 日志中的 insight.bundle 下载记录"), {})
        if dl.get("outcome") == "failed":
            return 1, "发现 insight.bundle 下载尝试（失败），执行未确认"
        return 1, "发现 insight.bundle 下载尝试，执行未确认"
    return 0, "未发现已知 K2F 痕迹"


def check_wallets(ids):
    matches = []
    local = os.environ.get("LOCALAPPDATA", "")
    for browser, base in (
        ("Chrome", os.path.join(local, "Google", "Chrome", "User Data")),
        ("Edge", os.path.join(local, "Microsoft", "Edge", "User Data")),
    ):
        for prof in ("Default", "Profile 1", "Profile 2"):
            ext_dir = os.path.join(base, prof, "Extensions")
            if not os.path.isdir(ext_dir):
                continue
            for eid in ids:
                if os.path.isdir(os.path.join(ext_dir, eid)):
                    matches.append({"browser": browser, "profile": prof, "id": eid})
    return matches


def count_browser_rows(user_data_dir):
    out = {}
    for profile in ("Default", "Profile 1", "Profile 2"):
        pdir = os.path.join(user_data_dir, profile)
        for label, rel in (("login_data", ("Login Data",)), ("cookies", ("Network", "Cookies"))):
            p = os.path.join(pdir, *rel)
            if not os.path.isfile(p):
                continue
            try:
                raw = read_shared(p)
                con = sqlite3.connect(":memory:")
                con.deserialize(raw)
                table = "logins" if label == "login_data" else "cookies"
                try:
                    n = con.execute("SELECT COUNT(*) FROM " + table).fetchone()[0]
                    out.setdefault(profile, {})[label] = n
                except sqlite3.Error:
                    out.setdefault(profile, {})[label] = "unreadable"
                con.close()
            except OSError as exc:
                out.setdefault(profile, {})[label] = "locked(%s)" % exc.errno
    return out


def fmt_status(item):
    s = item.get("status")
    if s == "present":
        if item.get("outcome") == "failed":
            return "存在（下载失败）"
        if item.get("outcome") == "success":
            return "存在（下载成功）"
        if item.get("type") == "dir":
            return "存在（目录）"
        if item.get("size") is not None:
            return "存在（文件 %d 字节）" % item["size"]
        return "存在"
    if s == "matched":
        return "通配符匹配 %d 项" % item.get("matches", 0)
    if s == "absent":
        return "不存在"
    if s == "file_missing":
        return "日志文件不存在"
    if s == "not_checked":
        return "未检查"
    return str(s)


def main():
    ap = argparse.ArgumentParser(description="K2F 离线自查（只读，不上传）")
    ap.add_argument("--targets", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "k2f_targets.json"))
    ap.add_argument("--out", default=None, help="报告路径（默认当前目录，带时间戳）")
    ap.add_argument("--nikke-launcher", default=None, help="NIKKE 根目录，例如 D:\\NIKKE；不填会自动探测")
    ap.add_argument("--quick", action="store_true", help="只查运行痕迹，不扫采集目标")
    ap.add_argument("--no-browser-count", action="store_true")
    args = ap.parse_args()

    ensure_environment()
    launcher = find_nikke_launcher(args.nikke_launcher)
    if not launcher:
        print("[提示] 未自动找到 NIKKE 安装目录；日志检查会被跳过。可用 --nikke-launcher 指定。")

    if not os.path.isfile(args.targets):
        print("找不到目标清单: " + args.targets, file=sys.stderr)
        return 2
    with open(args.targets, "r", encoding="utf-8") as f:
        data = json.load(f)

    traces = check_traces(launcher)
    stage, stage_text = compute_stage(traces)

    results = []
    if not args.quick:
        for item in data.get("paths", []):
            r = check_path(item["template"])
            r["category"] = item["category"]
            r["template"] = item["template"]
            results.append(r)

    present = [r for r in results if r["status"] == "present"]
    matched = [r for r in results if r["status"] == "matched"]
    absent = [r for r in results if r["status"] not in ("present", "matched")]
    regs = []
    for item in data.get("registry", []):
        r = check_registry(item["key"])
        r["key"] = item["key"]
        regs.append(r)

    browser_counts = {}
    if not args.no_browser_count and not args.quick:
        local = os.environ.get("LOCALAPPDATA", "")
        for label, path in (
            ("Chrome", os.path.join(local, "Google", "Chrome", "User Data")),
            ("Edge", os.path.join(local, "Microsoft", "Edge", "User Data")),
        ):
            if os.path.isdir(path):
                browser_counts[label] = count_browser_rows(path)

    wallets = check_wallets(data.get("wallet_extensions", [])) if not args.quick else []

    out_path = args.out or ("K2F_selfcheck_" + datetime.now().strftime("%Y%m%d_%H%M%S") + ".md")

    lines = []
    lines.append("# K2F 离线自查报告")
    lines.append("")
    lines.append("- 生成时间：" + datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    lines.append("- 主机：" + os.environ.get("COMPUTERNAME", "unknown"))
    lines.append("- 样本：" + data.get("source", {}).get("sample_sha256", "unknown"))
    lines.append("- NIKKE 目录：" + (launcher or "未找到"))
    lines.append("- 说明：只做存在性/计数，不读取文件内容、不联网、不写运行日志。")
    lines.append("")
    lines.append("## 判定")
    lines.append("")
    lines.append("**阶段 %d：%s**" % (stage, stage_text))
    lines.append("")
    lines.append("| 检查项 | 状态 |")
    lines.append("|---|---|")
    for t in traces:
        lines.append("| %s | %s |" % (t["name"], fmt_status(t)))
    lines.append("")
    if stage >= 2:
        lines.append("发现执行或持久化痕迹，建议按完整失陷处置：轮换凭据、隔离主机。")
    elif stage == 1:
        lines.append("只发现下载尝试，未确认执行；建议保留日志并复查网络记录。")
    else:
        lines.append("未发现已知 K2F 痕迹；这不等于绝对未感染，需结合日志完整性判断。")
    lines.append("")

    if not args.quick:
        lines.append("## 采集目标")
        lines.append("")
        lines.append("存在 %d 项，通配符匹配 %d 项，未命中 %d 项。"
                     % (len(present), len(matched), len(absent)))
        lines.append("")
        by_cat = {}
        for r in results:
            by_cat.setdefault(r["category"], []).append(r)
        for cat in sorted(by_cat, key=lambda c: -len(by_cat[c])):
            items = by_cat[cat]
            hit = [r for r in items if r["status"] in ("present", "matched")]
            if not hit:
                continue
            lines.append("### %s（存在 %d / 共 %d 项）" % (cat, len(hit), len(items)))
            lines.append("")
            lines.append("| 目标 | 状态 |")
            lines.append("|---|---|")
            for r in hit:
                lines.append("| %s | %s |" % (r["template"], fmt_status(r)))
            lines.append("")
        if regs:
            lines.append("### 注册表")
            lines.append("")
            lines.append("| 键 | 状态 |")
            lines.append("|---|---|")
            for r in regs:
                lines.append("| %s | %s |" % (r["key"], fmt_status(r)))
            lines.append("")
        if browser_counts:
            lines.append("## 浏览器数据库")
            lines.append("")
            for browser, profiles in browser_counts.items():
                for profile, counts in profiles.items():
                    parts = []
                    if "login_data" in counts:
                        parts.append("Login Data %s 条" % counts["login_data"])
                    if "cookies" in counts:
                        parts.append("Cookies %s 条" % counts["cookies"])
                    lines.append("- %s / %s：%s" % (browser, profile, "，".join(parts)))
            lines.append("")
        lines.append("## 钱包扩展")
        lines.append("")
        if wallets:
            lines.append("发现 %d 个样本目标中的钱包扩展：" % len(wallets))
            for w in wallets:
                lines.append("- " + w["browser"] + " / " + w["profile"] + "：" + w["id"])
        else:
            lines.append("未发现样本目标中的 28 个钱包扩展。")
        lines.append("")

    lines.append("## 边界")
    lines.append("")
    lines.append("- “存在”只表示样本会查找该目标，不代表它已经被读取或上传。")
    lines.append("- 工具不能判断已经上传了什么；确认外传需要 SRUM、防火墙/代理日志或 Launcher 日志。")
    lines.append("- 报告不含文件内容、密码或账户标识。")

    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print("报告已写入: " + out_path)
    print("阶段 %d：%s" % (stage, stage_text))
    print("采集目标：存在 %d，通配符匹配 %d，未命中 %d" % (len(present), len(matched), len(absent)))
    return 0 if stage < 2 else 1


if __name__ == "__main__":
    sys.exit(main())
