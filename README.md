# NIKKE K2F 离线自查工具

检查本机是否留有 NIKKE Launcher 供应链事件（K2F）的运行痕迹，以及样本字符串表还原出的采集目标在本机是否存在。

**纯离线、只读、不上传。** 不执行样本，不读取文件内容，不解析密码，不联网。

## 原理

基于公开分析中的 K2F LuaJIT bundle（SHA-256 `cc0ad05bfe85940a6067b3a72c182d3953339129206634141926d5d0b35973ec`）字符串表：

- 224 条采集路径模板（AI 工具、云密钥、SSH/GPG、浏览器、钱包、Shell 历史、CI token 等）
- 4 个注册表键
- 28 个钱包扩展 ID
- 运行痕迹：HKCU CLSID、`PlatformExperienceHelper` 下的 64-hex DLL、`k2f_chan`、`k2f.agent.state`、`%TEMP%\k2f-*`、`insight.bundle` 下载记录

## 用法

```powershell
python k2f_selfcheck.py
```

不带参数时自动探测 NIKKE 安装目录、检查运行痕迹和采集目标，并在当前目录生成带时间戳的 Markdown 报告。

```powershell
python k2f_selfcheck.py --nikke-launcher "D:\NIKKE" --out report.md
python k2f_selfcheck.py --quick
```

要求：Windows 10/11、Python 3.10+、普通用户权限即可。

## 判定阶段

| 阶段 | 含义 |
|---|---|
| 0 | 未发现已知 K2F 痕迹（不等于绝对未感染） |
| 1 | 发现 `insight.bundle` 下载尝试，执行未确认 |
| 2 | 发现 `k2f_chan` 或 `k2f.agent.state`，执行痕迹 |
| 3 | 发现 CLSID 或 DLL 持久化 |

## 输出

一份 Markdown 报告：

- 判定阶段与痕迹明细
- 采集目标：存在 / 共多少项（按类别展开，未命中折叠）
- 浏览器数据库规模（只计数，不解密）
- 钱包扩展匹配情况

## 边界

- “存在”只代表样本会查找该目标，不代表它已经被读取或上传。
- 无痕迹不等于绝对未感染；需要结合 Launcher 日志、SRUM、防火墙日志。
- 工具不能判断已经上传了什么。

## 相关项目

- [WormW/nikke_malware_analysis](https://github.com/WormW/nikke_malware_analysis) —— 事件与样本公开分析
- [Sheisback/nikke_malware_scanner](https://github.com/Sheisback/nikke_malware_scanner) —— 感染判定与证据收集工具
