**中文** | [English](README.en.md) | [日本語](README.ja.md) | [한국어](README.ko.md)

# NIKKE K2F 泄露面自查工具

依据 NIKKE Launcher 供应链事件中 K2F 样本的采集清单，检查这些位置在本机是否存在，统计浏览器密码与 Cookie 的加密方式，生成本地 HTML 报告。

位置存在不等于数据已被读取或外传。本工具不检测感染，也不能确认是否已泄露；检查 K2F 运行痕迹请用 [Sheisback/nikke_malware_scanner](https://github.com/Sheisback/nikke_malware_scanner)。

## 下载运行

在 [Releases](https://github.com/Small-tailqwq/nikke-k2f-selfcheck/releases) 下载 `k2f-selfcheck.exe`，双击运行。报告保存在 exe 所在目录，并自动用默认浏览器打开。

exe 由 GitHub Actions 从本仓库源码构建（PyInstaller 单文件），同目录的 `.sha256` 文件可用于校验：

```powershell
Get-FileHash .\k2f-selfcheck.exe -Algorithm SHA256
```

PyInstaller 打包的程序可能被部分杀毒软件误报。不放心时可以直接用源码运行。

## 源码运行

需要 Windows 10/11 和 Python 3.11+，不需要安装依赖。

```powershell
python k2f_selfcheck.py
```

从源码运行时，报告默认保存在脚本目录。`--out` 的相对路径以启动时的工作目录为准，绝对路径按指定位置保存。

| 参数 | 用途 |
|---|---|
| `--lang` | 报告与输出语言：`zh`、`en`、`ja`、`ko`。默认跟随 Windows 显示语言，其他语言的系统使用英语 |
| `--out` | 指定报告路径（`.html` 或 `.htm`）。文件已存在时不会覆盖 |
| `--no-open` | 只保存报告，不打开浏览器 |
| `--quick` | 跳过 Chromium 数据库和钱包，仍检查其他目标 |
| `--no-browser-count` | 跳过浏览器数据库 |
| `--targets` | 指定目标清单，默认使用同目录的 `k2f_targets.json` |

退出码 `0` 表示报告已生成，`2` 表示运行环境、输入或写入失败。退出码与感染或泄露状态无关。

## 报告内容

打开报告时先弹出一段说明，6 秒后才能点击“我知道了”。正文依次给出：摘要、浏览器数据、凭据位置、钱包扩展、未完成检查和说明。

- **v10：高风险。** 以当前用户身份运行的程序可直接解密。逐个站点修改密码、退出其他设备的登录、开启两步验证。
- **未加密 Cookie：样本不读取。** 样本查询的是 `encrypted_value`。仅有 `value` 的记录单独列示，不计入本样本的高风险项。
- **未知格式：** 无法判断保护方式，按 v10 处理。
- **v20：较低。** 受应用绑定加密保护，需提权或注入浏览器进程才能解密。处理完 v10 后再退出重要站点的登录。
- **凭据位置：** 按工具分类列出存在的配置、凭据文件和密钥目录，并给出各类的轮换方法。程序目录和普通用户目录单独折叠，不算作凭据位置。

数量按记录或目标模板计算，不代表已泄露的凭据数量。

明细中，密码按记录列出站点、脱敏账号和浏览器；Cookie 按站点汇总数量。长列表按固定行高分块渲染，离屏部分由浏览器跳过，上万条记录也能直接展开。报告不含脚本，不加载外部资源。

## 检查范围与隐私

- 普通目标只检查路径和文件元信息。另检查项目配置文件、Firefox 的 `key4.db` / `logins.json`、GPG 密钥文件、`KUBECONFIG` 指向的文件及 NIKKE 凭据文件，不读取其秘密内容。
- 项目目录搜索到第 2 层，跳过 `.git` / `node_modules`，排除 `.example` / `.sample` / `.template` 文件。SSH 配置及 PuTTY / WinSCP 会话只用于查找外部密钥路径和密码字段是否存在。
- 环境变量在进程和用户/系统注册表中按样本规则筛选，报告只保留变量名；Windows 凭据管理器只计条目数。环境变量值、凭据内容和实际自定义路径不写入报告。
- Chromium 数据库共享只读载入内存，识别加密前缀，不解密、不写源文件。遍历 Chrome、Edge、Brave、Vivaldi、Opera 已知根目录的全部子配置目录；不扫描 Opera 根目录数据库或已知根目录以外的便携配置。钱包按样本仅检查 Chrome 中已安装扩展对应容器的 `.ldb` / `.sst` / `.log` 文件。
- 浏览器明细只保留站点主机名、配置序号和脱敏账号（4 字符以内完全隐藏，其余只留首尾字符）。网址路径、参数、密码、Cookie 名称与值、令牌和私钥不进入报告。站点列表和环境变量名仍属隐私，不要公开分享报告。
- 网络路径、映射网络驱动器和重解析点不检查。未设置的环境变量标为不适用；超过样本 4 MiB 上限的浏览器文件标为样本跳过；读取失败保留为未完成。有未合并 WAL 时只统计主库并标为不完整。

目标路径和检测规则来自 K2F LuaJIT bundle（SHA-256 `cc0ad05bfe85940a6067b3a72c182d3953339129206634141926d5d0b35973ec`）的静态解析。文件存在性提示用于判断潜在存储位置；工具不复现样本对配置、历史记录和会话内容的提取或解密。

## 相关项目

- [WormW/nikke_malware_analysis](https://github.com/WormW/nikke_malware_analysis)：事件与样本公开分析
- [Sheisback/nikke_malware_scanner](https://github.com/Sheisback/nikke_malware_scanner)：检查运行痕迹
- [Google：Windows 上的应用绑定加密](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)
