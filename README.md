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

| 参数 | 用途 |
|---|---|
| `--lang` | 报告与输出语言：`zh`、`en`、`ja`、`ko`。默认跟随 Windows 显示语言，其他语言的系统使用英语 |
| `--out` | 指定报告路径（`.html` 或 `.htm`）。文件已存在时不会覆盖 |
| `--no-open` | 只保存报告，不打开浏览器 |
| `--quick` | 跳过浏览器数据库和钱包扩展，只检查路径 |
| `--no-browser-count` | 跳过浏览器数据库 |
| `--targets` | 指定目标清单，默认使用同目录的 `k2f_targets.json` |

退出码 `0` 表示报告已生成，`2` 表示运行环境、输入或写入失败。退出码与感染或泄露状态无关。

## 报告内容

打开报告时先弹出一段说明，6 秒后才能点击“我知道了”。正文依次给出：摘要、浏览器数据、凭据位置、钱包扩展、未完成检查和说明。

- **v10：高风险。** 以当前用户身份运行的程序可直接解密。逐个站点修改密码、退出其他设备的登录、开启两步验证。
- **未加密 Cookie：高风险。** 复制后即可使用，在对应站点退出登录使会话失效。
- **未知格式：** 无法判断保护方式，按 v10 处理。
- **v20：较低。** 受应用绑定加密保护，需提权或注入浏览器进程才能解密。处理完 v10 后再退出重要站点的登录。
- **凭据位置：** 按工具分类列出存在的配置、凭据文件和密钥目录，并给出各类的轮换方法。程序目录和普通用户目录单独折叠，不算作凭据位置。

数量按记录或目标模板计算，不代表已泄露的凭据数量。

明细中，密码按记录列出站点、脱敏账号和浏览器；Cookie 按站点汇总数量。长列表按固定行高分块渲染，离屏部分由浏览器跳过，上万条记录也能直接展开。报告不含脚本，不加载外部资源。

## 检查范围与隐私

- 普通目标只检查路径或注册表键是否存在，不打开文件，不读取键值。
- 浏览器数据库以共享只读方式载入内存，只识别加密前缀，不解密，不写源文件。覆盖 Chrome、Edge、Brave、Vivaldi、Opera 的 `Default` 与 `Profile N`，Opera 另含根配置。Firefox 只检查资料目录，便携版和自定义资料目录不在范围内。
- 报告只保留站点主机名、浏览器、配置序号和脱敏账号（不超过 4 个字符时完全隐藏，否则只保留首尾字符）。网址路径、参数、密码、Cookie 名称与值、令牌和私钥都不进入报告。站点列表仍属个人隐私，不要公开分享报告。
- 网络路径、映射网络驱动器和重解析点不检查。超过 512 MiB 或被锁定的数据库记为无法检查；有未合并 WAL 的数据库只统计主库并标为不完整。未检查的项目不计作零。

目标清单来自公开分析中的 K2F LuaJIT bundle（SHA-256 `cc0ad05bfe85940a6067b3a72c182d3953339129206634141926d5d0b35973ec`）字符串表。

## 相关项目

- [WormW/nikke_malware_analysis](https://github.com/WormW/nikke_malware_analysis)：事件与样本公开分析
- [Sheisback/nikke_malware_scanner](https://github.com/Sheisback/nikke_malware_scanner)：检查运行痕迹
- [Google：Windows 上的应用绑定加密](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)
