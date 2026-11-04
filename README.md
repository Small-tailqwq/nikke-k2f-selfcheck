# NIKKE K2F 泄露面模拟工具

本工具依据 NIKKE Launcher 供应链事件中 K2F 样本的已知采集目标，模拟本机可能暴露的数据位置，生成本地 HTML 报告。目标存在不代表数据已被读取或外传；本工具不排查或担保真实泄露。

工具不执行样本，不向外发送数据。报告包含目标模板、状态、计数和脱敏浏览器明细；不包含密码、Cookie 值、令牌、私钥或完整账号 / Cookie 名称。报告使用内置样式，表情和标签页图标直接嵌入 HTML，不自动加载外部资源。

如需另行检查 K2F 运行痕迹，可参考 [Sheisback/nikke_malware_scanner](https://github.com/Sheisback/nikke_malware_scanner)。

## 要求

- Windows 10/11
- Python 3.11 或更高版本
- 普通用户权限；权限不足的目标会标为无法检查

## 用法

```powershell
python k2f_selfcheck.py
```

默认在当前目录生成带时间戳的 HTML 报告，并用默认浏览器打开。若浏览器未能打开，可根据终端显示的路径手动打开报告。指定输出文件已存在时不会覆盖，请换一个文件名。

```powershell
python k2f_selfcheck.py --out report.html
python k2f_selfcheck.py --no-open
python k2f_selfcheck.py --quick
python k2f_selfcheck.py --no-browser-count
python k2f_selfcheck.py --targets k2f_targets.json
```

| 参数 | 用途 |
|---|---|
| `--out` | 指定 HTML 报告路径，使用 `.html` 或 `.htm` 扩展名 |
| `--no-open` | 生成报告，但不自动打开浏览器 |
| `--quick` | 只检查目标元信息，跳过浏览器数据库统计与钱包扩展检查 |
| `--no-browser-count` | 跳过浏览器数据库统计 |
| `--targets` | 指定目标清单 JSON，默认使用脚本目录下的 `k2f_targets.json` |

## 检查范围

目标清单基于公开分析中的 K2F LuaJIT bundle（SHA-256 `cc0ad05bfe85940a6067b3a72c182d3953339129206634141926d5d0b35973ec`）字符串表。报告按浏览器、AI 工具、钱包、云服务、代码托管、开发工具等内容分类。目录或配置存在不代表其中有凭据；程序目录和普通目录不会被当作凭据。

工具仅检查本地磁盘，拒绝网络路径和重解析点，包括符号链接与目录联接。对普通目标只检查路径或注册表键的元信息，不读取文件内容或注册表值。未检查和无法检查的项目不会计作未发现。

浏览器数据库检查读取数据以统计密码和 Cookie 的加密版本，不解密或展示鉴权值。支持 Chrome、Edge、Brave、Vivaldi 和 Opera 的 `Default` 与全部 `Profile N` 配置，另含 Opera 根配置目录；Firefox 仅检查资料目录是否存在。钱包扩展检查的实际覆盖范围以报告为准。

浏览器风险卡片可以展开 v10、v20、未加密 Cookie、未知格式与空值记录；点击明细中的站点，可查看该项的来源数据库和检查状态。定位信息只包含站点主机名、浏览器、配置、记录序号与脱敏标识：网址中的用户名、密码、路径、查询和片段均不保留；账号及 Cookie 名称长度不超过 4 个字符时全部隐藏，其他只保留首尾字符。密码、Cookie 值及其编码、散列或片段不进入报告。站点信息仍可能涉及隐私，分享报告前请自行检查。

浏览器数据库快照上限为 512 MiB；超过上限时不进行该数据库的统计。WAL 模式、存在 WAL 或快照在读取时发生变化时，报告会标明统计可能不完整；只统计主库，不合并 WAL。未检查或无法读取的数据不计作零条。

## 如何理解结果

- **v10：最高优先级、高风险。** 若恶意程序曾以当前用户身份运行，这类浏览器密码或 Cookie 可能被解密并用于访问账号。请优先在可信设备检查相关账号、退出其他会话、修改密码，并启用或检查多因素认证。
- **v20：相对较低，仍需关注。** 应用绑定保护提高了窃取门槛；相对 v10，v20 通常更难解密或利用，但不能保证安全。如怀疑发生入侵，请检查账号活动并撤销可疑会话。
- **未加密或未识别的数据：** 未加密 Cookie 需要优先处理；未知格式的保护强度需要进一步核查。
- **其他鉴权位置：** 如怀疑设备曾被入侵，请检查相关服务的登录活动，并撤销或轮换可能涉及的凭据。配置或历史记录中是否存在凭据需要自行核实。

报告中的数量表示检查到的目标模板或浏览器记录数量，不表示已泄露的凭据数量。

退出码 `0` 表示报告生成成功，`2` 表示运行环境、输入或报告写入失败；退出码不表示感染或泄露状态。

## 相关项目

- [WormW/nikke_malware_analysis](https://github.com/WormW/nikke_malware_analysis)：事件与样本公开分析
- [Sheisback/nikke_malware_scanner](https://github.com/Sheisback/nikke_malware_scanner)：另行检查运行痕迹
- [Google 对 Windows 应用绑定加密的说明](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)：保护机制与边界
