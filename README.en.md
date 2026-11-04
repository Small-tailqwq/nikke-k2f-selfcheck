[中文](README.md) | **English** | [日本語](README.ja.md) | [한국어](README.ko.md)

# NIKKE K2F Exposure Self-Check

Based on the collection list of the K2F sample from the NIKKE Launcher supply-chain incident, this tool checks whether those locations exist on your computer, counts how browser passwords and cookies are encrypted, and writes a local HTML report.

A location being present does not mean its data was read or sent out. This tool does not detect infection and cannot confirm whether anything leaked. To check for traces of K2F execution, use [Sheisback/nikke_malware_scanner](https://github.com/Sheisback/nikke_malware_scanner).

## Download

Download `k2f-selfcheck.exe` from [Releases](https://github.com/Small-tailqwq/nikke-k2f-selfcheck/releases) and double-click it. The report is saved next to the exe and opens in your default browser.

The exe is built from this repository by GitHub Actions (PyInstaller, single file). Verify it against the `.sha256` file published with it:

```powershell
Get-FileHash .\k2f-selfcheck.exe -Algorithm SHA256
```

Some antivirus products flag PyInstaller executables by mistake. If you would rather not run the exe, run the source directly.

## Run from source

Requires Windows 10/11 and Python 3.11+. No dependencies to install.

```powershell
python k2f_selfcheck.py
```

| Option | Purpose |
|---|---|
| `--lang` | Report and output language: `zh`, `en`, `ja`, `ko`. Defaults to the Windows display language; other languages fall back to English |
| `--out` | Report path (`.html` or `.htm`). Existing files are never overwritten |
| `--no-open` | Save the report without opening a browser |
| `--quick` | Skip browser databases and wallet extensions; check paths only |
| `--no-browser-count` | Skip browser databases |
| `--targets` | Target list to use; defaults to `k2f_targets.json` next to the script |

Exit code `0` means the report was written; `2` means the environment, input or write failed. The exit code says nothing about infection or leaks.

## What the report shows

The report opens with a short notice; the "Got it" button unlocks after 6 seconds. The body has six parts: summary, browser data, credential locations, wallet extensions, incomplete checks and about.

- **v10: high risk.** Any program running as the current user can decrypt these. For each site, change the password, sign out of other devices and turn on two-factor authentication.
- **Unencrypted cookies: high risk.** They work as soon as they are copied. Sign out on those sites to end the sessions.
- **Unknown format:** the protection cannot be determined; treat these as v10.
- **v20: lower.** Protected by app-bound encryption; decrypting them requires admin rights or injecting into the browser process. After handling v10, sign out of important sites.
- **Credential locations:** config files, credential files and key folders that exist, grouped by tool, with how to rotate each group. Program folders and ordinary user folders are listed separately and are not counted as credential locations.

Counts are records or target templates, not the number of leaked credentials.

In the details, passwords are listed per record with site, masked account and browser; cookies are summed per site. Long lists are rendered in fixed-height chunks that the browser skips while off screen, so tens of thousands of records still expand instantly. The report contains no scripts and loads no external resources.

## Scope and privacy

- Ordinary targets are checked only for whether the path or registry key exists. Files are not opened and values are not read.
- Browser databases are loaded into memory with shared read-only access. Only the encryption prefix is identified; nothing is decrypted and the source files are not written. Covers `Default` and `Profile N` for Chrome, Edge, Brave, Vivaldi and Opera, plus Opera's root profile. Firefox is checked for the profile folder only. Portable builds and custom profile folders are not covered.
- The report keeps only site host names, browser, profile number and masked accounts (fully hidden when 4 characters or fewer, otherwise only the first and last characters are kept). URL paths, parameters, passwords, cookie names and values, tokens and private keys never enter the report. The site list is still private, so do not share the report publicly.
- Network paths, mapped network drives and reparse points are not checked. Databases over 512 MiB or locked are marked unreadable; databases with an unmerged WAL are counted from the main file only and marked incomplete. Items that were not checked are never counted as zero.

The target list comes from the string table of the K2F LuaJIT bundle (SHA-256 `cc0ad05bfe85940a6067b3a72c182d3953339129206634141926d5d0b35973ec`) described in public analysis.

## Related projects

- [WormW/nikke_malware_analysis](https://github.com/WormW/nikke_malware_analysis): public analysis of the incident and samples
- [Sheisback/nikke_malware_scanner](https://github.com/Sheisback/nikke_malware_scanner): check for traces of execution
- [Google: app-bound encryption on Windows](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)
