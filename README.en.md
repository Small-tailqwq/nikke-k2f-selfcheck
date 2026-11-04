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
| `--quick` | Skip Chromium databases and wallets; still check other targets |
| `--no-browser-count` | Skip browser databases |
| `--targets` | Target list to use; defaults to `k2f_targets.json` next to the script |

Exit code `0` means the report was written; `2` means the environment, input or write failed. The exit code says nothing about infection or leaks.

## What the report shows

The report opens with a short notice; the "Got it" button unlocks after 6 seconds. The body has six parts: summary, browser data, credential locations, wallet extensions, incomplete checks and about.

- **v10: high risk.** Any program running as the current user can decrypt these. For each site, change the password, sign out of other devices and turn on two-factor authentication.
- **Unencrypted cookies: not read by this sample.** The sample queries `encrypted_value`. Records stored only in `value` are shown separately and are not counted as high-risk items for this sample.
- **Unknown format:** the protection cannot be determined; treat these as v10.
- **v20: lower.** Protected by app-bound encryption; decrypting them requires admin rights or injecting into the browser process. After handling v10, sign out of important sites.
- **Credential locations:** config files, credential files and key folders that exist, grouped by tool, with how to rotate each group. Program folders and ordinary user folders are listed separately and are not counted as credential locations.

Counts are records or target templates, not the number of leaked credentials.

In the details, passwords are listed per record with site, masked account and browser; cookies are summed per site. Long lists are rendered in fixed-height chunks that the browser skips while off screen, so tens of thousands of records still expand instantly. The report contains no scripts and loads no external resources.

## Scope and privacy

- Ordinary targets use path and file metadata only. Checks also cover project configuration, Firefox `key4.db` / `logins.json`, GPG key files, files listed in `KUBECONFIG`, and NIKKE credential files, without reading their secret contents.
- Project searches reach depth 2, skip `.git` / `node_modules`, and exclude `.example` / `.sample` / `.template` files. SSH configuration and PuTTY / WinSCP sessions are used only to find external key paths and check whether a password field exists.
- Process and user/system registry environment variables are filtered with the sample's rules; only variable names enter the report. Windows Credential Manager contributes an entry count. Environment values, credential contents and actual custom paths are not included.
- Chromium databases are loaded into memory with shared read-only access to identify encryption prefixes. Nothing is decrypted or written back. All profile subdirectories under known Chrome, Edge, Brave, Vivaldi and Opera roots are checked; Opera root databases and portable profiles outside those roots are excluded. Wallet checks cover only Chrome and require both an installed extension and `.ldb` / `.sst` / `.log` files in its sample-selected container.
- Browser details retain site host names, profile numbers and masked accounts (fully hidden up to 4 characters, otherwise first and last characters only). URL paths, parameters, passwords, cookie names and values, tokens and private keys are omitted. Site lists and environment variable names are still private; do not share reports publicly.
- Network paths, mapped network drives and reparse points are skipped. Unset environment variables are not applicable; browser files above the sample's 4 MiB limit are marked as skipped by the sample. Read failures remain incomplete. Databases with unmerged WAL data are counted from the main file only and marked incomplete.

Paths and detection rules were statically recovered from the K2F LuaJIT bundle (SHA-256 `cc0ad05bfe85940a6067b3a72c182d3953339129206634141926d5d0b35973ec`). File-presence findings identify potential storage locations; the tool does not reproduce the sample's extraction or decryption of configuration, history or session contents.

## Related projects

- [WormW/nikke_malware_analysis](https://github.com/WormW/nikke_malware_analysis): public analysis of the incident and samples
- [Sheisback/nikke_malware_scanner](https://github.com/Sheisback/nikke_malware_scanner): check for traces of execution
- [Google: app-bound encryption on Windows](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)
