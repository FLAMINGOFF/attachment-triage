# Email Attachment Triage

**English** | [简体中文](README.zh-CN.md)

A Python CLI for the first five minutes with a suspicious email attachment. It answers
three questions **without opening the file**:

1. **What is it really?** It reads the file's magic bytes and compares them with the
   extension. This catches `photo.jpg` that is really an `.exe`, `invoice.pdf.exe` double
   extensions, RTLO (right-to-left override) characters in file names, and RTF files
   renamed to `.doc`.
2. **What's inside?** It pulls Office **VBA and Excel 4.0 (XLM) macros** out with
   [oletools](https://github.com/decalage2/oletools) and flags auto-run entry points and
   suspicious keywords. It also looks for remote template injection in OOXML, JavaScript
   and auto-actions in PDFs, OLE objects in RTF, HTML smuggling, scripts inside ZIPs, and
   Office files encrypted with Office's built-in default password.
3. **Has anyone seen it before?** It computes MD5 / SHA-1 / SHA-256 and, if you give it
   your own [VirusTotal](https://www.virustotal.com/) API key, looks the **hash** up.
   The file itself is never uploaded.

It takes single files, whole folders, or a **`.eml` email**. For an email it pulls every
attachment out and checks each one. ZIP members get the same treatment, up to 3 levels deep.

Python 3.8+. `oletools` is the only dependency, and it's only needed for macro analysis.
Every other check works without it.

## Install

```bash
pip install -r requirements.txt      # oletools
```

## Usage

```bash
python3 triage.py suspicious.docm                 # one file
python3 triage.py ~/Downloads/attachments/        # a folder (recursive)
python3 triage.py message.eml                     # an email: checks every attachment
python3 triage.py file.xlsm -v                    # also print MD5/SHA-1 and the macro source
python3 triage.py file.xlsm -x macros/            # save extracted macro source to macros/
python3 triage.py message.eml --json              # machine-readable

export VT_API_KEY=your_key                        # free key: virustotal.com → sign up → API key
python3 triage.py message.eml --vt                # + VirusTotal hash lookups
python3 triage.py message.eml --vt --vt-top-only  # only look up top-level files (saves quota)
python3 triage.py --hash 44d88612fea8a8f36de82e1278abb02f   # look up a hash directly

python3 samples/make_samples.py                   # generate harmless demo samples in samples/out/
python3 triage.py samples/out/
python3 -m unittest -v                            # offline tests
```

Example output for the generated `phish.eml` sample (the CLI prints in Chinese;
shortened):

```
🔎 phish.eml  (4.5 KB)
   类型:   电子邮件 (EML)  主题: Overdue invoice #4471 (demo sample) | 发件人: Accounts <billing@example.invalid>
   结论:   🔴 高危
   └─ photo_<U+202E>gpj.exe  (88 B)  ← 邮件附件
      类型:   Windows 可执行文件 (PE)   扩展名: .exe
      ❌ [高] 伪装: 文件名含 Unicode 双向控制字符 U+202E，显示出来的扩展名是假的
           真实文件名（去掉控制字符）：photo_gpj.exe
      ❌ [高] 危险类型: 扩展名 .exe 双击即可执行代码…
   └─ invoice.docm  (2.0 KB)  ← 邮件附件
      ❌ [高] 宏: 含 VBA 宏（1 个模块），打开/关闭文档时会自动执行
           自动执行入口：AutoOpen
      ❌ [高] 宏: 宏里有可疑关键字：Shell, WScript.Shell, call, CreateObject
      ℹ️  [信息] 宏: 宏里出现的 IOC（网址/IP/可执行文件名）：http://example.invalid/payload.exe
      📜 宏模块 Module1.bas（8 行）
   └─ scan.pdf  (464 B)  ← 邮件附件
      ❌ [高] PDF: 内嵌 JavaScript（/JavaScript × 1）
      ❌ [高] PDF: PDF 名字用了 #xx 十六进制转义来躲关键字检测（例如 /Java#53cript）
      ⚠️  [中] PDF: 打开即触发的动作 (OpenAction)
```

(`结论` = verdict, `高危` = high risk, `伪装` = disguise, `宏` = macro, `邮件附件` = email
attachment.) The RTLO character is printed as `<U+202E>`, so your terminal doesn't flip
the name too.

| Exit code | Meaning |
|---|---|
| `0` | Nothing at medium or high risk |
| `1` | At least one file (or attachment, or archive member) is medium or high risk |
| `2` | A file couldn't be read, or a `--hash` lookup failed |

## What it checks

Every finding is rated **high / medium / low / info**. A file's verdict is its worst
finding, including findings on its attachments and archive members.

| Area | Checks | Typical rating |
|---|---|---|
| **File name** | RTLO and other bidi control characters (`photo_<U+202E>gpj.exe` shows as `photo_exe.jpg`) · double extensions (`invoice.pdf.exe`) · long runs of padding before the real extension · executable/script extensions (`.exe .scr .js .vbs .hta .lnk .ps1 …`) · disk images (`.iso .img .vhd`) and OneNote · macro-enabled Office (`.docm .xlsm …`) | high / medium |
| **Magic bytes vs extension** | ~40 formats: PE, ELF, Mach-O, LNK, OLE (and which kind: Word / Excel / PowerPoint / Outlook / MSI / *encrypted*), OOXML (docx / xlsx / pptx), ODF, JAR, APK, ZIP, RAR, 7z, CAB, ISO, PDF, RTF, CHM, images, HTML, MHT, Word 2003 XML, SYLK, email, scripts | high if the real content is executable, medium otherwise |
| **Office macros** (oletools) | VBA and XLM macros in OLE, OOXML, MHT, Word 2003 XML and SYLK files · auto-run entry points (`AutoOpen`, `Workbook_Open`, `Auto_Open` …) · suspicious keywords (`Shell`, `CreateObject`, `URLDownloadToFile` …) · IOCs (URLs, IPs, exe names) · hex/Base64/Dridex-encoded strings · XLM macro sheets in xlsm/xlsb | high when auto-run + suspicious keyword, else medium |
| **Encrypted Office files** | Tries Office's built-in default passwords (`VelvetSweatshop` and a few common ones). If one works, the decrypted file is analyzed as a child item; if not, the tool tells you it couldn't see inside | medium |
| **OOXML** | external `attachedTemplate` / `oleObject` / `frame` relationships (remote template injection, MITRE T1221) · `vbaProject.bin` inside a file named `.docx` · embedded objects / ActiveX | high / medium / low |
| **PDF** | `/JavaScript` `/JS` `/Launch` `/OpenAction` `/AA` `/EmbeddedFile` `/XFA` `/RichMedia` `/SubmitForm` · **`#xx`-escaped names** (`/Java#53cript`), a classic way to dodge keyword scanners · encryption | high / medium |
| **RTF** | embedded OLE objects (`\object`, `\objdata`), with an extra flag for Equation Editor / `\objupdate` | high / medium |
| **HTML / MHT** | HTML smuggling (`atob` + `Blob` + `createObjectURL` + `download`) · local login forms that post a password to an outside URL · auto-redirects | high / medium |
| **ZIP** | password-protected members (gateways can't scan them, and the password is usually in the email body) · every member is analyzed recursively, up to 3 levels deep and 50 MB per member | medium + members' own findings |
| **Email (.eml)** | subject and sender, then every attachment, including inline parts with a file name and forwarded `message/rfc822` emails | members' findings |
| **VirusTotal** | `GET /api/v3/files/{sha256}` only: ≥ 3 engines → high, 1–2 → medium, 0 → info, unknown to VT → info | high / medium / info |

### VirusTotal notes

- **Hash lookups only, never uploads.** Anything uploaded to VirusTotal can be downloaded
  by every paying VT customer. A real attachment can hold contracts, invoices or personal
  data, so the tool never sends the file. Upload it yourself if you decide it's safe to.
- **"Not found" doesn't mean safe.** Targeted phishing often uses files built for one
  campaign, which VT has never seen. "0 / 70 engines" doesn't mean safe either: it may be
  too new to be detected.
- **Keep the key out of shell history.** Pass it with the `VT_API_KEY` environment variable.
  `--vt-key` also works, but it ends up in your shell history and in `ps` output.
- **The free API allows 4 requests per minute**, so lookups are spaced 15 seconds apart
  (`--vt-delay`). Repeated hashes are cached for the run. If the key is invalid (401/403)
  or the quota runs out (429), the remaining lookups are skipped instead of hammering the API.
- The email file itself is never looked up (every email's hash is unique). Its attachments are.

### Demo samples (all harmless)

The repository contains **no binary samples**. `samples/make_samples.py` builds them
with the standard library when you run it:

| Sample | What it is | Why it's harmless |
|---|---|---|
| `invoice.pdf.exe`, `photo.jpg` | an 88-byte DOS/PE header | No sections and no code. Windows refuses to run it |
| `macro_demo.docm` | a Word document with a real VBA project | `AutoOpen` only shows a `MsgBox`. The suspicious keywords appear only in a string |
| `template.docx` | a remote template reference | It points to `example.invalid`, a TLD that can never resolve |
| `scan.pdf` | `OpenAction` + JavaScript (with a `#53` escaped name) | The script is `app.alert(...)` |
| `report.doc` | an RTF file with a `.doc` extension | It contains one line of text |
| `archive.zip` | a ZIP with an `invoice.js` inside | The `.js` file is one comment line |
| `phish.eml` | an email carrying three of the above, one with an RTLO name | Same files as above |

To build the `.docm`, the script includes a small writer for the OLE compound file format
(MS-CFB) and the VBA project format (MS-OVBA). The tests use them too, so they can check
the real oletools path end to end without shipping a macro document.

## Limitations

- **This is triage, not a sandbox.** It reads the file's structure and never runs
  anything. A clean result means "no known red flags", not "safe". When in doubt, detonate
  the file in a sandbox ([ANY.RUN](https://any.run/), [Hybrid Analysis](https://www.hybrid-analysis.com/),
  CAPE) or open it in a throwaway VM with no network.
- **Macro analysis is as good as oletools' keyword lists.** Heavy obfuscation can slip past
  it. For deeper work use `olevba --deobf`, `olevba --decode`, and the pcode and VBA
  stomping checks that `olevba` runs on files on disk (this tool parses in memory, where
  stomping detection isn't available).
- **Not covered:** DDE fields (use `msodde`), extracting embedded OLE objects (`oleobj`,
  `rtfobj`), Outlook `.msg` attachments (identified, not unpacked), RAR / 7z / ISO contents
  (identified, not unpacked), OneNote internals, PE analysis (imports, signatures, packers).
- PDF checks are keyword counts, like Didier Stevens' `pdfid`. They don't decompress object
  streams, so keywords inside compressed object streams are missed. Use `pdf-parser` or
  `peepdf` for those.
- Encrypted ZIPs are listed but not cracked. You still see member names and their
  name-based warnings.

## Safety tips for handling attachments

- Save attachments, don't open them. Analyze them on a machine where a mistake doesn't
  matter (a VM, or a Mac/Linux box for Windows malware).
- Rename real samples (`.exe` → `.exe_`) or keep them in a password-protected ZIP
  (the convention is the password `infected`), so nobody double-clicks them.
- Report phishing to your security team. The hashes and IOCs from this tool are what they
  will ask for.

## Files
- `triage.py`: the CLI (magic bytes → name checks → type vs extension → encryption →
  macros → OOXML / PDF / RTF / HTML checks → ZIP / email recursion → hashes → VirusTotal → report)
- `test_triage.py`: offline tests for type detection, each check, recursion limits, the
  VirusTotal client (mocked: hash only, key header, 404, bad key, rate limit, cache) and the CLI
- `samples/make_samples.py`: generator for the harmless samples above, including the small
  MS-CFB / MS-OVBA writer
- `requirements.txt`: `oletools`

## References
- oletools / olevba: https://github.com/decalage2/oletools/wiki/olevba
- MS-OVBA (VBA project format): https://learn.microsoft.com/openspecs/office_file_formats/ms-ovba/
- MS-CFB (compound file format): https://learn.microsoft.com/openspecs/windows_protocols/ms-cfb/
- MITRE ATT&CK T1566.001 Spearphishing Attachment: https://attack.mitre.org/techniques/T1566/001/
- MITRE ATT&CK T1221 Template Injection: https://attack.mitre.org/techniques/T1221/
- MITRE ATT&CK T1036.002 Right-to-Left Override: https://attack.mitre.org/techniques/T1036/002/
- MITRE ATT&CK T1027.006 HTML Smuggling: https://attack.mitre.org/techniques/T1027/006/
- Didier Stevens, PDF tools (pdfid, pdf-parser): https://blog.didierstevens.com/programs/pdf-tools/
- VirusTotal API v3, file reports: https://docs.virustotal.com/reference/file-info
- List of file signatures: https://en.wikipedia.org/wiki/List_of_file_signatures
