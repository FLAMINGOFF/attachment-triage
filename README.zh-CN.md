# 邮件附件快速分诊工具 (Email Attachment Triage)

[English](README.md) | **简体中文**

一个 Python 命令行工具，用在拿到可疑邮件附件后的头五分钟。它在**不打开文件**的前提下
回答三个问题：

1. **它到底是什么？** 读文件头的魔数（magic bytes），和扩展名对比。能揪出
   “photo.jpg 其实是 exe”、`invoice.pdf.exe` 双扩展名、文件名里的 RTLO 反转字符、
   改名成 `.doc` 的 RTF 等伪装。
2. **里面藏了什么？** 用 [oletools](https://github.com/decalage2/oletools) 提取 Office 的
   **VBA 宏和 Excel 4.0 (XLM) 宏**，标出自动执行入口和可疑关键字。另外还检查 OOXML
   远程模板注入、PDF 里的 JavaScript 和自动动作、RTF 里嵌的 OLE 对象、HTML 走私、
   压缩包里的脚本，以及用 Office 内置默认密码加密的文档。
3. **别人见过它吗？** 计算 MD5 / SHA-1 / SHA-256，提供你自己的
   [VirusTotal](https://www.virustotal.com/) API key 后会按**哈希**查询，绝不上传文件本身。

可以分析单个文件、整个目录，或者一封 **`.eml` 邮件**：邮件会自动拆出所有附件逐个分析，
ZIP 里的成员也一样，最多往里拆 3 层。

需要 Python 3.8+。唯一的依赖是 `oletools`，而且只有宏分析用得到，没装时其它检查照常进行。

## 安装

```bash
pip install -r requirements.txt      # oletools
```

## 用法

```bash
python3 triage.py suspicious.docm                 # 单个文件
python3 triage.py ~/Downloads/attachments/        # 整个目录（递归）
python3 triage.py message.eml                     # 一封邮件：分析所有附件
python3 triage.py file.xlsm -v                    # 同时显示 MD5/SHA-1 和宏源码
python3 triage.py file.xlsm -x macros/            # 把提取的宏源码保存到 macros/
python3 triage.py message.eml --json              # 机器可读的输出

export VT_API_KEY=你的key                         # 免费注册：virustotal.com → 头像 → API key
python3 triage.py message.eml --vt                # 再加上 VirusTotal 哈希查询
python3 triage.py message.eml --vt --vt-top-only  # 只查最外层文件（省配额）
python3 triage.py --hash 44d88612fea8a8f36de82e1278abb02f   # 直接按哈希查

python3 samples/make_samples.py                   # 在 samples/out/ 生成无害的演示样本
python3 triage.py samples/out/
python3 -m unittest -v                            # 离线测试
```

对生成的 `phish.eml` 样本的输出（节选）：

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

RTLO 字符会显示成 `<U+202E>`，免得终端也把文件名 “反转” 了骗到你。

| 退出码 | 含义 |
|---|---|
| `0` | 没有中危及以上的问题 |
| `1` | 至少一个文件（或附件、压缩包成员）是中危或高危 |
| `2` | 有文件读不了，或 `--hash` 查询失败 |

## 检查了什么

每条发现分 **高 / 中 / 低 / 信息** 四级。一个文件的结论取它自己和所有附件、压缩包成员里
最严重的那一级。

| 方面 | 检查内容 | 常见级别 |
|---|---|---|
| **文件名** | RTLO 等双向控制字符（`photo_<U+202E>gpj.exe` 显示成 `photo_exe.jpg`）· 双扩展名（`invoice.pdf.exe`）· 真实扩展名前的一长串空白/填充 · 可执行/脚本扩展名（`.exe .scr .js .vbs .hta .lnk .ps1 …`）· 磁盘镜像（`.iso .img .vhd`）和 OneNote · 允许宏的 Office（`.docm .xlsm …`） | 高 / 中 |
| **魔数 vs 扩展名** | 约 40 种格式：PE、ELF、Mach-O、LNK、OLE（并细分 Word / Excel / PowerPoint / Outlook / MSI / *已加密*）、OOXML（docx / xlsx / pptx）、ODF、JAR、APK、ZIP、RAR、7z、CAB、ISO、PDF、RTF、CHM、图片、HTML、MHT、Word 2003 XML、SYLK、邮件、脚本 | 真实内容是可执行程序为高，否则为中 |
| **Office 宏**（oletools） | OLE、OOXML、MHT、Word 2003 XML、SYLK 里的 VBA 和 XLM 宏 · 自动执行入口（`AutoOpen`、`Workbook_Open`、`Auto_Open` …）· 可疑关键字（`Shell`、`CreateObject`、`URLDownloadToFile` …）· IOC（网址、IP、exe 文件名）· 十六进制/Base64/Dridex 编码字符串 · xlsm/xlsb 里的 XLM 宏表 | 自动执行 + 可疑关键字为高，否则为中 |
| **加密的 Office 文档** | 用 Office 内置默认密码（`VelvetSweatshop` 和几个常见密码）试着解密。解开了就把解密后的文件作为子项继续分析，解不开就明确告诉你看不到里面 | 中 |
| **OOXML** | 外部的 `attachedTemplate` / `oleObject` / `frame` 关系（远程模板注入，MITRE T1221）· 扩展名是 `.docx` 却含 `vbaProject.bin` · 内嵌对象 / ActiveX | 高 / 中 / 低 |
| **PDF** | `/JavaScript` `/JS` `/Launch` `/OpenAction` `/AA` `/EmbeddedFile` `/XFA` `/RichMedia` `/SubmitForm` · **用 `#xx` 转义的名字**（`/Java#53cript`），躲关键字扫描的经典手法 · 加密 | 高 / 中 |
| **RTF** | 嵌入的 OLE 对象（`\object`、`\objdata`），带公式编辑器 / `\objupdate` 特征时额外标高 | 高 / 中 |
| **HTML / MHT** | HTML 走私（`atob` + `Blob` + `createObjectURL` + `download`）· 把密码提交到外部网址的本地登录表单 · 自动跳转 | 高 / 中 |
| **ZIP** | 有密码保护的成员（网关扫不到，密码通常写在邮件正文里）· 逐个递归分析成员，最多 3 层，单个成员不超过 50 MB | 中 + 成员各自的发现 |
| **邮件 (.eml)** | 显示主题和发件人，然后分析每个附件，包括带文件名的内联部分和转发的 `message/rfc822` 邮件 | 附件各自的发现 |
| **VirusTotal** | 只调用 `GET /api/v3/files/{sha256}`：≥ 3 个引擎报毒为高，1–2 个为中，0 个为信息，VT 没见过为信息 | 高 / 中 / 信息 |

### 关于 VirusTotal

- **只查哈希，绝不上传。** 上传到 VirusTotal 的文件，所有付费用户都能下载。真实附件里
  可能有合同、发票、个人信息，所以工具从不发送文件本身。确认可以公开后，要上传请自己动手。
- **“没见过” 不等于安全。** 定向钓鱼常用为一次行动专门制作的文件，VT 从没见过。
  “0/70 个引擎报毒” 也不等于安全，可能只是太新，还没被识别出来。
- **key 不要留在 shell 历史里。** 用环境变量 `VT_API_KEY` 传入。`--vt-key` 也能用，
  但会留在 shell 历史和 `ps` 的输出里。
- **免费 API 每分钟 4 次**，所以默认两次查询间隔 15 秒（`--vt-delay`）。同一次运行里
  重复的哈希会走缓存。key 无效（401/403）或配额用完（429）时，后面的查询直接跳过，
  不会反复撞接口。
- 邮件文件本身不查（每封邮件的哈希都独一无二），查的是它的附件。

### 演示样本（全部无害）

仓库里**没有任何二进制样本**。运行 `samples/make_samples.py` 时用标准库现场生成：

| 样本 | 是什么 | 为什么无害 |
|---|---|---|
| `invoice.pdf.exe`、`photo.jpg` | 88 字节的 DOS/PE 头 | 没有节，也没有代码，Windows 会拒绝运行 |
| `macro_demo.docm` | 含真实 VBA 工程的 Word 文档 | `AutoOpen` 里只有一个 `MsgBox`，可疑关键字只出现在字符串里 |
| `template.docx` | 远程模板引用 | 指向 `example.invalid`，这个顶级域名永远解析不到 |
| `scan.pdf` | `OpenAction` + JavaScript（名字用 `#53` 转义） | 脚本只是 `app.alert(...)` |
| `report.doc` | 扩展名是 `.doc` 的 RTF | 里面只有一行文字 |
| `archive.zip` | 里面有个 `invoice.js` 的压缩包 | 那个 `.js` 只有一行注释 |
| `phish.eml` | 带上面三个附件的邮件，其中一个文件名含 RTLO | 附件同上 |

为了生成 `.docm`，脚本里带了一个小型的 OLE 复合文档（MS-CFB）和 VBA 工程（MS-OVBA）写入器。
测试也用它们，这样不用在仓库里放宏文档，也能端到端地测试真实的 oletools 解析路径。

## 局限

- **这是分诊，不是沙箱。** 它只读文件结构，从不运行任何东西。结果干净的意思是 “没发现
  已知的危险信号”，不是 “安全”。拿不准时，放进沙箱（[ANY.RUN](https://any.run/)、
  [Hybrid Analysis](https://www.hybrid-analysis.com/)、CAPE）跑一下，或者在断网的
  一次性虚拟机里打开。
- **宏分析的能力取决于 oletools 的关键字列表。** 重度混淆可能漏过。要深入分析，用
  `olevba --deobf`、`olevba --decode`，以及 `olevba` 对磁盘文件做的 P-code 和
  VBA stomping 检查（本工具在内存里解析，这种情况下不支持 stomping 检测）。
- **没覆盖的：** DDE 字段（用 `msodde`）、提取内嵌 OLE 对象（`oleobj`、`rtfobj`）、
  Outlook `.msg` 的附件（能识别，不拆）、RAR / 7z / ISO 的内容（能识别，不拆）、
  OneNote 内部结构、PE 分析（导入表、签名、加壳）。
- PDF 检查是关键字计数，和 Didier Stevens 的 `pdfid` 一样，不解压对象流，所以藏在压缩
  对象流里的关键字会漏掉。那种情况用 `pdf-parser` 或 `peepdf`。
- 加密的 ZIP 只列出成员，不破解密码。你仍能看到成员名和基于文件名的警告。

## 处理附件的安全建议

- 附件只保存，别打开。在出错也无所谓的机器上分析（虚拟机，或者分析 Windows 恶意软件时
  用 Mac/Linux）。
- 真样本改个扩展名（`.exe` → `.exe_`），或者放进带密码的 ZIP（惯例密码是 `infected`），
  免得有人双击。
- 把钓鱼邮件报告给安全团队。这个工具给出的哈希和 IOC 正是他们会问你要的东西。

## 文件说明
- `triage.py`：命令行工具（魔数 → 文件名检查 → 类型 vs 扩展名 → 加密 → 宏 →
  OOXML / PDF / RTF / HTML 检查 → ZIP / 邮件递归 → 哈希 → VirusTotal → 报告）
- `test_triage.py`：离线测试，覆盖类型识别、每一项检查、递归层数限制、VirusTotal 客户端
  （模拟网络：只发哈希、key 请求头、404、无效 key、限速、缓存）和命令行
- `samples/make_samples.py`：上面那些无害样本的生成器，含小型 MS-CFB / MS-OVBA 写入器
- `requirements.txt`：`oletools`

## 参考资料
- oletools / olevba：https://github.com/decalage2/oletools/wiki/olevba
- MS-OVBA（VBA 工程格式）：https://learn.microsoft.com/openspecs/office_file_formats/ms-ovba/
- MS-CFB（复合文档格式）：https://learn.microsoft.com/openspecs/windows_protocols/ms-cfb/
- MITRE ATT&CK T1566.001 鱼叉式钓鱼附件：https://attack.mitre.org/techniques/T1566/001/
- MITRE ATT&CK T1221 模板注入：https://attack.mitre.org/techniques/T1221/
- MITRE ATT&CK T1036.002 RTLO 反转字符：https://attack.mitre.org/techniques/T1036/002/
- MITRE ATT&CK T1027.006 HTML 走私：https://attack.mitre.org/techniques/T1027/006/
- Didier Stevens 的 PDF 工具（pdfid、pdf-parser）：https://blog.didierstevens.com/programs/pdf-tools/
- VirusTotal API v3 文件报告：https://docs.virustotal.com/reference/file-info
- 文件签名列表：https://en.wikipedia.org/wiki/List_of_file_signatures
