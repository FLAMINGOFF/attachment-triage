#!/usr/bin/env python3
"""
邮件附件快速分诊工具 (Email Attachment Triage)

拿到一个可疑附件（或一整封 .eml 邮件），在 **不打开它** 的前提下回答三个问题：

1. 它到底是什么？读文件头的魔数（magic bytes），和扩展名对比，
   揪出 "photo.jpg 其实是 exe"、"invoice.pdf.exe" 双扩展名、RTLO 反转字符等伪装。
2. 里面藏了什么？用 oletools 提取 Office 宏源码并标出自动执行/可疑关键字；
   另外检查 OOXML 远程模板注入、PDF 里的 JavaScript/自动动作、压缩包里的脚本、HTML 走私。
3. 别人见过它吗？算 MD5 / SHA-1 / SHA-256，可选用你自己的 VirusTotal API key
   **只按哈希查询**（绝不上传文件本身）。

依赖：Python 3.8+；oletools 用于宏提取（没装时其它检查照常，只跳过宏分析）。
"""

import argparse
import email
import email.policy
import hashlib
import io
import json
import os
import re
import sys
import tempfile
import time
import unicodedata
import urllib.error
import urllib.request
import zipfile
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional, Tuple

try:  # 可选依赖
    from oletools import olevba
    import olefile
except ImportError:  # pragma: no cover - 在没装 oletools 的环境下走这里
    olevba = None
    olefile = None
try:
    from oletools import crypto as olecrypto
except ImportError:  # pragma: no cover
    olecrypto = None

VT_URL = "https://www.virustotal.com/api/v3/files/"
USER_AGENT = "attachment-triage (learning project)"

HIGH, MEDIUM, LOW, INFO = "high", "medium", "low", "info"
SEV_ORDER = {INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3}
SEV_LABEL = {HIGH: "高", MEDIUM: "中", LOW: "低", INFO: "信息"}
SEV_ICON = {HIGH: "❌", MEDIUM: "⚠️ ", LOW: "🔸", INFO: "ℹ️ "}
VERDICT = {HIGH: "🔴 高危", MEDIUM: "🟠 可疑", LOW: "🟡 留意", INFO: "🟢 未发现明显问题"}

MAX_DEPTH = 3                # 邮件 → 压缩包 → 文件，最多往里拆三层
MAX_MEMBER_SIZE = 50 << 20   # 压缩包里单个成员超过 50 MB 就不解出来分析（防解压炸弹）

# ---------------------------------------------------------------------------
# 扩展名分类
# ---------------------------------------------------------------------------
# 双击就能执行代码的
EXEC_EXT = {
    "exe", "scr", "com", "pif", "cpl", "msi", "msp", "dll", "sys", "ocx",
    "bat", "cmd", "vbs", "vbe", "js", "jse", "wsf", "wsh", "wsc", "hta", "ps1", "psm1",
    "lnk", "url", "scf", "reg", "jar", "chm", "xll", "appx", "msix", "appxbundle",
    "application", "gadget", "inf", "sct", "app", "command", "sh",
}
# 能 "装" 东西、常被用来绕过 Mark-of-the-Web 或邮件网关的容器
CONTAINER_EXT = {"iso", "img", "vhd", "vhdx", "one", "onepkg"}
# 允许宏的 Office 格式
MACRO_EXT = {"docm", "dotm", "xlsm", "xltm", "xlam", "pptm", "potm", "ppsm", "ppam", "sldm"}
# 看起来 "像文档" 的扩展名——双扩展名里排在前面的通常是这些
DOC_LIKE_EXT = {
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "rtf", "txt", "csv", "jpg", "jpeg",
    "png", "gif", "bmp", "mp3", "mp4", "avi", "mov", "zip", "rar", "htm", "html", "odt",
}
# Unicode 双向控制字符：RLO (U+202E) 能把 "gpj.exe" 显示成 "exe.jpg"
BIDI_CHARS = {"‪", "‫", "‬", "‭", "‮",
              "⁦", "⁧", "⁨", "⁩", "‎", "‏", "؜"}

# 识别出的类型 -> (中文说明, 合法扩展名, 是否属于 "可执行"类)
TYPES: Dict[str, Tuple[str, set, bool]] = {
    "pe":       ("Windows 可执行文件 (PE)", {"exe", "dll", "scr", "sys", "cpl", "ocx", "drv", "efi", "mui", "com", "msstyles"}, True),
    "elf":      ("Linux 可执行文件 (ELF)", {"", "so", "elf", "bin", "o", "ko"}, True),
    "macho":    ("macOS 可执行文件 (Mach-O)", {"", "dylib", "bundle", "o"}, True),
    "lnk":      ("Windows 快捷方式 (LNK)", {"lnk"}, True),
    "script":   ("脚本文本", set(), True),  # 扩展名由具体脚本语言决定，见 detect_script
    "ole":      ("OLE 复合文档（旧版 Office 等）", {"doc", "dot", "xls", "xlt", "xla", "ppt", "pot", "pps", "msg", "msi", "msp", "vsd", "pub", "mpp"}, False),
    "ole-doc":  ("Word 97-2003 文档", {"doc", "dot"}, False),
    "ole-xls":  ("Excel 97-2003 工作簿", {"xls", "xlt", "xla"}, False),
    "ole-ppt":  ("PowerPoint 97-2003 演示文稿", {"ppt", "pot", "pps"}, False),
    "ole-msg":  ("Outlook 邮件 (.msg)", {"msg"}, False),
    "ole-msi":  ("Windows 安装包 (MSI)", {"msi", "msp"}, True),
    "ole-encrypted": ("加密的 Office 文档", {"docx", "docm", "xlsx", "xlsm", "xlsb", "pptx", "pptm", "doc", "xls", "ppt"}, False),
    "docx":     ("Word 文档 (OOXML)", {"docx", "docm", "dotx", "dotm"}, False),
    "xlsx":     ("Excel 工作簿 (OOXML)", {"xlsx", "xlsm", "xlsb", "xltx", "xltm", "xlam"}, False),
    "pptx":     ("PowerPoint 演示文稿 (OOXML)", {"pptx", "pptm", "potx", "potm", "ppsx", "ppsm", "ppam"}, False),
    "odf":      ("OpenDocument 文档", {"odt", "ods", "odp", "odg", "ott", "ots"}, False),
    "jar":      ("Java 程序包 (JAR)", {"jar", "war", "ear"}, True),
    "apk":      ("Android 安装包 (APK)", {"apk"}, True),
    "zip":      ("ZIP 压缩包", {"zip", "zipx"}, False),
    "rar":      ("RAR 压缩包", {"rar"}, False),
    "7z":       ("7-Zip 压缩包", {"7z"}, False),
    "gzip":     ("gzip 压缩", {"gz", "tgz"}, False),
    "bzip2":    ("bzip2 压缩", {"bz2", "tbz2"}, False),
    "xz":       ("xz 压缩", {"xz", "txz"}, False),
    "cab":      ("Windows CAB 压缩包", {"cab"}, False),
    "iso":      ("光盘镜像 (ISO 9660)", {"iso", "img"}, False),
    "pdf":      ("PDF 文档", {"pdf"}, False),
    "rtf":      ("RTF 富文本", {"rtf"}, False),
    "chm":      ("Windows 帮助文件 (CHM)", {"chm"}, True),
    "png":      ("PNG 图片", {"png"}, False),
    "jpeg":     ("JPEG 图片", {"jpg", "jpeg", "jpe", "jfif"}, False),
    "gif":      ("GIF 图片", {"gif"}, False),
    "bmp":      ("BMP 图片", {"bmp", "dib"}, False),
    "webp":     ("WebP 图片", {"webp"}, False),
    "tiff":     ("TIFF 图片", {"tif", "tiff"}, False),
    "html":     ("HTML 网页", {"html", "htm", "xhtml", "shtml"}, False),
    "mht":      ("MHTML 单文件网页", {"mht", "mhtml", "doc", "xls", "eml"}, False),
    "word2003xml": ("Word 2003 XML 文档", {"xml", "doc"}, False),
    "slk":      ("SYLK 电子表格", {"slk", "sylk", "csv"}, False),
    "eml":      ("电子邮件 (EML)", {"eml", "msg", "txt"}, False),
    "text":     ("纯文本", {"txt", "csv", "log", "md", "json", "xml", "ini", "cfg", "conf", "yaml", "yml", "tsv", ""}, False),
}

SCRIPT_EXT = {"vbs", "vbe", "js", "jse", "wsf", "ps1", "psm1", "bat", "cmd", "hta", "sh", "py"}

# ---------------------------------------------------------------------------
# 数据结构
# ---------------------------------------------------------------------------
@dataclass
class Finding:
    severity: str        # high / medium / low / info
    category: str        # 伪装 / 宏 / PDF / 压缩包 / VirusTotal ...
    message: str
    detail: str = ""


@dataclass
class Report:
    name: str                          # 文件名（附件名）
    size: int
    file_type: str                     # TYPES 里的键，或 "unknown"
    type_desc: str
    extension: str
    md5: str = ""
    sha1: str = ""
    sha256: str = ""
    findings: List[Finding] = field(default_factory=list)
    macros: List[Dict] = field(default_factory=list)   # [{module, stream, lines, code?}]
    virustotal: Optional[Dict] = None
    children: List["Report"] = field(default_factory=list)  # 邮件附件 / 压缩包成员
    source: str = ""                   # 磁盘路径，或 "邮件附件"、"压缩包成员"
    error: str = ""

    def add(self, severity, category, message, detail=""):
        self.findings.append(Finding(severity, category, message, detail))

    @property
    def severity(self) -> str:
        """整体结论：自己和所有子项里最严重的那一级。"""
        sev = INFO
        for f in self.findings:
            if SEV_ORDER[f.severity] > SEV_ORDER[sev]:
                sev = f.severity
        for c in self.children:
            if SEV_ORDER[c.severity] > SEV_ORDER[sev]:
                sev = c.severity
        return sev

    def walk(self):
        yield self
        for c in self.children:
            yield from c.walk()

    def to_dict(self):
        d = asdict(self)
        d["children"] = [c.to_dict() for c in self.children]
        d["severity"] = self.severity
        return d


# ---------------------------------------------------------------------------
# 1. 魔数识别
# ---------------------------------------------------------------------------
def _is_pe(data: bytes) -> bool:
    if len(data) < 64 or data[:2] != b"MZ":
        return False
    off = int.from_bytes(data[0x3C:0x40], "little")
    return data[off:off + 4] == b"PE\0\0"


def detect_script(text: str) -> Optional[str]:
    """猜纯文本是不是脚本，返回语言（vbs/js/ps1/bat/hta/sh）或 None。"""
    head = text[:4096]
    low = head.lower()
    if low.startswith("#!"):
        return "sh"
    if re.search(r"<hta:application", low):
        return "hta"
    if re.search(r"\b(wscript\.shell|createobject\s*\(|wscript\.echo)\b", low) and \
            re.search(r"^\s*(dim|set|sub|function|on error)\b", low, re.M):
        return "vbs"
    if re.search(r"\b(new\s+activexobject|wscript\.createobject|wscript\.shell)", low):
        return "js"
    if re.search(r"(invoke-expression|\biex\s*\(|invoke-webrequest|-encodedcommand|-enc\s|new-object\s+"
                 r"net\.webclient|start-process|set-executionpolicy|powershell(\.exe)?\s+-(nop|w|e)\b)", low):
        return "ps1"
    if re.match(r"\s*@echo\s+off", low) or re.search(r"^\s*(set|if|goto|call)\s.*%\w+%", low, re.M):
        return "bat"
    return None


def detect_type(data: bytes) -> str:
    """只看内容、不看名字，返回 TYPES 里的一个键，认不出来返回 "unknown"。"""
    if data[:2] == b"MZ":
        return "pe"
    if data[:4] == b"\x7fELF":
        return "elf"
    if data[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        return "macho"
    if data[:20] == b"L\0\0\0\x01\x14\x02\0\0\0\0\0\xc0\0\0\0\0\0\0F":
        return "lnk"
    if data[:8] == b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1":
        return _ole_subtype(data)
    if data[:4] in (b"PK\x03\x04", b"PK\x05\x06"):
        return _zip_subtype(data)
    if b"%PDF-" in data[:1024]:
        return "pdf"
    if data[:5] == b"{\\rtf" or data[:4] == b"{\\rt":
        return "rtf"
    if data[:6] == b"Rar!\x1a\x07":
        return "rar"
    if data[:6] == b"7z\xbc\xaf\x27\x1c":
        return "7z"
    if data[:2] == b"\x1f\x8b":
        return "gzip"
    if data[:3] == b"BZh":
        return "bzip2"
    if data[:6] == b"\xfd7zXZ\0":
        return "xz"
    if data[:4] == b"MSCF":
        return "cab"
    if data[:4] == b"ITSF":
        return "chm"
    if len(data) > 0x8006 and data[0x8001:0x8006] == b"CD001":
        return "iso"
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return "png"
    if data[:3] == b"\xff\xd8\xff":
        return "jpeg"
    if data[:6] in (b"GIF87a", b"GIF89a"):
        return "gif"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "webp"
    if data[:4] in (b"II*\0", b"MM\0*"):
        return "tiff"
    if data[:2] == b"BM" and len(data) >= 14 and int.from_bytes(data[2:6], "little") == len(data):
        return "bmp"
    return _text_subtype(data)


def _ole_subtype(data: bytes) -> str:
    if olefile is None:
        return "ole"
    try:
        ole = olefile.OleFileIO(io.BytesIO(data))
    except Exception:
        return "ole"
    try:
        names = {"/".join(p).lower() for p in ole.listdir(streams=True, storages=True)}
    finally:
        ole.close()
    if "encryptioninfo" in names or "encryptedpackage" in names:
        return "ole-encrypted"
    if "worddocument" in names:
        return "ole-doc"
    if "workbook" in names or "book" in names:
        return "ole-xls"
    if "powerpoint document" in names:
        return "ole-ppt"
    if any(n.startswith("__substg1.0_") for n in names):
        return "ole-msg"
    # MSI 的流名用了特殊编码，但总会有 \x05SummaryInformation，且根 CLSID 固定；这里用一个简单特征
    if any("䡀" in n for n in names):
        return "ole-msi"
    return "ole"


def _zip_subtype(data: bytes) -> str:
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
        names = set(z.namelist())
    except Exception:
        return "zip"
    if "[Content_Types].xml" in names:
        if any(n.startswith("word/") for n in names):
            return "docx"
        if any(n.startswith("xl/") for n in names):
            return "xlsx"
        if any(n.startswith("ppt/") for n in names):
            return "pptx"
    if "mimetype" in names:
        try:
            if z.read("mimetype").startswith(b"application/vnd.oasis.opendocument"):
                return "odf"
        except Exception:
            pass
    if "AndroidManifest.xml" in names and "classes.dex" in names:
        return "apk"
    if "META-INF/MANIFEST.MF" in names:
        return "jar"
    return "zip"


def _text_subtype(data: bytes) -> str:
    sample = data[:8192]
    if not sample or b"\0" in sample.lstrip(b"\xff\xfe\xef\xbb\xbf")[:2048]:
        return "unknown"
    try:
        text = sample.decode("utf-8")
    except UnicodeDecodeError:
        try:
            text = sample.decode("latin-1")
        except Exception:  # pragma: no cover
            return "unknown"
        if sum(ch < " " and ch not in "\r\n\t\f" for ch in text) > len(text) // 20:
            return "unknown"
    low = text.lstrip("﻿ \r\n\t").lower()
    if re.match(r"(mime-version\s*:|content-type\s*:\s*multipart/related)", low) and "multipart" in low[:2000]:
        # MHT 和普通邮件长得很像；MHT 一般以 MIME-Version 开头且是 multipart/related
        if "multipart/related" in low[:2000]:
            return "mht"
    if sample.startswith(b"ID;P") or sample.startswith(b"ID;N"):
        return "slk"
    if re.match(r"(<\?xml[^>]*>\s*)?(<\?mso-application[^>]*word\.document)", low) or "<w:worddocument" in low[:4096]:
        return "word2003xml"
    if _looks_like_email(text):
        return "eml"
    if re.match(r"(<!doctype\s+html|<html|<head|<body|<script|<meta|<iframe|<svg)", low):
        return "html"
    if detect_script(text):
        return "script"
    return "text"


def _looks_like_email(text: str) -> bool:
    head = text[:4096]
    headers = re.findall(r"^(From|To|Subject|Date|Received|Message-ID|MIME-Version|Return-Path):",
                         head, re.M | re.I)
    return len({h.lower() for h in headers}) >= 3


# ---------------------------------------------------------------------------
# 2. 文件名检查（不看内容就能发现的伪装）
# ---------------------------------------------------------------------------
def split_ext(name: str) -> Tuple[str, str]:
    base = os.path.basename(name.replace("\\", "/"))
    clean = "".join(ch for ch in base if ch not in BIDI_CHARS)
    stem, dot, ext = clean.rpartition(".")
    if not dot:
        return clean, ""
    return stem, ext.lower().strip()


def check_name(report: Report, name: str):
    base = os.path.basename(name.replace("\\", "/"))
    bidi = [c for c in base if c in BIDI_CHARS]
    if bidi:
        report.add(HIGH, "伪装", "文件名含 Unicode 双向控制字符 %s，显示出来的扩展名是假的"
                   % ", ".join("U+%04X" % ord(c) for c in sorted(set(bidi))),
                   "真实文件名（去掉控制字符）：%s" % "".join(c for c in base if c not in BIDI_CHARS))
    if any(unicodedata.category(c) == "Cf" and c not in BIDI_CHARS for c in base):
        report.add(MEDIUM, "伪装", "文件名含不可见的格式字符（零宽字符等）")

    stem, ext = split_ext(base)
    report.extension = ext
    prev = stem.rpartition(".")[2].lower().strip() if "." in stem else ""
    if ext in EXEC_EXT | CONTAINER_EXT | MACRO_EXT and prev in DOC_LIKE_EXT:
        report.add(HIGH, "伪装", "双扩展名：看起来是 .%s，实际是 .%s" % (prev, ext),
                   "Windows 默认隐藏已知扩展名，用户只会看到 “%s”" % stem)
    if re.search(r"\s{5,}\.\w+$", base) or re.search(r"[_.\-]{8,}\.\w+$", base):
        report.add(MEDIUM, "伪装", "扩展名前有一长串空白/填充字符，常用来把真实扩展名挤出显示范围")

    if ext in EXEC_EXT:
        report.add(HIGH, "危险类型", "扩展名 .%s 双击即可执行代码，正常业务邮件几乎不会发这种附件" % ext)
    elif ext in CONTAINER_EXT:
        report.add(MEDIUM, "危险类型", "扩展名 .%s 是磁盘镜像/笔记容器，常被用来绕过 Mark-of-the-Web 和邮件网关" % ext)
    elif ext in MACRO_EXT:
        report.add(MEDIUM, "危险类型", "扩展名 .%s 是允许宏的 Office 格式" % ext)


def check_type_vs_ext(report: Report, data: bytes):
    ftype, ext = report.file_type, report.extension
    if ftype == "unknown":
        report.add(INFO, "类型", "认不出文件格式（魔数不在已知列表中）")
        return
    desc, allowed, is_exec = TYPES[ftype]
    if ftype == "script":
        lang = detect_script(data[:8192].decode("utf-8", "replace")) or "?"
        report.type_desc = "%s（像 %s）" % (desc, lang)
        if ext not in SCRIPT_EXT and ext != lang:
            report.add(MEDIUM, "伪装", "内容像 %s 脚本，但扩展名是 .%s" % (lang, ext or "(无)"),
                       "单独看不会执行，但说明有人想把脚本伪装成别的东西")
        return
    if ext in allowed:
        return
    if ftype == "text":
        # 纯文本可以叫任何代码/配置扩展名；只有冒充二进制格式（.pdf/.jpg/.exe…）才值得一提
        binary_exts = set().union(*(v[1] for k, v in TYPES.items() if k not in ("text", "eml", "mht", "word2003xml", "html")))
        if ext in binary_exts:
            report.add(LOW, "伪装", "扩展名是 .%s，但内容只是纯文本" % ext, "可能是损坏/误命名，也可能是诱饵")
        return
    if ftype == "pe" and not _is_pe(data):
        desc += "（只有 MZ 头，PE 结构不完整）"
    sev = HIGH if is_exec else MEDIUM
    hint = ""
    if ftype == "rtf" and ext in {"doc", "docx"}:
        hint = "RTF 改名成 .doc 是老套路：Word 照样能打开，很多公式编辑器漏洞（如 CVE-2017-11882）就这样投递"
    elif ftype in ("docx", "xlsx", "pptx") and ext in {"doc", "xls", "ppt"}:
        sev, hint = LOW, "新格式改成旧扩展名，Office 仍能打开；可能是误命名，也可能是在躲过滤规则"
    elif ftype == "zip" and ext in TYPES["docx"][1] | TYPES["xlsx"][1] | TYPES["pptx"][1]:
        hint = "是 ZIP 但不是有效的 Office 文档结构"
    elif ftype == "html":
        hint = "HTML 附件双击会在浏览器打开，常见于仿冒登录页和 HTML 走私"
    elif is_exec:
        hint = "实际内容是可执行程序，扩展名是伪装"
    report.add(sev, "伪装", "扩展名是 .%s，但内容其实是 %s" % (ext or "(无)", desc), hint)


# ---------------------------------------------------------------------------
# 3. 内容检查
# ---------------------------------------------------------------------------
OLEVBA_TYPES = {"ole", "ole-doc", "ole-xls", "ole-ppt", "ole-msg", "ole-encrypted",
                "docx", "xlsx", "pptx", "mht", "word2003xml", "slk"}
OLE_TYPES = {t for t in TYPES if t == "ole" or t.startswith("ole-")}
TYPE_CN = {"AutoExec": "自动执行", "Suspicious": "可疑", "IOC": "IOC",
           "Hex String": "十六进制字符串", "Base64 String": "Base64 字符串",
           "Dridex String": "Dridex 编码", "VBA string": "VBA 字符串表达式"}


def check_macros(report: Report, data: bytes, extract_dir: Optional[str]):
    if report.file_type not in OLEVBA_TYPES:
        return
    if olevba is None:
        report.add(INFO, "宏", "没装 oletools，跳过宏分析（pip install -r requirements.txt）")
        return
    try:
        parser = olevba.VBA_Parser(report.name or "attachment", data=data)
    except Exception as e:  # 格式损坏、不支持的变种
        report.add(INFO, "宏", "oletools 打不开这个文件：%s" % str(e)[:120])
        return
    try:
        has_vba = parser.detect_vba_macros()
        has_xlm = bool(parser.detect_xlm_macros()) if hasattr(parser, "detect_xlm_macros") else False
        if not (has_vba or has_xlm):
            return
        for subfile, stream, vba_name, code in parser.extract_all_macros():
            if not code:
                continue
            item = {"module": vba_name, "container": subfile, "stream": stream,
                    "lines": len(code.splitlines()), "code": code}
            if extract_dir:
                os.makedirs(extract_dir, exist_ok=True)
                safe = re.sub(r"[^\w.\-]+", "_", vba_name or "macro")
                path = os.path.join(extract_dir, "%s_%s.vba.txt" % (report.sha256[:12], safe))
                with open(path, "w", encoding="utf-8") as f:
                    f.write(code)
                item["saved_to"] = path
            report.macros.append(item)

        kinds = []
        if has_vba:
            kinds.append("VBA")
        if has_xlm:
            kinds.append("Excel 4.0 (XLM)")
        results = parser.analyze_macros() or []
        auto = [kw for t, kw, _ in results if t == "AutoExec"]
        susp = [kw for t, kw, _ in results if t == "Suspicious"]
        iocs = [kw for t, kw, _ in results if t == "IOC"]
        obf = [t for t, _, _ in results if t in ("Hex String", "Base64 String", "Dridex String", "VBA string")]

        sev = MEDIUM
        if auto and susp:
            sev = HIGH
        msg = "含 %s 宏（%d 个模块）" % (" + ".join(kinds), len(report.macros))
        if auto:
            msg += "，打开/关闭文档时会自动执行"
        report.add(sev, "宏", msg, "自动执行入口：%s" % ", ".join(sorted(set(auto))) if auto else "")
        if susp:
            report.add(HIGH if auto else MEDIUM, "宏", "宏里有可疑关键字：%s" % ", ".join(_uniq(susp)[:12]),
                       "; ".join("%s = %s" % (kw, d) for t, kw, d in results if t == "Suspicious")[:600])
        if iocs:
            report.add(INFO, "宏", "宏里出现的 IOC（网址/IP/可执行文件名）：%s" % ", ".join(_uniq(iocs)[:10]))
        if obf:
            report.add(MEDIUM, "宏", "宏里有编码/混淆过的字符串（%s）" % ", ".join(
                TYPE_CN.get(t, t) for t in _uniq(obf)))
    except Exception as e:
        report.add(INFO, "宏", "宏分析出错：%s" % str(e)[:120])
    finally:
        try:
            parser.close()
        except Exception:
            pass


def _uniq(items):
    seen, out = set(), []
    for x in items:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def check_encryption(report: Report, data: bytes, depth: int, opts) -> bool:
    """加密的 Office 文档：先用 Office 的默认密码试解（VelvetSweatshop 等）。
    解开了就把解密后的内容当成子项继续分析；解不开就提醒。返回 True 表示已加密。"""
    if report.file_type not in OLE_TYPES or olecrypto is None:
        return False
    fd, path = tempfile.mkstemp(prefix="triage-", suffix="." + (report.extension or "bin"))
    decrypted = None
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        try:
            if not olecrypto.is_encrypted(path):
                return False
        except Exception:
            return False
        try:
            decrypted = olecrypto.decrypt(path)
        except Exception:
            decrypted = None
        if decrypted:
            with open(decrypted, "rb") as f:
                plain = f.read()
            report.add(MEDIUM, "加密", "加密的 Office 文档，但用 Office 内置默认密码就能解开",
                       "这是常见的躲扫描手法：用户打开时无感，网关却看不到内容。下面分析的是解密后的内容")
            if depth < MAX_DEPTH:
                report.children.append(analyze_bytes(report.name, plain, opts, depth + 1, source="默认密码解密后"))
        else:
            report.add(MEDIUM, "加密", "加密的 Office 文档：没有密码就无法检查里面的宏和内容",
                       "钓鱼邮件常把密码写在正文里；确认来源前不要输入密码打开")
        return True
    finally:
        for p in (path, decrypted):
            if p:
                try:
                    os.remove(p)
                except OSError:
                    pass


def check_ooxml(report: Report, data: bytes):
    """OOXML（docx/xlsx/pptx）：外部关系（远程模板、外链 OLE 对象）、内嵌对象、宏工程。"""
    if report.file_type not in ("docx", "xlsx", "pptx"):
        return
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
    except Exception:
        return
    names = z.namelist()
    if any(n.lower().endswith("vbaproject.bin") for n in names) and report.extension in {"docx", "xlsx", "pptx", "dotx", "xltx", "potx"}:
        report.add(MEDIUM, "伪装", "扩展名 .%s 表示 “不含宏”，但包里有 vbaProject.bin" % report.extension)
    for n in names:
        if not n.endswith(".rels"):
            continue
        try:
            xml = z.read(n).decode("utf-8", "replace")
        except Exception:
            continue
        for rel in re.findall(r"<Relationship\b[^>]*>", xml):
            if not re.search(r'TargetMode\s*=\s*"External"', rel, re.I):
                continue
            target = (re.search(r'Target\s*=\s*"([^"]*)"', rel) or [None, ""])[1]
            rtype = (re.search(r'Type\s*=\s*"([^"]*)"', rel) or [None, ""])[1].rsplit("/", 1)[-1]
            if rtype in ("attachedTemplate", "oleObject", "frame", "subDocument"):
                report.add(HIGH, "远程加载",
                           "外部 %s 关系：打开文档时会去远程拉取 %s" % (rtype, target),
                           "远程模板注入（T1221）：文档本身干净，恶意宏在远程模板里")
            elif rtype not in ("hyperlink",):
                report.add(LOW, "远程加载", "外部关系 %s -> %s" % (rtype, target))
    sheets = [n for n in names if n.startswith("xl/macrosheets/")]
    if sheets:
        auto = False
        try:
            wb = z.read("xl/workbook.xml").decode("utf-8", "replace") if "xl/workbook.xml" in names else ""
            auto = bool(re.search(r"_xlnm\.Auto_(Open|Close|Activate)|Auto_Open", wb, re.I))
        except Exception:
            pass
        report.add(HIGH if auto else MEDIUM, "宏",
                   "含 Excel 4.0 (XLM) 宏表 %d 个%s" % (len(sheets), "，并定义了 Auto_Open 自动执行" if auto else ""),
                   "XLM 宏比 VBA 更老、也更容易被忽略，很多宏病毒（如 Zloader）用它")
    embeds = [n for n in names if re.search(r"/(embeddings|activeX)/", n)]
    if embeds:
        report.add(LOW, "内嵌对象", "包含 %d 个内嵌对象/ActiveX：%s" % (len(embeds), ", ".join(embeds[:5])),
                   "可以用 oletools 的 oleobj 进一步提取")


PDF_KEYS = [
    ("/JavaScript", HIGH, "内嵌 JavaScript"),
    ("/JS", HIGH, "内嵌 JavaScript"),
    ("/Launch", HIGH, "Launch 动作：可以启动外部程序"),
    ("/OpenAction", MEDIUM, "打开即触发的动作 (OpenAction)"),
    ("/AA", MEDIUM, "附加动作 (AA)：翻页/打开/关闭时触发"),
    ("/EmbeddedFile", MEDIUM, "内嵌文件"),
    ("/XFA", MEDIUM, "XFA 表单（历史上漏洞很多）"),
    ("/RichMedia", MEDIUM, "RichMedia（Flash 等）"),
    ("/SubmitForm", LOW, "SubmitForm：可能把表单内容提交到外部"),
    ("/URI", INFO, "包含链接"),
]


def _pdf_normalize(data: bytes) -> bytes:
    """把名字里的 #xx 十六进制转义还原：/Java#53cript -> /JavaScript（经典混淆手法）。"""
    return re.sub(rb"/[^\s/<>\[\]()]+",
                  lambda m: re.sub(rb"#([0-9A-Fa-f]{2})", lambda h: bytes([int(h.group(1), 16)]), m.group(0)),
                  data)


def check_pdf(report: Report, data: bytes):
    if report.file_type != "pdf":
        return
    norm = _pdf_normalize(data)
    obfuscated = norm != data and re.search(rb"/[A-Za-z]*#[0-9A-Fa-f]{2}", data)
    hits = []
    for key, sev, desc in PDF_KEYS:
        n = len(re.findall(re.escape(key.encode()) + rb"(?![A-Za-z])", norm))
        if n:
            hits.append((key, sev, desc, n))
    # /JS 和 /JavaScript 只报一次
    keys = {h[0] for h in hits}
    for key, sev, desc, n in hits:
        if key == "/JS" and "/JavaScript" in keys:
            continue
        if sev == INFO:
            report.add(INFO, "PDF", "%s（%d 处）" % (desc, n))
        else:
            report.add(sev, "PDF", "%s（%s × %d）" % (desc, key, n))
    if obfuscated:
        report.add(HIGH, "PDF", "PDF 名字用了 #xx 十六进制转义来躲关键字检测（例如 /Java#53cript）")
    if b"/Encrypt" in norm:
        report.add(LOW, "PDF", "PDF 已加密，内容流无法直接检查")


def check_rtf(report: Report, data: bytes):
    if report.file_type != "rtf":
        return
    low = data.lower()
    # (?<!\\)：排除 "\\object" 这种被转义的普通文字（例如 RTF 规范文档本身）
    if re.search(rb"(?<!\\)\\(objdata|object)\b", low):
        sev = HIGH if re.search(rb"equation\.3|\\objupdate", low) else MEDIUM
        report.add(sev, "RTF", "RTF 里嵌入了 OLE 对象%s" % ("（含公式编辑器/自动更新特征）" if sev == HIGH else ""),
                   "可以用 oletools 的 rtfobj 提取分析")


def check_html(report: Report, data: bytes):
    if report.file_type not in ("html", "mht"):
        return
    low = data[:2_000_000].lower()
    signs = [s for s in (b"atob(", b"new blob", b"createobjecturl", b".download", b"msSaveOrOpenBlob".lower())
             if s in low]
    if len(signs) >= 2:
        report.add(HIGH, "HTML", "疑似 HTML 走私：页面在浏览器里用脚本拼出文件并自动下载",
                   "命中特征：" + ", ".join(s.decode() for s in signs))
    if re.search(rb"<form[^>]+action\s*=\s*[\"']?https?://", low) and re.search(rb"type\s*=\s*[\"']?password", low):
        report.add(HIGH, "HTML", "本地 HTML 里有提交到外部网址的密码表单，典型仿冒登录页")
    elif re.search(rb"<meta[^>]+http-equiv\s*=\s*[\"']?refresh", low) or re.search(rb"window\.location", low):
        report.add(MEDIUM, "HTML", "打开后会自动跳转到其它网址")


def is_encrypted_member(info: zipfile.ZipInfo) -> bool:
    return bool(info.flag_bits & 0x1)


def check_archive(report: Report, data: bytes, depth: int, opts) -> None:
    """ZIP（含 JAR 外的普通压缩包）：列成员，查加密和危险扩展名，能解开的递归分析。"""
    if report.file_type not in ("zip",):
        if report.file_type in ("rar", "7z", "cab", "iso", "gzip", "bzip2", "xz"):
            report.add(LOW, "压缩包", "%s：本工具不解包，建议在隔离环境里列出内容再判断" % report.type_desc)
        return
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
        infos = z.infolist()
    except Exception as e:
        report.add(LOW, "压缩包", "ZIP 结构损坏：%s" % e)
        return
    enc = [i for i in infos if is_encrypted_member(i)]
    if enc:
        report.add(MEDIUM, "压缩包", "%d/%d 个成员有密码保护：网关和杀软都扫不到里面" % (len(enc), len(infos)),
                   "钓鱼邮件常把密码写在正文里（“密码 1234”）")
    for info in infos:
        if info.is_dir():
            continue
        if depth >= MAX_DEPTH or is_encrypted_member(info) or info.file_size > MAX_MEMBER_SIZE:
            child = Report(info.filename, info.file_size, "unknown", "未解包", "", source="压缩包成员（未解包）")
            check_name(child, info.filename)
            report.children.append(child)
            continue
        try:
            member = z.read(info)
        except Exception as e:
            child = Report(info.filename, info.file_size, "unknown", "读取失败", "", source="压缩包成员",
                           error=str(e))
            report.children.append(child)
            continue
        report.children.append(analyze_bytes(info.filename, member, opts, depth + 1, source="压缩包成员"))


def check_email(report: Report, data: bytes, depth: int, opts):
    if report.file_type != "eml":
        return
    try:
        msg = email.message_from_bytes(data, policy=email.policy.default)
    except Exception as e:
        report.add(LOW, "邮件", "邮件解析失败：%s" % e)
        return
    report.type_desc += "  主题: %s | 发件人: %s" % (str(msg.get("Subject", ""))[:80], str(msg.get("From", ""))[:80])
    count = 0
    for part in msg.walk():
        if part.is_multipart():
            continue
        fname = part.get_filename()
        disp = part.get_content_disposition()
        if not fname and disp != "attachment" and part.get_content_type() != "message/rfc822":
            continue
        count += 1
        name = fname or "attachment-%d" % count
        payload = part.get_payload(decode=True)
        if payload is None:  # message/rfc822 里面是解析好的 Message
            inner = part.get_payload()
            payload = inner[0].as_bytes() if isinstance(inner, list) and inner else b""
            if not fname:
                name += ".eml"
        if depth >= MAX_DEPTH:
            child = Report(name, len(payload), "unknown", "未分析（层数太深）", "", source="邮件附件")
            check_name(child, name)
            report.children.append(child)
            continue
        report.children.append(analyze_bytes(name, payload, opts, depth + 1, source="邮件附件"))
    if count == 0:
        report.add(INFO, "邮件", "这封邮件没有附件")


# ---------------------------------------------------------------------------
# 4. 哈希与 VirusTotal
# ---------------------------------------------------------------------------
def hashes(data: bytes) -> Tuple[str, str, str]:
    return (hashlib.md5(data).hexdigest(), hashlib.sha1(data).hexdigest(),
            hashlib.sha256(data).hexdigest())


class VTError(Exception):
    def __init__(self, message, fatal=False):
        super().__init__(message)
        self.fatal = fatal  # True：key 错误/额度用完，后面的也别查了


class VirusTotal:
    """只做 GET /api/v3/files/{hash}。免费 key 每分钟 4 次，所以默认两次查询间隔 15 秒。"""

    def __init__(self, api_key: str, delay: float = 15.0, timeout: float = 20.0):
        self.api_key = api_key
        self.delay = delay
        self.timeout = timeout
        self._last = 0.0
        self.cache: Dict[str, Dict] = {}
        self.disabled_reason = ""

    def lookup(self, sha256: str) -> Dict:
        sha256 = sha256.lower()
        if sha256 in self.cache:
            return self.cache[sha256]
        if self.disabled_reason:
            return {"status": "skipped", "reason": self.disabled_reason}
        wait = self._last + self.delay - time.monotonic()
        if self._last and wait > 0:
            time.sleep(wait)
        self._last = time.monotonic()
        req = urllib.request.Request(VT_URL + sha256, headers={
            "x-apikey": self.api_key, "accept": "application/json", "User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = json.loads(resp.read().decode("utf-8"))
            result = parse_vt(body)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                result = {"status": "not_found"}
            elif e.code in (401, 403):
                self.disabled_reason = "API key 无效或没有权限 (HTTP %d)" % e.code
                result = {"status": "error", "reason": self.disabled_reason}
            elif e.code == 429:
                self.disabled_reason = "超出 VirusTotal 配额 (HTTP 429)，稍后再试或加大 --vt-delay"
                result = {"status": "error", "reason": self.disabled_reason}
            else:
                result = {"status": "error", "reason": "HTTP %d" % e.code}
        except (urllib.error.URLError, OSError, ValueError) as e:
            result = {"status": "error", "reason": "网络错误：%s" % getattr(e, "reason", e)}
        if result["status"] in ("found", "not_found"):
            self.cache[sha256] = result
        return result


def parse_vt(body: Dict) -> Dict:
    attr = body.get("data", {}).get("attributes", {})
    stats = attr.get("last_analysis_stats", {}) or {}
    total = sum(v for v in stats.values() if isinstance(v, int))
    label = (attr.get("popular_threat_classification") or {}).get("suggested_threat_label", "")
    return {
        "status": "found",
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "total": total,
        "label": label,
        "names": (attr.get("names") or [])[:5],
        "type": attr.get("type_description", ""),
        "first_seen": attr.get("first_submission_date"),
        "link": "https://www.virustotal.com/gui/file/%s" % body.get("data", {}).get("id", ""),
    }


def apply_vt(report: Report, result: Dict):
    report.virustotal = result
    st = result.get("status")
    if st == "found":
        mal, sus, total = result["malicious"], result["suspicious"], result["total"]
        label = ("，家族标签：%s" % result["label"]) if result.get("label") else ""
        if mal >= 3:
            report.add(HIGH, "VirusTotal", "%d/%d 个引擎报毒%s" % (mal, total, label), result["link"])
        elif mal or sus:
            report.add(MEDIUM, "VirusTotal", "%d/%d 个引擎报毒，%d 个标为可疑%s" % (mal, total, sus, label),
                       result["link"])
        else:
            report.add(INFO, "VirusTotal", "0/%d 个引擎报毒（不等于安全，可能只是还没人识别出来）" % total,
                       result["link"])
    elif st == "not_found":
        report.add(INFO, "VirusTotal", "VirusTotal 没见过这个文件",
                   "定向攻击样本通常是全新的，“没见过” 不代表安全")
    elif st in ("error", "skipped"):
        report.add(INFO, "VirusTotal", "查询失败：%s" % result.get("reason", "?"))


# ---------------------------------------------------------------------------
# 5. 主流程
# ---------------------------------------------------------------------------
class Options:
    def __init__(self, vt: Optional[VirusTotal] = None, extract_dir: Optional[str] = None,
                 vt_children: bool = True):
        self.vt = vt
        self.extract_dir = extract_dir
        self.vt_children = vt_children


def analyze_bytes(name: str, data: bytes, opts: Optional[Options] = None, depth: int = 0,
                  source: str = "") -> Report:
    opts = opts or Options()
    ftype = detect_type(data)
    desc = TYPES[ftype][0] if ftype in TYPES else "未知格式"
    r = Report(name=name, size=len(data), file_type=ftype, type_desc=desc, extension="", source=source)
    r.md5, r.sha1, r.sha256 = hashes(data)
    check_name(r, name)
    check_type_vs_ext(r, data)
    if not check_encryption(r, data, depth, opts):
        check_macros(r, data, opts.extract_dir)
    check_ooxml(r, data)
    check_pdf(r, data)
    check_rtf(r, data)
    check_html(r, data)
    check_archive(r, data, depth, opts)
    check_email(r, data, depth, opts)
    if r.size == 0:
        r.add(INFO, "类型", "空文件")
    # 邮件本身不查 VT（每封邮件的哈希都不一样，没意义），查它的附件
    if opts.vt and ftype != "eml" and r.size and (depth == 0 or opts.vt_children):
        apply_vt(r, opts.vt.lookup(r.sha256))
    return r


def analyze_path(path: str, opts: Options) -> Report:
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError as e:
        r = Report(os.path.basename(path), 0, "unknown", "读取失败", "", source=path, error=str(e))
        return r
    r = analyze_bytes(os.path.basename(path), data, opts, source=path)
    return r


def iter_paths(paths: List[str]):
    for p in paths:
        if os.path.isdir(p):
            for root, dirs, files in os.walk(p):
                dirs.sort()
                for fn in sorted(files):
                    yield os.path.join(root, fn)
        else:
            yield p


# ---------------------------------------------------------------------------
# 输出
# ---------------------------------------------------------------------------
def human_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return ("%d %s" % (n, unit)) if unit == "B" else ("%.1f %s" % (n, unit))
        n /= 1024.0
    return str(n)  # pragma: no cover


def safe_name(name: str) -> str:
    """把双向控制字符显示成 <U+202E>，避免终端里也被 "反转" 骗到。"""
    return "".join("<U+%04X>" % ord(c) if c in BIDI_CHARS or unicodedata.category(c) == "Cf" else c
                   for c in name)


def print_report(r: Report, verbose: bool = False, indent: int = 0, out=None):
    out = out or sys.stdout
    pad = "   " * indent
    p = lambda s="": print(pad + s, file=out)  # noqa: E731
    head = "🔎" if indent == 0 else "└─"
    p("%s %s  (%s)%s" % (head, safe_name(r.name), human_size(r.size), ("  ← " + r.source) if indent and r.source else ""))
    if r.error:
        p("   ❗ %s" % r.error)
        return
    p("   类型:   %s   扩展名: .%s" % (r.type_desc, r.extension or "(无)"))
    if r.sha256:
        if verbose:
            p("   MD5:    %s" % r.md5)
            p("   SHA-1:  %s" % r.sha1)
        p("   SHA256: %s" % r.sha256)
    p("   结论:   %s" % VERDICT[r.severity])
    for f in sorted(r.findings, key=lambda f: -SEV_ORDER[f.severity]):
        p("   %s [%s] %s: %s" % (SEV_ICON[f.severity], SEV_LABEL[f.severity], f.category, f.message))
        if f.detail:
            p("        %s" % f.detail)
    for m in r.macros:
        p("   📜 宏模块 %s（%d 行）%s" % (m["module"], m["lines"],
                                     ("  已保存到 " + m["saved_to"]) if m.get("saved_to") else ""))
        if verbose:
            for line in m["code"].splitlines()[:60]:
                p("      | " + line)
            if m["lines"] > 60:
                p("      | …（还有 %d 行，用 --extract-dir 保存完整源码）" % (m["lines"] - 60))
    for c in r.children:
        print_report(c, verbose, indent + 1, out)
    if indent == 0:
        p()


def exit_code(reports: List[Report]) -> int:
    if any(r.error for top in reports for r in top.walk()):
        return 2
    worst = max((SEV_ORDER[r.severity] for r in reports), default=0)
    return 1 if worst >= SEV_ORDER[MEDIUM] else 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="邮件附件快速分诊：魔数 vs 扩展名、Office 宏提取、哈希 + VirusTotal 查询（只查哈希，不上传）。",
        epilog="VirusTotal API key 推荐用环境变量传入：export VT_API_KEY=...")
    ap.add_argument("paths", nargs="*", help="文件、目录或 .eml 邮件（目录会递归）")
    ap.add_argument("--hash", action="append", default=[], metavar="HASH",
                    help="直接按哈希查 VirusTotal（MD5/SHA-1/SHA-256，可重复）")
    ap.add_argument("--vt", action="store_true", help="用 VirusTotal 查询哈希（需要 VT_API_KEY 或 --vt-key）")
    ap.add_argument("--vt-key", help="VirusTotal API key（会留在 shell 历史里，更推荐环境变量 VT_API_KEY）")
    ap.add_argument("--vt-delay", type=float, default=15.0,
                    help="两次 VirusTotal 请求之间的间隔秒数（免费 key 每分钟 4 次，默认 15）")
    ap.add_argument("--vt-top-only", action="store_true",
                    help="只查最外层文件，不查邮件附件/压缩包成员（省配额）")
    ap.add_argument("-x", "--extract-dir", help="把提取出的宏源码保存到这个目录")
    ap.add_argument("-v", "--verbose", action="store_true", help="显示 MD5/SHA-1 和宏源码")
    ap.add_argument("--json", action="store_true", help="输出 JSON")
    args = ap.parse_args(argv)

    if not args.paths and not args.hash:
        ap.error("请给出要分析的文件/目录，或用 --hash 查询哈希")

    vt = None
    if args.vt or args.hash:
        key = args.vt_key or os.environ.get("VT_API_KEY", "")
        if not key:
            ap.error("要查 VirusTotal 需要 API key：export VT_API_KEY=你的key（https://www.virustotal.com 免费注册）")
        vt = VirusTotal(key.strip(), delay=args.vt_delay)
    opts = Options(vt=vt, extract_dir=args.extract_dir, vt_children=not args.vt_top_only)

    reports = [analyze_path(p, opts) for p in iter_paths(args.paths)]

    hash_results = []
    for h in args.hash:
        h = h.strip().lower()
        if not re.fullmatch(r"[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}", h):
            hash_results.append({"hash": h, "status": "error", "reason": "不是合法的 MD5/SHA-1/SHA-256"})
            continue
        res = vt.lookup(h)
        res["hash"] = h
        hash_results.append(res)

    if args.json:
        print(json.dumps({"files": [r.to_dict() for r in reports], "hash_lookups": hash_results},
                         ensure_ascii=False, indent=2))
    else:
        for r in reports:
            print_report(r, args.verbose)
        for res in hash_results:
            tmp = Report(res["hash"], 0, "unknown", "", "")
            apply_vt(tmp, res)
            f = tmp.findings[0]
            print("🔎 %s\n   %s [%s] %s%s\n" % (res["hash"], SEV_ICON[f.severity], SEV_LABEL[f.severity],
                                             f.message, ("\n        " + f.detail) if f.detail else ""))
        if reports:
            worst = max(reports, key=lambda r: SEV_ORDER[r.severity]).severity
            total = sum(1 for top in reports for _ in top.walk())
            print("共分析 %d 个对象（含附件/压缩包成员），最高风险：%s" % (total, VERDICT[worst]))

    code = exit_code(reports)
    if any(r.get("status") == "error" for r in hash_results):
        code = max(code, 2)
    if any(r.get("status") == "found" and r.get("malicious", 0) >= 3 for r in hash_results):
        code = max(code, 1)
    return code


if __name__ == "__main__":
    sys.exit(main())
