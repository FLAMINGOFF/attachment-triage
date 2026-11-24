#!/usr/bin/env python3
"""
生成一组 **无害** 的演示/测试样本（Generate harmless demo samples）。

    python3 samples/make_samples.py            # 写到 samples/out/
    python3 samples/make_samples.py /tmp/demo  # 写到指定目录

所有样本都是现场用 Python 拼出来的，仓库里不放任何二进制样本：
- invoice.pdf.exe   只有 MZ/PE 头的 "空壳"，没有任何代码，不能运行
- photo.jpg         同上的空壳，但扩展名伪装成图片
- macro_demo.docm   含 VBA 宏：AutoOpen 里只有一个 MsgBox；可疑关键字只出现在字符串里
- template.docx     远程模板注入的结构，目标是永远解析不到的 example.invalid
- scan.pdf          OpenAction + JavaScript，脚本内容只是 app.alert
- report.doc        其实是 RTF（真实攻击常这样伪装 .doc）
- archive.zip       压缩包里有一个 .js（内容只是一行注释）
- phish.eml         一封带上述几个附件的邮件，附件名里有 RTLO 字符

只依赖 Python 标准库。
"""

import io
import os
import struct
import sys
import zipfile
from email.message import EmailMessage

# ---------------------------------------------------------------------------
# 1. 最小的 OLE / CFB（复合文档）写入器
#    MS-CFB 规范，版本 3（512 字节扇区）。小于 4096 字节的流放进 mini stream。
# ---------------------------------------------------------------------------
SECTOR = 512
MINI = 64
CUTOFF = 4096
FREESECT, ENDOFCHAIN, FATSECT, NOSTREAM = 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFD, 0xFFFFFFFF


def _pad(b, n):
    return b + b"\0" * (-len(b) % n)


def _cfb_key(name):
    # CFB 规定的兄弟节点排序：先比长度，再比大写后的名字
    return (len(name), name.upper())


def build_cfb(streams):
    """streams: {"VBA/dir": b"...", "PROJECT": b"..."} -> OLE 文件字节。"""
    root = {"name": "Root Entry", "type": 5, "children": {}, "data": b""}
    for path, data in streams.items():
        node = root
        parts = path.split("/")
        for p in parts[:-1]:
            node = node["children"].setdefault(p, {"name": p, "type": 1, "children": {}, "data": b""})
        node["children"][parts[-1]] = {"name": parts[-1], "type": 2, "children": {}, "data": data}

    entries = []

    def add(node):
        node["id"] = len(entries)
        entries.append(node)
        for child in node["children"].values():
            add(child)

    add(root)

    def balance(nodes):
        """把排好序的兄弟节点建成平衡二叉树，返回根的 id。"""
        if not nodes:
            return NOSTREAM
        mid = len(nodes) // 2
        nodes[mid]["left"] = balance(nodes[:mid])
        nodes[mid]["right"] = balance(nodes[mid + 1:])
        return nodes[mid]["id"]

    for e in entries:
        e.setdefault("left", NOSTREAM)
        e.setdefault("right", NOSTREAM)
    for e in entries:
        kids = sorted(e["children"].values(), key=lambda n: _cfb_key(n["name"]))
        e["child"] = balance(kids)

    # mini stream：小流按 64 字节一格依次排开
    ministream, minifat = b"", []
    for e in entries:
        if e["type"] == 2 and len(e["data"]) < CUTOFF:
            data = e["data"]
            if not data:
                e["start"] = ENDOFCHAIN
                continue
            first = len(ministream) // MINI
            count = -(-len(data) // MINI)
            e["start"] = first
            minifat += [first + i + 1 for i in range(count - 1)] + [ENDOFCHAIN]
            ministream += _pad(data, MINI)

    # 普通扇区里要放的链：目录、MiniFAT、mini stream、大流
    chains = []  # [(owner, bytes)]
    chains.append(("dir", len(_pad(b"\0" * (128 * len(entries)), SECTOR))))
    minifat_blob = b""
    if minifat:
        # 剩下的位置填 FREESECT
        minifat_blob = b"".join(struct.pack("<I", x) for x in minifat)
        minifat_blob += struct.pack("<I", FREESECT) * ((-len(minifat_blob) % SECTOR) // 4)
        chains.append(("minifat", len(minifat_blob)))
    if ministream:
        chains.append(("ministream", len(_pad(ministream, SECTOR))))
    for e in entries:
        if e["type"] == 2 and len(e["data"]) >= CUTOFF:
            chains.append((e["id"], len(_pad(e["data"], SECTOR))))

    data_sectors = sum(n // SECTOR for _, n in chains)
    nfat = 1
    while nfat * (SECTOR // 4) < data_sectors + nfat:
        nfat += 1
    assert nfat <= 109, "样本太大，这个小写入器不支持 DIFAT"

    fat = [FATSECT] * nfat
    starts = {}
    for owner, n in chains:
        count = n // SECTOR
        first = len(fat)
        starts[owner] = first
        fat += [first + i + 1 for i in range(count - 1)] + [ENDOFCHAIN]
    fat += [FREESECT] * (nfat * (SECTOR // 4) - len(fat))

    root["start"] = starts.get("ministream", ENDOFCHAIN)
    root["data_len"] = len(ministream)
    for e in entries:
        if e["type"] == 2 and len(e["data"]) >= CUTOFF:
            e["start"] = starts[e["id"]]

    def dirent(e):
        name = e["name"].encode("utf-16-le") + b"\0\0"
        size = e.get("data_len", len(e["data"])) if e["type"] != 1 else 0
        start = e.get("start", 0) if e["type"] != 1 else 0
        return (name.ljust(64, b"\0") + struct.pack("<HBB", len(name), e["type"], 1)
                + struct.pack("<III", e["left"], e["right"], e["child"])
                + b"\0" * 16 + b"\0" * 4 + b"\0" * 16
                + struct.pack("<IQ", start, size))

    empty = b"\0" * 64 + struct.pack("<HBB", 0, 0, 0) + struct.pack("<III", NOSTREAM, NOSTREAM, NOSTREAM) \
        + b"\0" * 36 + struct.pack("<IQ", 0, 0)
    dir_blob = b"".join(dirent(e) for e in entries)
    dir_blob += empty * ((-len(dir_blob) % SECTOR) // 128)

    blobs = {"dir": dir_blob, "minifat": minifat_blob, "ministream": _pad(ministream, SECTOR)}
    for e in entries:
        if e["type"] == 2 and len(e["data"]) >= CUTOFF:
            blobs[e["id"]] = _pad(e["data"], SECTOR)

    difat = list(range(nfat)) + [FREESECT] * (109 - nfat)
    header = (b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1" + b"\0" * 16
              + struct.pack("<HHHHH", 0x3E, 3, 0xFFFE, 9, 6) + b"\0" * 6
              + struct.pack("<IIIIIIIII", 0, nfat, starts["dir"], 0, CUTOFF,
                            starts.get("minifat", ENDOFCHAIN), len(minifat_blob) // SECTOR,
                            ENDOFCHAIN, 0)
              + b"".join(struct.pack("<I", x) for x in difat))
    assert len(header) == SECTOR
    fat_blob = b"".join(struct.pack("<I", x) for x in fat)
    return header + fat_blob + b"".join(blobs[owner] for owner, _ in chains)


# ---------------------------------------------------------------------------
# 2. VBA 工程（MS-OVBA）：dir 流 + 模块流 + PROJECT 流
# ---------------------------------------------------------------------------
def ovba_compress(data):
    """MS-OVBA 压缩容器，只用 "字面量" token（不做真正的压缩，但格式合法）。"""
    out = bytearray(b"\x01")
    step = 3584  # 每块 3584 字节原文 -> 3584 + 448 字节，块大小 <= 4096
    for i in range(0, len(data), step):
        chunk = data[i:i + step]
        body = bytearray()
        for j in range(0, len(chunk), 8):
            body.append(0)  # flag byte：8 个 token 全是字面量
            body += chunk[j:j + 8]
        header = (len(body) + 2 - 3) | 0x3000 | 0x8000
        out += struct.pack("<H", header) + body
    return bytes(out)


def _rec(rid, payload):
    return struct.pack("<HI", rid, len(payload)) + payload


def build_vba_project(modules):
    """modules: {"Module1": "VBA 源码"} -> vbaProject.bin（OLE）字节。"""
    name = b"VBAProject"
    d = b""
    d += _rec(0x0001, struct.pack("<I", 1))          # PROJECTSYSKIND: Win32
    d += _rec(0x0002, struct.pack("<I", 0x409))      # PROJECTLCID
    d += _rec(0x0014, struct.pack("<I", 0x409))      # PROJECTLCIDINVOKE
    d += _rec(0x0003, struct.pack("<H", 1252))       # PROJECTCODEPAGE
    d += _rec(0x0004, name)                          # PROJECTNAME
    d += _rec(0x0005, b"") + _rec(0x0040, b"")       # PROJECTDOCSTRING (+unicode)
    d += _rec(0x0006, b"") + _rec(0x003D, b"")       # PROJECTHELPFILEPATH
    d += _rec(0x0007, struct.pack("<I", 0))          # PROJECTHELPCONTEXT
    d += _rec(0x0008, struct.pack("<I", 0))          # PROJECTLIBFLAGS
    d += struct.pack("<HIIH", 0x0009, 4, 1, 0)       # PROJECTVERSION
    d += _rec(0x000C, b"") + _rec(0x003C, b"")       # PROJECTCONSTANTS
    d += _rec(0x000F, struct.pack("<H", len(modules)))   # PROJECTMODULES
    d += _rec(0x0013, struct.pack("<H", 0xFFFF))         # PROJECTCOOKIE
    streams = {}
    for mod in modules:
        m = mod.encode("ascii")
        u = mod.encode("utf-16-le")
        d += _rec(0x0019, m) + _rec(0x0047, u)       # MODULENAME (+unicode)
        d += _rec(0x001A, m) + _rec(0x0032, u)       # MODULESTREAMNAME (+unicode)
        d += _rec(0x001C, b"") + _rec(0x0048, b"")   # MODULEDOCSTRING
        d += _rec(0x0031, struct.pack("<I", 0))      # MODULEOFFSET：源码从流开头开始
        d += _rec(0x001E, struct.pack("<I", 0))      # MODULEHELPCONTEXT
        d += _rec(0x002C, struct.pack("<H", 0xFFFF)) # MODULECOOKIE
        d += _rec(0x0021, b"")                       # MODULETYPE: 标准模块
        d += _rec(0x002B, b"")                       # 模块结束
        src = ('Attribute VB_Name = "%s"\r\n' % mod + modules[mod]).encode("cp1252")
        streams["VBA/" + mod] = ovba_compress(src)
    d += _rec(0x0010, b"")                           # dir 结束
    streams["VBA/dir"] = ovba_compress(d)
    # 版本号 0xFFFF：告诉 Office 忽略性能缓存、从源码重新编译（规范允许）
    streams["VBA/_VBA_PROJECT"] = struct.pack("<HHBH", 0x61CC, 0xFFFF, 0, 0)
    project = 'ID="{00000000-0000-0000-0000-000000000000}"\r\n'
    project += "".join("Module=%s\r\n" % m for m in modules)
    project += 'Name="VBAProject"\r\nHelpContextID="0"\r\n'
    streams["PROJECT"] = project.encode("ascii")
    return build_cfb(streams)


DEMO_MACRO = (
    "Sub AutoOpen()\r\n"
    "    ' Harmless demo: this macro only shows a message box.\r\n"
    "    Dim note As String\r\n"
    "    note = \"Real malware would call Shell or CreateObject(\"\"WScript.Shell\"\") here, \" & _\r\n"
    "           \"then download http://example.invalid/payload.exe\"\r\n"
    "    MsgBox \"attachment-triage demo macro\"\r\n"
    "End Sub\r\n"
)


# ---------------------------------------------------------------------------
# 3. 各种样本
# ---------------------------------------------------------------------------
def fake_pe():
    """一个只有 DOS 头 + "PE\\0\\0" 签名的空壳：没有节、没有代码，系统也不会执行它。"""
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 64)  # e_lfanew -> 紧跟在后面的 PE 签名
    return bytes(dos) + b"PE\0\0" + b"\0" * 20


def _ooxml(parts):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in parts.items():
            z.writestr(name, data)
    return buf.getvalue()


_RELS = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
         '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
         '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/'
         'relationships/officeDocument" Target="word/document.xml"/></Relationships>')
_DOC = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        '<w:body><w:p><w:r><w:t>attachment-triage demo</w:t></w:r></w:p></w:body></w:document>')


def macro_docm():
    ct = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
          '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
          '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
          '<Default Extension="xml" ContentType="application/xml"/>'
          '<Default Extension="bin" ContentType="application/vnd.ms-office.vbaProject"/>'
          '<Override PartName="/word/document.xml" '
          'ContentType="application/vnd.ms-word.document.macroEnabled.main+xml"/></Types>')
    doc_rels = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                '<Relationship Id="rId1" Type="http://schemas.microsoft.com/office/2006/relationships/'
                'vbaProject" Target="vbaProject.bin"/></Relationships>')
    return _ooxml({
        "[Content_Types].xml": ct, "_rels/.rels": _RELS, "word/document.xml": _DOC,
        "word/_rels/document.xml.rels": doc_rels,
        "word/vbaProject.bin": build_vba_project({"Module1": DEMO_MACRO}),
    })


def template_docx():
    ct = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
          '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
          '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
          '<Default Extension="xml" ContentType="application/xml"/>'
          '<Override PartName="/word/document.xml" ContentType="application/'
          'vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>')
    settings_rels = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                     '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                     '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/'
                     'relationships/attachedTemplate" Target="http://example.invalid/template.dotm" '
                     'TargetMode="External"/></Relationships>')
    return _ooxml({
        "[Content_Types].xml": ct, "_rels/.rels": _RELS, "word/document.xml": _DOC,
        "word/settings.xml": '<w:settings xmlns:w="http://schemas.openxmlformats.org/'
                             'wordprocessingml/2006/main"/>',
        "word/_rels/settings.xml.rels": settings_rels,
    })


def js_pdf():
    # /JavaScript 故意写成 /Java#53cript（#53 = 'S'），演示名字混淆也能识别
    objs = [
        b"<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>",
        b"<< /Type /Action /S /Java#53cript /JS (app.alert\\('attachment-triage demo'\\);) >>",
    ]
    out = b"%PDF-1.7\n"
    offsets = []
    for i, body in enumerate(objs, 1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % i + body + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
    out += b"".join(b"%010d 00000 n \n" % o for o in offsets)
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objs) + 1, xref)
    return out


def rtf_doc():
    return b"{\\rtf1\\ansi\\deff0 {\\fonttbl {\\f0 Arial;}} \\f0 attachment-triage demo\\par}"


def js_zip():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("readme.txt", "Open the invoice script to view your invoice.\n")
        z.writestr("invoice.js", "// harmless demo file: no code here\n")
    return buf.getvalue()


def phish_eml(attachments):
    msg = EmailMessage()
    msg["From"] = "Accounts <billing@example.invalid>"
    msg["To"] = "you@example.invalid"
    msg["Subject"] = "Overdue invoice #4471 (demo sample)"
    msg.set_content("Please review the attached invoice today.\n\n(This is a harmless demo email.)")
    for name, data in attachments:
        msg.add_attachment(data, maintype="application", subtype="octet-stream", filename=name)
    return msg.as_bytes()


def all_samples():
    pe = fake_pe()
    samples = {
        "invoice.pdf.exe": pe,
        "photo.jpg": pe,
        "macro_demo.docm": macro_docm(),
        "template.docx": template_docx(),
        "scan.pdf": js_pdf(),
        "report.doc": rtf_doc(),
        "archive.zip": js_zip(),
    }
    # RTLO（U+202E）让 "photo_‮gpj.exe" 在很多界面里显示成 "photo_exe.jpg"
    samples["phish.eml"] = phish_eml([
        ("photo_‮gpj.exe", pe),
        ("invoice.docm", samples["macro_demo.docm"]),
        ("scan.pdf", samples["scan.pdf"]),
    ])
    return samples


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    out = argv[0] if argv else os.path.join(os.path.dirname(os.path.abspath(__file__)), "out")
    os.makedirs(out, exist_ok=True)
    for name, data in all_samples().items():
        with open(os.path.join(out, name), "wb") as f:
            f.write(data)
        print("写入 %-18s %6d 字节" % (name, len(data)))
    print("\n现在可以试试: python3 triage.py %s" % out)


if __name__ == "__main__":
    main()
