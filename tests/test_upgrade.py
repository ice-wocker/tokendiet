"""Regression tests for TokenDiet 1.2 security, filtering, and output handling."""
import json
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from http.server import HTTPServer
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import tokendiet
from tokendiet import IgnoreEngine, PromptFormatter, TokenDietEngine, git_changed_files


class TestUpgrade(unittest.TestCase):
    def test_gitignore_scoped_rules_and_hidden_project_files(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / ".gitignore").write_text("*.tmp\n!keep.tmp\n" + r"\!literal.tmp" + "\n", encoding="utf-8")
            (root / ".github").mkdir()
            (root / ".github" / "workflow.yml").write_text("name: test", encoding="utf-8")
            (root / "drop.tmp").write_text("x", encoding="utf-8")
            (root / "keep.tmp").write_text("x", encoding="utf-8")
            (root / "!literal.tmp").write_text("x", encoding="utf-8")
            (root / "src").mkdir()
            (root / "src" / ".gitignore").write_text("*.generated\n!keep.generated\n", encoding="utf-8")
            (root / "src" / "drop.generated").write_text("x", encoding="utf-8")
            (root / "src" / "keep.generated").write_text("x", encoding="utf-8")
            engine = IgnoreEngine(root)
            self.assertFalse(engine.is_ignored(root / ".github" / "workflow.yml"))
            self.assertTrue(engine.is_ignored(root / "drop.tmp"))
            self.assertFalse(engine.is_ignored(root / "keep.tmp"))
            self.assertTrue(engine.is_ignored(root / "!literal.tmp"))
            self.assertTrue(engine.is_ignored(root / "src" / "drop.generated"))
            self.assertFalse(engine.is_ignored(root / "src" / "keep.generated"))

    def test_scanned_original_is_scrubbed_before_web_serialization(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            # Build a deterministic dummy credential from fragments so scanners won't flag this test.
            value = "gh" + "p_" + "A" * 36
            source = root / "config.py"
            source.write_text('TOKEN = "' + value + '"\n', encoding="utf-8")
            summary = TokenDietEngine(root).scan()
            file = summary.files[0]
            self.assertNotIn(value, file.original_content)
            self.assertNotIn(value, file.compressed_content)
            self.assertEqual(file.secrets_redacted, 1)
            self.assertIn("[REDACTED_SECRET:GITHUB_TOKEN]", file.original_content)

    def test_xml_escapes_source_and_paths(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            weird = root / "a&b.py"
            weird.write_text('def f():\n    return "<tag>&"\n', encoding="utf-8")
            summary = TokenDietEngine(root, mode="full").scan()
            xml = PromptFormatter.to_xml(summary)
            parsed = ET.fromstring(xml)
            file_node = parsed.find("file")
            self.assertEqual(file_node.attrib["path"], "a&b.py")
            self.assertIn('"<tag>&"', file_node.text)

    def test_xml_sanitizes_forbidden_codepoints(self):
        invalid = "ok" + chr(1) + chr(0xFFFE) + chr(0xD800) + "\t"
        self.assertEqual(PromptFormatter._xml_safe(invalid), "ok\t")

    def test_markdown_fence_is_longer_than_embedded_fence(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "note.md").write_text("```\n````\n", encoding="utf-8")
            summary = TokenDietEngine(root, mode="full").scan()
            markdown = PromptFormatter.to_markdown(summary)
            self.assertIn("`````markdown", markdown)

    def test_json_format_stdout_is_valid_json(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "tokendiet.py"), str(ROOT / "samples"), "--format", "json"],
            check=True, capture_output=True, text=True,
        )
        data = json.loads(result.stdout)
        self.assertIn("files", data)
        self.assertIn("TokenDiet Context Compression Report", result.stderr)

    def test_python_ast_fallback_without_unparse(self):
        source = '''def calculate(value: int) -> int:\n    """Keep the contract."""\n    result = value + 2\n    return result\n'''
        with mock.patch.object(tokendiet.ast, "unparse", None, create=True):
            output = tokendiet.PythonSkeletonizer.skeletonize(source)
        self.assertIn("def calculate(value: int) -> int:", output)
        self.assertIn('"""Keep the contract."""', output)
        self.assertIn("...", output)
        self.assertNotIn("result = value + 2", output)
        one_line = "def short(x): return x + 1\n"
        with mock.patch.object(tokendiet.ast, "unparse", None, create=True):
            one_line_output = tokendiet.PythonSkeletonizer.skeletonize(one_line)
        self.assertEqual(one_line_output.strip(), "def short(x): ...")

    def test_security_audit_checks_env_files(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            value = "gh" + "p_" + "B" * 36
            (root / ".env").write_text("TOKEN=" + value, encoding="utf-8")
            engine = TokenDietEngine(root)
            # Assert the environment file is omitted from prompt scan but auditable.
            self.assertEqual(engine.scan().total_files, 0)
            from io import StringIO
            with mock.patch("sys.stdout", new_callable=StringIO) as output:
                status = tokendiet.run_secret_audit(root, engine)
            self.assertEqual(status, 1)
            self.assertIn("GITHUB_TOKEN", output.getvalue())
            self.assertNotIn(value, output.getvalue())

    def test_web_api_serves_scrubbed_source_and_rejects_invalid_mode(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            secret = "gh" + "p_" + "C" * 36
            (root / "settings.py").write_text('TOKEN = "' + secret + '"', encoding="utf-8")
            engine = TokenDietEngine(root)
            summary = engine.scan()
            tokendiet.WebServerHandler.summary = summary
            tokendiet.WebServerHandler.engine = engine
            server = HTTPServer(("127.0.0.1", 0), tokendiet.WebServerHandler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            base = "http://127.0.0.1:{}".format(server.server_port)
            try:
                with urllib.request.urlopen(base + "/api/scan") as response:
                    payload = json.loads(response.read().decode("utf-8"))
                encoded = json.dumps(payload)
                self.assertNotIn(secret, encoded)
                self.assertIn("[REDACTED_SECRET:GITHUB_TOKEN]", encoded)
                request = urllib.request.Request(
                    base + "/api/update_file",
                    data=json.dumps({"path": "settings.py", "mode": "invalid"}).encode("utf-8"),
                    headers={"Content-Type": "application/json"}, method="POST",
                )
                with self.assertRaises(urllib.error.HTTPError) as err:
                    urllib.request.urlopen(request)
                self.assertEqual(err.exception.code, 400)
                selection = urllib.request.Request(
                    base + "/api/set_included",
                    data=json.dumps({"path": "settings.py", "included": False}).encode("utf-8"),
                    headers={"Content-Type": "application/json"}, method="POST",
                )
                with urllib.request.urlopen(selection) as response:
                    selected_payload = json.loads(response.read().decode("utf-8"))
                self.assertFalse(selected_payload["files"][0]["included"])
                with urllib.request.urlopen(base + "/api/prompt?format=json") as response:
                    prompt_payload = json.loads(response.read().decode("utf-8"))
                prompt = json.loads(prompt_payload["prompt"])
                self.assertEqual(prompt["total_files"], 0)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

    def test_custom_reference_price_is_used(self):
        summary = TokenDietEngine(ROOT / "samples", price_per_million=12.0).scan()
        expected = summary.total_original_tokens * 12.0 / 1_000_000
        self.assertAlmostEqual(summary.cost_original_usd, expected)
        self.assertEqual(summary.price_per_million_usd, 12.0)
        data = json.loads(PromptFormatter.to_json(summary))
        self.assertEqual(data["reference_price_per_million_usd"], 12.0)

    def test_xss_safe_web_rendering(self):
        html = tokendiet.WEB_UI_HTML
        self.assertNotIn("innerHTML", html)
        self.assertIn("path.textContent = f.path", html)
        self.assertIn("/api/set_included", html)
        self.assertIn("tag.textContent = symbol", html)

    @staticmethod
    def _git(root, *args):
        subprocess.run(
            ["git", "-C", str(root), *args], check=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )

    def test_changed_and_untracked_files_are_full_and_marked(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self._git(root, "init", "-q")
            self._git(root, "config", "user.email", "test@example.invalid")
            self._git(root, "config", "user.name", "TokenDiet Test")
            (root / "changed.py").write_text("def value():\n    return 1\n", encoding="utf-8")
            (root / "stable.py").write_text("def stable():\n    return 2\n", encoding="utf-8")
            self._git(root, "add", ".")
            self._git(root, "commit", "-qm", "baseline")
            (root / "changed.py").write_text("def value():\n    return 999\n", encoding="utf-8")
            (root / "new file.py").write_text("def fresh():\n    return 3\n", encoding="utf-8")

            changed = git_changed_files(root)
            self.assertEqual(changed, {"changed.py", "new file.py"})
            summary = TokenDietEngine(root, changed_files=changed).scan()
            files = {item.path: item for item in summary.files}
            self.assertEqual(files["changed.py"].mode, "full")
            self.assertEqual(files["new file.py"].mode, "full")
            self.assertEqual(files["stable.py"].mode, "skeleton")
            self.assertTrue(files["changed.py"].is_changed)
            self.assertIn('changed="true"', PromptFormatter.to_xml(summary))
            self.assertIn("[CHANGED]", PromptFormatter.to_markdown(summary))
            data = json.loads(PromptFormatter.to_json(summary))
            changed_json = {item["path"]: item for item in data["files"]}
            self.assertTrue(changed_json["new file.py"]["changed"])

    def test_nested_git_root_scopes_changed_paths(self):
        with tempfile.TemporaryDirectory() as temp:
            repo = Path(temp)
            root = repo / "packages" / "app"
            root.mkdir(parents=True)
            outside = repo / "outside.py"
            inside = root / "inside.py"
            outside.write_text("x = 1\n", encoding="utf-8")
            inside.write_text("x = 1\n", encoding="utf-8")
            self._git(repo, "init", "-q")
            self._git(repo, "config", "user.email", "test@example.invalid")
            self._git(repo, "config", "user.name", "TokenDiet Test")
            self._git(repo, "add", ".")
            self._git(repo, "commit", "-qm", "baseline")
            inside.write_text("x = 2\n", encoding="utf-8")
            outside.write_text("x = 2\n", encoding="utf-8")
            (root / "untracked.py").write_text("y = 1\n", encoding="utf-8")
            self.assertEqual(git_changed_files(root), {"inside.py", "untracked.py"})

    def test_changed_mode_requires_a_valid_git_base(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self._git(root, "init", "-q")
            self._git(root, "config", "user.email", "test@example.invalid")
            self._git(root, "config", "user.name", "TokenDiet Test")
            (root / "file.py").write_text("x = 1\n", encoding="utf-8")
            self._git(root, "add", ".")
            self._git(root, "commit", "-qm", "baseline")
            with self.assertRaisesRegex(ValueError, "cannot read Git changes"):
                git_changed_files(root, "missing-branch")


if __name__ == "__main__":
    unittest.main()
