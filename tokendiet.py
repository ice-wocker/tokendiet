#!/usr/bin/env python3
"""
TokenDiet 🧊 — Extreme AI Codebase Context Compressor
Zero Dependencies · Single File · Pure Python 3.8+ Standard Library

Compresses repositories by 70%~85% using AST skeletonization, whitespace compacting,
symbol mapping, dynamic token budget fitting, and intelligent secret scrubbing.
Transforms codebases into the optimal prompt format for Claude Code, Cursor, Windsurf,
ChatGPT, and autonomous AI agents.

Author: ice-wocker (https://github.com/ice-wocker)
License: MIT
"""

from __future__ import annotations

import argparse
import ast
import fnmatch
import hashlib
import http.server
import json
import math
import os
import re
import socketserver
import subprocess
import sys
import threading
import urllib.parse
from xml.sax.saxutils import escape as xml_escape, quoteattr as xml_quoteattr
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

__version__ = "1.3.1"
__banner__ = r"""
 _____     _              ____  _      _   
|_   _|___| | _____ _ __ |  _ \(_) ___| |_ 
  | | / _ \ |/ / _ \ '_ \| | | | |/ _ \ __|
  | || (_) |   <  __/ | | | |_| | |  __/ |_ 
  |_| \___/|_|\_\___|_| |_|____/|_|\___|\__|
  🧊 Extreme AI Context Compressor · 0 Dependencies
"""

# ==============================================================================
# 1. Token Estimation & Reference Cost Model
# ==============================================================================

class TokenEstimator:
    """
    Dependency-free heuristic estimate for common BPE tokenizers.
    This is useful for relative comparisons, not a substitute for the model tokenizer.
    """
    CJK_RE = re.compile(r'[\u4e00-\u9fff\u3040-\u30ff\uac00-\ud7af]')
    WORD_SYM_RE = re.compile(r'[A-Za-z0-9_]+|[^\s\w]')
    SPACES_RE = re.compile(r' {2,}')

    PRICING = {
        "claude-3-5-sonnet": {"name": "Claude 3.5 Sonnet", "cost_per_m": 3.00},
        "gpt-4o": {"name": "GPT-4o", "cost_per_m": 2.50},
        "claude-3-opus": {"name": "Claude 3 Opus", "cost_per_m": 15.00},
        "deepseek-v3": {"name": "DeepSeek-V3", "cost_per_m": 0.14},
    }

    @classmethod
    def estimate(cls, text: str) -> int:
        if not text:
            return 0
        cjk_chars = len(cls.CJK_RE.findall(text))
        non_cjk = cls.CJK_RE.sub('', text)

        words_and_symbols = cls.WORD_SYM_RE.findall(non_cjk)
        space_tokens = sum(max(1, len(m.group(0)) // 4) for m in cls.SPACES_RE.finditer(non_cjk))
        newlines = non_cjk.count('\n')

        subword_penalty = 0
        for token in words_and_symbols:
            tlen = len(token)
            if tlen > 7 and token.isalnum():
                subword_penalty += (tlen - 6) // 4

        total = len(words_and_symbols) + space_tokens + (newlines // 2) + subword_penalty + int(cjk_chars * 1.25)
        return max(1, total)

    @classmethod
    def calculate_cost(
        cls, tokens: int, model: str = "claude-3-5-sonnet",
        cost_per_million: Optional[float] = None,
    ) -> float:
        rate = cost_per_million
        if rate is None:
            rate = cls.PRICING.get(model, cls.PRICING["claude-3-5-sonnet"])["cost_per_m"]
        if not math.isfinite(rate) or rate < 0:
            raise ValueError("cost_per_million must be a finite, non-negative number")
        return (tokens / 1_000_000.0) * rate


# ==============================================================================
# 2. Secret & Credential Sanitizer
# ==============================================================================

@dataclass
class SecretFinding:
    secret_type: str
    line_number: int
    matched_preview: str


class SecretScrubber:
    """
    Detects and sanitizes sensitive credentials before sending prompts to cloud AI.
    Includes rules for GitHub, OpenAI, Anthropic, AWS, Google, Stripe, HuggingFace, Slack, JWT, and Private Keys.
    """
    RULES = [
        ("GITHUB_TOKEN", re.compile(r'\b(gh[pousr]_[A-Za-z0-9_]{36,}|github_pat_[A-Za-z0-9_]{82})\b')),
        ("ANTHROPIC_KEY", re.compile(r'\b(sk-ant-[A-Za-z0-9_\-]{40,})\b')),
        ("OPENAI_KEY", re.compile(r'\b(sk-(?!ant-)(?:proj-)?[A-Za-z0-9_\-]{40,})\b')),
        ("HUGGINGFACE_TOKEN", re.compile(r'\b(hf_[A-Za-z0-9]{34,})\b')),
        ("STRIPE_KEY", re.compile(r'\b([rs]k_(?:live|test)_[A-Za-z0-9]{24,})\b')),
        ("AWS_KEY_ID", re.compile(r'\b(AKIA[0-9A-Z]{16})\b')),
        ("GOOGLE_AI_KEY", re.compile(r'\b(AIza[0-9A-Za-z\-_]{35})\b')),
        ("SLACK_TOKEN", re.compile(r'\b(xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32})\b')),
        ("PRIVATE_KEY", re.compile(r'-----BEGIN (RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY-----[\s\S]*?-----END \1 PRIVATE KEY-----')),
        ("JWT_TOKEN", re.compile(r'\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b')),
        ("DATABASE_URI", re.compile(r'\b((?:postgres|mysql|mongodb|mongodb\+srv|redis)://[^:\s]+:[^@\s]+@[^\s]+)\b')),
        ("GENERIC_SECRET", re.compile(
            r'''(?i)\b(api_key|apikey|secret_key|client_secret|auth_token|access_token|password|passwd|db_password)\s*[:=]\s*["']([A-Za-z0-9_\-.~!@#$%^&*+/=]{8,})["']'''
        )),
    ]

    @classmethod
    def audit(cls, content: str) -> List[SecretFinding]:
        """Audits content and returns findings with line numbers without replacing."""
        findings: List[SecretFinding] = []
        lines = content.splitlines()

        for idx, line in enumerate(lines, 1):
            for name, pattern in cls.RULES:
                if name == "PRIVATE_KEY":
                    continue
                for match in pattern.finditer(line):
                    val = match.group(0)
                    preview = val[:4] + "..." + val[-3:] if len(val) > 8 else "***"
                    findings.append(SecretFinding(secret_type=name, line_number=idx, matched_preview=preview))

        # Check multiline private keys
        for match in cls.RULES[8][1].finditer(content):
            start_pos = match.start()
            line_no = content[:start_pos].count('\n') + 1
            findings.append(SecretFinding(secret_type="PRIVATE_KEY", line_number=line_no, matched_preview="-----BEGIN...KEY-----"))

        return findings

    @classmethod
    def scrub(cls, content: str) -> Tuple[str, int]:
        total_redacted = 0
        cleaned = content

        # 1. Private keys
        def pk_sub(m):
            nonlocal total_redacted
            total_redacted += 1
            return "[REDACTED_SECRET:PRIVATE_KEY]"
        cleaned = cls.RULES[8][1].sub(pk_sub, cleaned)

        # 2. Generic secret assignments (key="val")
        def generic_sub(m):
            nonlocal total_redacted
            total_redacted += 1
            key_name = m.group(1)
            assign = m.group(0)
            sep = "=" if "=" in assign else ":"
            return f'{key_name} {sep} "[REDACTED_SECRET:{key_name.upper()}]"'
        cleaned = cls.RULES[11][1].sub(generic_sub, cleaned)

        # 3. Known tokens and patterns
        target_rules = cls.RULES[:8] + cls.RULES[9:11]
        for name, pattern in target_rules:
            def sub_fn(m, n=name):
                nonlocal total_redacted
                total_redacted += 1
                return f"[REDACTED_SECRET:{n}]"
            cleaned = pattern.sub(sub_fn, cleaned)

        return cleaned, total_redacted


# ==============================================================================
# 3. Language AST, Skeletonizer & Symbol Indexer Engine
# ==============================================================================

class SymbolExtractor:
    """
    Extracts top-level symbols (classes, functions, interfaces, structs)
    to build an instant architectural symbol map for AI agents.
    """
    @staticmethod
    def extract_python(source: str) -> List[str]:
        symbols = []
        try:
            tree = ast.parse(source)
            for node in tree.body:
                if isinstance(node, ast.ClassDef):
                    methods = [n.name for n in node.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
                    if methods:
                        symbols.append(f"class {node.name} [{', '.join(methods[:4])}{'...' if len(methods) > 4 else ''}]")
                    else:
                        symbols.append(f"class {node.name}")
                elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    symbols.append(f"def {node.name}()")
        except Exception:
            pass
        return symbols

    @staticmethod
    def extract_braces(source: str) -> List[str]:
        symbols = []
        for line in source.splitlines():
            line_str = line.strip()
            # TypeScript/JavaScript interfaces and types
            if re.match(r'^(?:export\s+)?(?:interface|type)\s+([A-Za-z0-9_]+)', line_str):
                m = re.match(r'^(?:export\s+)?(?:interface|type)\s+([A-Za-z0-9_]+)', line_str)
                if m:
                    symbols.append(f"type {m.group(1)}")
            # Classes
            elif re.match(r'^(?:export\s+)?(?:public\s+)?class\s+([A-Za-z0-9_]+)', line_str):
                m = re.match(r'^(?:export\s+)?(?:public\s+)?class\s+([A-Za-z0-9_]+)', line_str)
                if m:
                    symbols.append(f"class {m.group(1)}")
            # Functions
            elif re.match(r'^(?:export\s+)?(?:async\s+)?function\s+([A-Za-z0-9_]+)', line_str):
                m = re.match(r'^(?:export\s+)?(?:async\s+)?function\s+([A-Za-z0-9_]+)', line_str)
                if m:
                    symbols.append(f"fn {m.group(1)}()")
            # Go functions and structs
            elif re.match(r'^func\s+(?:\([^)]+\)\s+)?([A-Za-z0-9_]+)', line_str):
                m = re.match(r'^func\s+(?:\([^)]+\)\s+)?([A-Za-z0-9_]+)', line_str)
                if m:
                    symbols.append(f"func {m.group(1)}()")
            elif re.match(r'^type\s+([A-Za-z0-9_]+)\s+struct', line_str):
                m = re.match(r'^type\s+([A-Za-z0-9_]+)\s+struct', line_str)
                if m:
                    symbols.append(f"struct {m.group(1)}")
        return symbols[:8]  # Limit to top 8 symbols per file for compactness


class PythonSkeletonizer:
    """
    Pure Python AST skeletonizer.
    Preserves: imports, module docstrings, type aliases, classes, signatures, decorators, return types.
    Omites: function/method implementation bodies, replacing them with '...'
    """
    @staticmethod
    def _source_fallback(source: str, tree: ast.Module, stub_level: str) -> str:
        """Stub function bodies without ast.unparse (available only from Python 3.9)."""
        lines = source.splitlines()
        edits = []

        class FunctionCollector(ast.NodeVisitor):
            def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
                self._collect(node)

            def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
                self._collect(node)

            def _collect(self, node: Any) -> None:
                if node.body:
                    value = getattr(node.body[0], "value", None)
                    is_docstring = isinstance(node.body[0], ast.Expr) and isinstance(value, ast.Constant) and isinstance(value.value, str)
                    doc = node.body[0] if is_docstring else None
                    body_start = node.body[0].lineno - 1
                    body_end = getattr(node, "end_lineno", node.body[-1].lineno) - 1
                    if body_start == node.lineno - 1:
                        # One-line suites (``def f(): return x``) share their header line.
                        raw_line = lines[body_start].encode("utf-8")
                        prefix = raw_line[:node.body[0].col_offset].decode("utf-8", errors="ignore")
                        replacement = [prefix + "..."]
                    elif doc is not None and stub_level != "minimal":
                        keep_end = getattr(doc, "end_lineno", doc.lineno) - 1
                        replacement = lines[body_start:keep_end + 1]
                        indent = lines[body_start][:len(lines[body_start]) - len(lines[body_start].lstrip())]
                        replacement.append(indent + "...")
                    else:
                        indent = lines[body_start][:len(lines[body_start]) - len(lines[body_start].lstrip())]
                        replacement = [indent + "..."]
                    edits.append((body_start, body_end, replacement))
                self.generic_visit(node)

        FunctionCollector().visit(tree)
        for first, last, replacement in sorted(edits, key=lambda item: item[0], reverse=True):
            lines[first:last + 1] = replacement
        return "\n".join(lines)

    @staticmethod
    def skeletonize(source: str, stub_level: str = "standard") -> str:
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return GenericCompactor.compact(source, lang="python")

        if not callable(getattr(ast, "unparse", None)):
            return PythonSkeletonizer._source_fallback(source, tree, stub_level)

        class Transformer(ast.NodeTransformer):
            def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.AST:
                return self._stub_func(node)

            def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> ast.AST:
                return self._stub_func(node)

            def _stub_func(self, node: Any) -> Any:
                docstring = ast.get_docstring(node)
                new_body: List[ast.stmt] = []

                if docstring and stub_level != "minimal":
                    first_line = docstring.strip().split("\n")[0]
                    short_doc = f"{first_line} ..." if len(docstring.strip().split("\n")) > 1 else first_line
                    new_body.append(ast.Expr(value=ast.Constant(value=short_doc)))

                new_body.append(ast.Expr(value=ast.Constant(value=Ellipsis)))
                node.body = new_body
                return node

        transformer = Transformer()
        transformed = transformer.visit(tree)
        ast.fix_missing_locations(transformed)

        try:
            unparse = getattr(ast, "unparse", None)
            if unparse is None:
                return PythonSkeletonizer._source_fallback(source, tree, stub_level)
            unparsed = unparse(transformed)
            lines = []
            for line in unparsed.splitlines():
                if line.strip() == "...":
                    indent = line[:len(line) - 3]
                    lines.append(f"{indent}...  # [implementation omitted]")
                else:
                    lines.append(line)
            return "\n".join(lines)
        except Exception:
            return GenericCompactor.compact(source, lang="python")


class BraceSkeletonizer:
    """
    Universal brace-aware skeletonizer for C-family languages:
    TypeScript, JavaScript, Java, Go, Rust, C++, C, C#, Kotlin, Swift, Dart.
    Preserves: imports, exports, interfaces, types, structs, class headers, signatures.
    Replaces: function & method bodies with '{ /* [implementation omitted] */ }'.
    """
    TOKEN_PATTERN = re.compile(
        r'(?P<COMMENT_SL>//[^\n]*)'
        r'|(?P<COMMENT_ML>/\*.*?\*/)'
        r'|(?P<STRING_DQ>"(?:\\.|[^"\\])*")'
        r'|(?P<STRING_SQ>\'(?:\\.|[^\'\\])*\')'
        r'|(?P<STRING_BT>`(?:\\.|[^`\\])*`)'
        r'|(?P<LBRACE>\{)'
        r'|(?P<RBRACE>\})'
        r'|(?P<SEMI>;)'
        r'|(?P<OTHER>[^{};\'"`/]+|/)'
    , re.DOTALL)

    NON_FUNC_DECL_RE = re.compile(
        r'\b(class|interface|struct|enum|namespace|module|type|union)\b\s+[A-Za-z0-9_]+'
    )
    CONTROL_KW_RE = re.compile(r'\b(if|for|while|switch|catch)\s*\(')

    @classmethod
    def skeletonize(cls, code: str, lang: str = "generic") -> str:
        tokens: List[Tuple[str, str]] = []
        for m in cls.TOKEN_PATTERN.finditer(code):
            tokens.append((m.lastgroup or "OTHER", m.group(0)))

        result: List[str] = []
        num_tokens = len(tokens)
        i = 0
        header_buf: List[str] = []

        def is_function_header(header: str) -> bool:
            s = header.strip()
            s = re.sub(r'//.*', '', s)
            s = re.sub(r'/\*.*?\*/', '', s, flags=re.DOTALL).strip()
            if not s:
                return False

            if cls.NON_FUNC_DECL_RE.search(s):
                last_decl = re.split(r'\b(class|interface|struct|enum|namespace|module|type)\b', s)[-1]
                if not any(marker in last_decl for marker in ['(', '=>', 'func ']):
                    return False

            if re.search(r'\b(function|func|fn)\b', s):
                return True
            if '=>' in s:
                return True
            if re.search(r'\)\s*([A-Za-z0-9_<>\[\]\?:\s]*)\s*$', s):
                if cls.CONTROL_KW_RE.search(s):
                    return False
                return True
            return False

        while i < num_tokens:
            kind, val = tokens[i]

            if kind == 'LBRACE':
                header_text = "".join(header_buf)
                if is_function_header(header_text):
                    depth = 1
                    j = i + 1
                    skipped: List[str] = []
                    while j < num_tokens and depth > 0:
                        tk, tv = tokens[j]
                        if tk == 'LBRACE':
                            depth += 1
                        elif tk == 'RBRACE':
                            depth -= 1
                        if depth > 0:
                            skipped.append(tv)
                        j += 1

                    lines_omitted = "".join(skipped).count('\n')
                    if lines_omitted > 2:
                        result.append(f"{{ /* [omitted {lines_omitted} lines] */ }}")
                    else:
                        result.append("{ /* ... */ }")
                    i = j
                    header_buf = []
                    continue
                else:
                    result.append(val)
                    header_buf = []
            elif kind in ('RBRACE', 'SEMI'):
                result.append(val)
                header_buf = []
            else:
                result.append(val)
                header_buf.append(val)

            i += 1

        return "".join(result)


class GenericCompactor:
    """
    Compresses non-code or generic text files:
    Collapses whitespace, strips excessive comments, and summarizes giant JSON/YAML.
    """
    @staticmethod
    def compact(content: str, lang: str = "") -> str:
        # Smart JSON summarization if file is large (>2KB)
        if lang == "json" and len(content) > 2048:
            try:
                data = json.loads(content)
                summary = GenericCompactor.summarize_json_structure(data)
                return json.dumps(summary, indent=2, ensure_ascii=False)
            except Exception:
                pass

        lines = content.splitlines()
        output = []
        blank_run = 0

        for line in lines:
            stripped = line.strip()
            if not stripped:
                blank_run += 1
                if blank_run <= 1:
                    output.append("")
                continue

            blank_run = 0

            if lang in ("python", "shell", "yaml") and stripped.startswith("#") and not stripped.startswith("#!"):
                if any(c in stripped for c in ("===", "---", "###")):
                    output.append(stripped)
                continue

            output.append(line.rstrip())

        return "\n".join(output)

    @staticmethod
    def summarize_json_structure(obj: Any, depth: int = 0) -> Any:
        if depth > 2:
            return "..."
        if isinstance(obj, dict):
            return {k: GenericCompactor.summarize_json_structure(v, depth + 1) for k, v in list(obj.items())[:12]}
        elif isinstance(obj, list):
            sample = [GenericCompactor.summarize_json_structure(obj[0], depth + 1)] if obj else []
            return f"[Array of {len(obj)} items, sample: {sample}]"
        elif isinstance(obj, (int, float, bool)):
            return obj
        elif isinstance(obj, str):
            return obj[:40] + "..." if len(obj) > 40 else obj
        return str(type(obj).__name__)


# ==============================================================================
# 4. File Discovery & Smart Ignore Engine
# ==============================================================================

class IgnoreEngine:
    """Small, dependency-free ignore engine with scoped .gitignore rules."""
    DEFAULT_IGNORED_DIRS = {
        ".git", ".svn", ".hg", "node_modules", "bower_components",
        "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".tox",
        "venv", ".venv", "virtualenv", "dist", "build", "out", "target",
        ".next", ".nuxt", ".output", ".parcel-cache", ".turbo", ".svelte-kit",
        "coverage", "vendor", "Pods", ".gradle", "bin", "obj"
    }
    DEFAULT_IGNORED_EXTS = {
        ".exe", ".dll", ".so", ".dylib", ".bin", ".apk", ".aab", ".ipa", ".class",
        ".pyc", ".pyo", ".pyd", ".o", ".a", ".obj", ".zip", ".tar", ".gz", ".bz2",
        ".xz", ".7z", ".rar", ".jar", ".war", ".png", ".jpg", ".jpeg", ".gif", ".ico",
        ".svg", ".webp", ".mp3", ".mp4", ".wav", ".ogg", ".pdf", ".docx", ".xlsx",
        ".pptx", ".ttf", ".woff", ".woff2", ".lock", ".sqlite", ".sqlite3", ".db", ".log"
    }
    DEFAULT_IGNORED_FILES = {
        "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "Cargo.lock", "composer.lock",
        "poetry.lock", "Pipfile.lock", "Gemfile.lock", ".DS_Store", "Thumbs.db",
        ".env", ".env.local", ".env.production", ".env.development"
    }

    def __init__(self, root: Path, custom_ignores: Optional[List[str]] = None):
        self.root = root.resolve()
        self.custom_ignores = custom_ignores or []
        self.gitignore_rules: List[Tuple[Path, str, bool]] = []
        self._load_all_gitignores()

    def _load_all_gitignores(self) -> None:
        # Avoid descending into known generated/dependency trees while finding nested rules.
        for base, dirs, files in os.walk(self.root):
            dirs[:] = sorted(d for d in dirs if d not in self.DEFAULT_IGNORED_DIRS)
            if ".gitignore" not in files:
                continue
            ignore_path = Path(base) / ".gitignore"
            try:
                with open(ignore_path, "r", encoding="utf-8", errors="replace") as stream:
                    for raw in stream:
                        line = raw.rstrip("\r\n")
                        if not line or line.lstrip().startswith("#"):
                            continue
                        # Backslash escapes a leading # or ! in gitignore syntax.
                        escaped_marker = line.startswith(r"\!") or line.startswith(r"\#")
                        if escaped_marker:
                            line = line[1:]
                        negated = line.startswith("!") and not escaped_marker
                        pattern = line[1:] if negated else line
                        if pattern:
                            self.gitignore_rules.append((Path(base).resolve(), pattern, negated))
            except (OSError, UnicodeError):
                continue

    @staticmethod
    def _glob_match(value: str, pattern: str) -> bool:
        # fnmatch supports the common gitignore glob forms (including **).
        return fnmatch.fnmatchcase(value, pattern)

    def _rule_matches(self, path: Path, base: Path, pattern: str) -> bool:
        try:
            rel = path.relative_to(base).as_posix()
        except ValueError:
            return False
        directory_only = pattern.endswith("/")
        pattern = pattern.rstrip("/")
        anchored = pattern.startswith("/")
        pattern = pattern.lstrip("/")
        has_slash = "/" in pattern
        candidates = [rel]
        # Directory rules apply to that directory and all descendants.
        if directory_only or path.is_dir():
            parts = rel.split("/")
            candidates.extend("/".join(parts[:i]) for i in range(1, len(parts)))
        elif "/" in rel:
            parts = rel.split("/")
            candidates.extend("/".join(parts[:i]) for i in range(1, len(parts)))
        for candidate in candidates:
            if has_slash or anchored:
                if self._glob_match(candidate, pattern):
                    return True
            elif self._glob_match(candidate.rsplit("/", 1)[-1], pattern):
                return True
        return False

    def is_ignored(self, path: Path) -> bool:
        try:
            resolved = path.resolve()
            rel = resolved.relative_to(self.root)
        except (ValueError, OSError):
            return True
        parts = rel.parts
        if any(part in self.DEFAULT_IGNORED_DIRS for part in parts[:-1]):
            return True
        if (path.name in self.DEFAULT_IGNORED_FILES or path.name.startswith(".env.")
                or path.suffix.lower() in self.DEFAULT_IGNORED_EXTS):
            return True
        # Never follow symlinks out of the scanned tree.
        if path.is_symlink():
            return True
        rel_posix = rel.as_posix()
        if any(self._glob_match(rel_posix, pat) or self._glob_match(path.name, pat)
               for pat in self.custom_ignores):
            return True

        ignored = False
        # Root rules precede nested rules, matching git's last-matching-rule behavior.
        for base, pattern, negated in sorted(self.gitignore_rules, key=lambda rule: len(rule[0].parts)):
            if self._rule_matches(resolved, base, pattern):
                ignored = not negated
        return ignored


# ==============================================================================
# 5. Git-aware change selection
# ==============================================================================

def git_changed_files(root: Path, base: str = "HEAD") -> Set[str]:
    """Return changed tracked and untracked file paths under root.

    Uses NUL-delimited Git output and never invokes a shell, so unusual filenames
    are handled safely. Paths are returned relative to the requested root.
    """
    root = root.resolve()

    def run_git_at(directory: Path, *args: str) -> bytes:
        result = subprocess.run(
            ["git", "-C", str(directory), *args],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
        if result.returncode:
            detail = result.stderr.decode("utf-8", "replace").strip()
            raise ValueError(detail or "git command failed")
        return result.stdout

    try:
        repo_root = Path(run_git_at(root, "rev-parse", "--show-toplevel").decode().strip()).resolve()
        prefix = root.relative_to(repo_root).as_posix()
        # Run path-list commands from the repository root so all paths have a
        # single, predictable origin even when root points at a nested package.
        changed = run_git_at(repo_root, "diff", "--name-only", "-z", base, "--")
        untracked = run_git_at(repo_root, "ls-files", "--others", "--exclude-standard", "-z")
    except (ValueError, OSError) as exc:
        raise ValueError("cannot read Git changes for {}: {}".format(root, exc)) from exc

    root_prefix = prefix + "/" if prefix != "." else ""
    paths: Set[str] = set()
    for raw in changed.split(b"\0") + untracked.split(b"\0"):
        if not raw:
            continue
        repo_rel = raw.decode("utf-8", "surrogateescape").replace("\\", "/")
        if root_prefix:
            if not repo_rel.startswith(root_prefix):
                continue
            rel = repo_rel[len(root_prefix):]
        else:
            rel = repo_rel
        if (root / rel).is_file():
            paths.add(rel)
    return paths


# ==============================================================================
# 6. Core Repository Processor & Dynamic Budget Optimizer
# ==============================================================================

@dataclass
class ProcessedFile:
    path: str
    language: str
    mode: str
    original_lines: int
    compressed_lines: int
    original_tokens: int
    compressed_tokens: int
    secrets_redacted: int
    original_content: str
    compressed_content: str
    symbols: List[str] = field(default_factory=list)
    is_focused: bool = False
    is_changed: bool = False
    included: bool = True

    @property
    def reduction_pct(self) -> float:
        if self.original_tokens <= 0:
            return 0.0
        return max(0.0, ((self.original_tokens - self.compressed_tokens) / self.original_tokens) * 100.0)


@dataclass
class RepoSummary:
    root_path: str
    total_files: int
    total_original_lines: int
    total_compressed_lines: int
    total_original_tokens: int
    total_compressed_tokens: int
    total_secrets_redacted: int
    cost_original_usd: float
    cost_compressed_usd: float
    files: List[ProcessedFile] = field(default_factory=list)
    price_per_million_usd: float = 3.0

    @property
    def total_reduction_pct(self) -> float:
        if self.total_original_tokens <= 0:
            return 0.0
        return max(0.0, ((self.total_original_tokens - self.total_compressed_tokens) / self.total_original_tokens) * 100.0)

    @property
    def cost_saved_usd(self) -> float:
        return max(0.0, self.cost_original_usd - self.cost_compressed_usd)


class TokenDietEngine:
    """
    Main orchestration engine for TokenDiet.
    Supports multi-tier compression and dynamic token budget optimization.
    """
    EXT_MAP = {
        ".py": "python", ".pyi": "python",
        ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
        ".ts": "typescript", ".tsx": "typescript",
        ".go": "go",
        ".java": "java", ".kt": "kotlin", ".kts": "kotlin",
        ".rs": "rust",
        ".c": "c", ".h": "c", ".cpp": "cpp", ".hpp": "cpp", ".cc": "cpp",
        ".cs": "csharp",
        ".php": "php", ".swift": "swift", ".dart": "dart",
        ".html": "html", ".css": "css", ".scss": "css",
        ".json": "json", ".yaml": "yaml", ".yml": "yaml", ".toml": "toml",
        ".md": "markdown", ".sh": "shell", ".bash": "shell", ".sql": "sql"
    }

    BRACE_LANGS = {
        "javascript", "typescript", "java", "kotlin", "go",
        "rust", "c", "cpp", "csharp", "php", "swift", "dart"
    }

    def __init__(
        self,
        root: Path,
        mode: str = "skeleton",
        focus_patterns: Optional[List[str]] = None,
        custom_ignores: Optional[List[str]] = None,
        max_file_size_kb: int = 512,
        scrub_secrets: bool = True,
        token_budget: Optional[int] = None,
        price_per_million: float = 3.0,
        changed_files: Optional[Set[str]] = None,
    ):
        self.root = root.resolve()
        self.default_mode = mode
        self.focus_patterns = focus_patterns or []
        self.changed_files = set(changed_files or set())
        self.ignore_engine = IgnoreEngine(self.root, custom_ignores)
        self.max_file_size_bytes = max_file_size_kb * 1024
        self.scrub_secrets = scrub_secrets
        self.token_budget = token_budget
        if not math.isfinite(price_per_million) or price_per_million < 0:
            raise ValueError("price_per_million must be a finite, non-negative number")
        self.price_per_million = price_per_million

    def detect_language(self, path: Path) -> str:
        ext = path.suffix.lower()
        if ext in self.EXT_MAP:
            return self.EXT_MAP[ext]
        name = path.name.lower()
        if name in ("dockerfile", "containerfile"):
            return "dockerfile"
        if name in ("makefile", "gnumakefile"):
            return "makefile"
        return "text"

    def is_focused(self, rel_path: str) -> bool:
        if not self.focus_patterns:
            return False
        clean_rel = rel_path.replace("\\", "/")
        for pat in self.focus_patterns:
            pat_clean = pat.replace("\\", "/")
            if fnmatch.fnmatch(clean_rel, pat_clean) or fnmatch.fnmatch(clean_rel, f"*{pat_clean}*"):
                return True
        return False

    def process_file_content(self, content: str, lang: str, mode: str) -> Tuple[str, int]:
        secrets_redacted = 0
        working = content

        if self.scrub_secrets:
            working, secrets_redacted = SecretScrubber.scrub(working)

        if mode == "full":
            return working, secrets_redacted

        if mode == "skeleton":
            if lang == "python":
                transformed = PythonSkeletonizer.skeletonize(working)
            elif lang in self.BRACE_LANGS:
                transformed = BraceSkeletonizer.skeletonize(working, lang=lang)
            else:
                transformed = GenericCompactor.compact(working, lang=lang)
            return transformed, secrets_redacted

        if mode == "compact":
            transformed = GenericCompactor.compact(working, lang=lang)
            return transformed, secrets_redacted

        if mode == "stub":
            # Extreme one-line stub mode when fitting strict token budgets
            symbols = SymbolExtractor.extract_python(working) if lang == "python" else SymbolExtractor.extract_braces(working)
            stub_text = f"// [STUB: {len(working.splitlines())} lines omitted to fit token budget]\n"
            stub_text += "\n".join(f"// symbol: {s}" for s in symbols)
            return stub_text, secrets_redacted

        return working, secrets_redacted

    def extract_symbols(self, content: str, lang: str) -> List[str]:
        if lang == "python":
            return SymbolExtractor.extract_python(content)
        elif lang in self.BRACE_LANGS:
            return SymbolExtractor.extract_braces(content)
        return []

    def process_single_file(self, file_path: Path, mode_override: Optional[str] = None) -> Optional[ProcessedFile]:
        try:
            rel_path = str(file_path.relative_to(self.root)).replace("\\", "/")
        except ValueError:
            rel_path = file_path.name

        try:
            size = file_path.stat().st_size
            if size > self.max_file_size_bytes or size == 0:
                return None

            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception:
            return None

        is_changed = rel_path in self.changed_files
        is_focus = self.is_focused(rel_path)
        file_mode = mode_override or ("full" if is_focus or is_changed else self.default_mode)

        lang = self.detect_language(file_path)
        # Keep only scrubbed source in the summary; this object is also served to the local UI.
        safe_content, redacted = SecretScrubber.scrub(content) if self.scrub_secrets else (content, 0)
        compressed, _ = self.process_file_content(safe_content, lang, file_mode)
        symbols = self.extract_symbols(safe_content, lang)

        orig_tokens = TokenEstimator.estimate(content)
        comp_tokens = TokenEstimator.estimate(compressed)

        return ProcessedFile(
            path=rel_path,
            language=lang,
            mode=file_mode,
            original_lines=len(content.splitlines()),
            compressed_lines=len(compressed.splitlines()),
            original_tokens=orig_tokens,
            compressed_tokens=comp_tokens,
            secrets_redacted=redacted,
            original_content=safe_content,
            compressed_content=compressed,
            symbols=symbols,
            is_focused=is_focus,
            is_changed=is_changed,
        )

    def scan(self) -> RepoSummary:
        processed_files: List[ProcessedFile] = []

        for root, dirs, files in os.walk(self.root):
            dirs[:] = [
                d for d in dirs
                if not self.ignore_engine.is_ignored(Path(root) / d)
            ]

            for file in sorted(files):
                full_path = Path(root) / file
                if self.ignore_engine.is_ignored(full_path):
                    continue

                pf = self.process_single_file(full_path)
                if pf:
                    processed_files.append(pf)

        processed_files.sort(key=lambda x: x.path)

        # Dynamic Token Budget Optimization
        if self.token_budget and self.token_budget > 0:
            processed_files = self._optimize_for_budget(processed_files, self.token_budget)

        orig_tokens = sum(f.original_tokens for f in processed_files)
        comp_tokens = sum(f.compressed_tokens for f in processed_files)
        orig_lines = sum(f.original_lines for f in processed_files)
        comp_lines = sum(f.compressed_lines for f in processed_files)
        redacted = sum(f.secrets_redacted for f in processed_files)

        return RepoSummary(
            root_path=str(self.root),
            total_files=len(processed_files),
            total_original_lines=orig_lines,
            total_compressed_lines=comp_lines,
            total_original_tokens=orig_tokens,
            total_compressed_tokens=comp_tokens,
            total_secrets_redacted=redacted,
            cost_original_usd=TokenEstimator.calculate_cost(orig_tokens, cost_per_million=self.price_per_million),
            cost_compressed_usd=TokenEstimator.calculate_cost(comp_tokens, cost_per_million=self.price_per_million),
            files=processed_files,
            price_per_million_usd=self.price_per_million,
        )

    def _optimize_for_budget(self, files: List[ProcessedFile], budget: int) -> List[ProcessedFile]:
        """Progressively compacts non-focus files until context fits under token budget."""
        total_tokens = sum(f.compressed_tokens for f in files)
        if total_tokens <= budget:
            return files

        # Tier 1: Convert non-focused code files from skeleton to compact/minimal stub
        non_focused = [f for f in files if not f.is_focused and not f.is_changed]
        # Sort by largest token footprint descending
        non_focused.sort(key=lambda f: f.compressed_tokens, reverse=True)

        for f in non_focused:
            if total_tokens <= budget:
                break
            # Downgrade to stub
            new_comp, red = self.process_file_content(f.original_content, f.language, "stub")
            new_tokens = TokenEstimator.estimate(new_comp)
            saved = f.compressed_tokens - new_tokens
            if saved > 0:
                f.mode = "stub"
                f.compressed_content = new_comp
                f.compressed_lines = len(new_comp.splitlines())
                f.compressed_tokens = new_tokens
                total_tokens -= saved

        return files


# ==============================================================================
# 6. Output Formatters (XML / Markdown / JSON / RepoMap)
# ==============================================================================

class PromptFormatter:
    """
    Renders processed files into LLM-optimized prompt formats with Symbol Maps.
    """
    @staticmethod
    def build_ascii_tree(paths: List[str]) -> str:
        tree: Dict[str, Any] = {}
        for path in sorted(paths):
            parts = path.split("/")
            curr = tree
            for part in parts:
                curr = curr.setdefault(part, {})

        lines = []
        def _render(node: Dict[str, Any], prefix: str = ""):
            keys = sorted(node.keys())
            for i, k in enumerate(keys):
                is_last = (i == len(keys) - 1)
                connector = "└── " if is_last else "├── "
                lines.append(f"{prefix}{connector}{k}")
                next_prefix = f"{prefix}    " if is_last else f"{prefix}│   "
                _render(node[k], next_prefix)

        _render(tree)
        return "\n".join(lines)

    @classmethod
    def build_repomap(cls, files: List[ProcessedFile]) -> str:
        """Builds a ctags-like architectural symbol map for AI agents."""
        lines = []
        for f in files:
            if f.symbols:
                lines.append(f"• {f.path}:")
                for sym in f.symbols:
                    lines.append(f"    - {sym}")
        return "\n".join(lines) if lines else "(No exported symbols detected)"

    @staticmethod
    def _selected_summary(summary: RepoSummary) -> RepoSummary:
        """Build output totals from only the files currently included in the prompt."""
        files = [f for f in summary.files if f.included]
        original_tokens = sum(f.original_tokens for f in files)
        compressed_tokens = sum(f.compressed_tokens for f in files)
        return RepoSummary(
            root_path=summary.root_path,
            total_files=len(files),
            total_original_lines=sum(f.original_lines for f in files),
            total_compressed_lines=sum(f.compressed_lines for f in files),
            total_original_tokens=original_tokens,
            total_compressed_tokens=compressed_tokens,
            total_secrets_redacted=sum(f.secrets_redacted for f in files),
            cost_original_usd=TokenEstimator.calculate_cost(
                original_tokens, cost_per_million=summary.price_per_million_usd
            ),
            cost_compressed_usd=TokenEstimator.calculate_cost(
                compressed_tokens, cost_per_million=summary.price_per_million_usd
            ),
            files=files,
            price_per_million_usd=summary.price_per_million_usd,
        )

    @staticmethod
    def _xml_safe(value: str) -> str:
        """Remove characters forbidden by XML 1.0 while preserving legal whitespace."""
        def is_xml_char(ch: str) -> bool:
            code = ord(ch)
            return (code in (9, 10, 13) or 0x20 <= code <= 0xD7FF
                    or 0xE000 <= code <= 0xFFFD or 0x10000 <= code <= 0x10FFFF)
        return "".join(ch for ch in value if is_xml_char(ch))

    @classmethod
    def to_xml(cls, summary: RepoSummary, include_repomap: bool = True) -> str:
        summary = cls._selected_summary(summary)
        tree_str = cls.build_ascii_tree([f.path for f in summary.files])
        out = ["<codebase>"]
        out.append(
            "  <metadata total_files={} original_tokens={} compressed_tokens={} savings={}>".format(
                xml_quoteattr(str(summary.total_files)),
                xml_quoteattr(str(summary.total_original_tokens)),
                xml_quoteattr(str(summary.total_compressed_tokens)),
                xml_quoteattr("{:.1f}%".format(summary.total_reduction_pct)),
            )
        )
        out.append("    <directory_tree>")
        out.append(xml_escape(cls._xml_safe(tree_str)))
        out.append("    </directory_tree>")
        if include_repomap:
            out.append("    <symbol_map>")
            out.append(xml_escape(cls._xml_safe(cls.build_repomap(summary.files))))
            out.append("    </symbol_map>")
        out.append("  </metadata>")
        for f in summary.files:
            attrs = [
                "path={}".format(xml_quoteattr(cls._xml_safe(f.path))),
                "language={}".format(xml_quoteattr(cls._xml_safe(f.language))),
                "mode={}".format(xml_quoteattr(f.mode)),
                "tokens={}".format(xml_quoteattr(str(f.compressed_tokens))),
            ]
            if f.is_focused:
                attrs.append('focus="true"')
            if f.is_changed:
                attrs.append('changed="true"')
            # XML 1.0 disallows most C0 controls; remove them without touching tabs/newlines.
            content = cls._xml_safe(f.compressed_content)
            out.append("  <file {}>".format(" ".join(attrs)))
            out.append(xml_escape(content))
            out.append("  </file>")
        out.append("</codebase>")
        return "\n".join(out)

    @classmethod
    def to_markdown(cls, summary: RepoSummary, include_repomap: bool = True) -> str:
        summary = cls._selected_summary(summary)
        tree_str = cls.build_ascii_tree([f.path for f in summary.files])
        out = []
        out.append(f"# Codebase Context: `{Path(summary.root_path).name}`")
        out.append(f"> 🧊 Compressed with **TokenDiet**: **{summary.total_original_tokens:,}** tokens → **{summary.total_compressed_tokens:,}** tokens (**{summary.total_reduction_pct:.1f}% reduction**).")
        out.append(f"> Illustrative cost delta: **${summary.cost_saved_usd:.3f}** at **${summary.price_per_million_usd:.2f}/1M input tokens**. Update this rate for your provider.\n")
        out.append("## Repository Tree\n```text")
        out.append(tree_str)
        out.append("```\n")

        if include_repomap:
            out.append("## Architectural Symbol Map\n```text")
            out.append(cls.build_repomap(summary.files))
            out.append("```\n")

        out.append("## Files\n")
        for f in summary.files:
            tag = " [CHANGED]" if f.is_changed else (" [FOCUS]" if f.is_focused else f" [{f.mode}]")
            out.append(f"### `{f.path}`{tag}")
            fence = "`" * max(3, max((len(m.group(0)) for m in re.finditer(r"`+", f.compressed_content)), default=0) + 1)
            out.append(f"{fence}{f.language}")
            out.append(f.compressed_content)
            out.append(f"{fence}\n")

        return "\n".join(out)

    @classmethod
    def to_json(cls, summary: RepoSummary) -> str:
        summary = cls._selected_summary(summary)
        data = {
            "root": summary.root_path,
            "total_files": summary.total_files,
            "original_tokens": summary.total_original_tokens,
            "compressed_tokens": summary.total_compressed_tokens,
            "savings_percent": round(summary.total_reduction_pct, 2),
            "estimated_cost_saved_usd": round(summary.cost_saved_usd, 4),
            "reference_price_per_million_usd": summary.price_per_million_usd,
            "symbols": {f.path: f.symbols for f in summary.files if f.symbols},
            "files": [
                {
                    "path": f.path,
                    "language": f.language,
                    "mode": f.mode,
                    "original_tokens": f.original_tokens,
                    "compressed_tokens": f.compressed_tokens,
                    "reduction_percent": round(f.reduction_pct, 1),
                    "symbols": f.symbols,
                    "changed": f.is_changed,
                    "content": f.compressed_content,
                }
                for f in summary.files
            ]
        }
        return json.dumps(data, indent=2, ensure_ascii=False)


# ==============================================================================
# 7. System Clipboard Helper (Cross-Platform Fallback)
# ==============================================================================

def copy_to_clipboard(text: str) -> bool:
    if sys.platform == "darwin":
        try:
            p = subprocess.Popen(["pbcopy"], stdin=subprocess.PIPE)
            p.communicate(text.encode("utf-8"))
            return p.returncode == 0
        except Exception:
            pass

    if sys.platform.startswith("linux"):
        for cmd in [["wl-copy"], ["xclip", "-selection", "clipboard"], ["xsel", "-b"]]:
            try:
                p = subprocess.Popen(cmd, stdin=subprocess.PIPE)
                p.communicate(text.encode("utf-8"))
                if p.returncode == 0:
                    return True
            except Exception:
                continue

    if sys.platform in ("win32", "cygwin") or "microsoft" in sys.platform.lower():
        try:
            p = subprocess.Popen(["clip.exe"], stdin=subprocess.PIPE)
            p.communicate(text.encode("utf-8"))
            return p.returncode == 0
        except Exception:
            pass

    return False


# ==============================================================================
# 8. Zero-Dependency Interactive Web Visualizer
# ==============================================================================

WEB_UI_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>TokenDiet 🧊 — Codebase Context Compressor</title>
<style>
:root {
  --bg-dark: #0d1117;
  --bg-card: #161b22;
  --bg-card-hover: #1f242c;
  --border: #30363d;
  --text-main: #c9d1d9;
  --text-muted: #8b949e;
  --accent: #58a6ff;
  --green: #3fb950;
  --orange: #d29922;
  --red: #f85149;
  --font-mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  background: var(--bg-dark);
  color: var(--text-main);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  height: 100vh;
  display: flex;
  flex-direction: column;
  overflow: hidden;
}
header {
  background: var(--bg-card);
  border-bottom: 1px solid var(--border);
  padding: 12px 20px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex-shrink: 0;
}
.brand {
  display: flex;
  align-items: center;
  gap: 10px;
  font-weight: 700;
  font-size: 1.15rem;
  color: #fff;
}
.brand span { color: var(--accent); }
.stats-bar {
  display: flex;
  gap: 16px;
  align-items: center;
}
.stat-pill {
  background: rgba(88, 166, 255, 0.1);
  border: 1px solid rgba(88, 166, 255, 0.25);
  border-radius: 6px;
  padding: 4px 12px;
  font-size: 0.85rem;
  display: flex;
  gap: 6px;
  align-items: baseline;
}
.stat-pill strong { color: var(--green); font-size: 1rem; }
.actions {
  display: flex;
  gap: 10px;
  align-items: center;
}
button {
  background: #21262d;
  color: #c9d1d9;
  border: 1px solid var(--border);
  padding: 6px 14px;
  border-radius: 6px;
  font-size: 0.85rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
  display: inline-flex;
  align-items: center;
  gap: 6px;
}
button:hover { background: #30363d; border-color: #8b949e; }
button.btn-primary {
  background: #238636;
  border-color: #2ea043;
  color: #fff;
  font-weight: 600;
}
button.btn-primary:hover { background: #2ea043; }
.main-container {
  display: flex;
  flex: 1;
  overflow: hidden;
}
.sidebar {
  width: 380px;
  background: var(--bg-card);
  border-right: 1px solid var(--border);
  display: flex;
  flex-direction: column;
  flex-shrink: 0;
}
.sidebar-header {
  padding: 10px 14px;
  border-bottom: 1px solid var(--border);
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.search-input {
  width: 100%;
  background: #0d1117;
  border: 1px solid var(--border);
  color: var(--text-main);
  padding: 6px 10px;
  border-radius: 6px;
  font-size: 0.85rem;
}
.search-input:focus { outline: none; border-color: var(--accent); }
.file-list {
  flex: 1;
  overflow-y: auto;
  list-style: none;
}
.file-item {
  padding: 8px 14px;
  border-bottom: 1px solid rgba(48, 54, 61, 0.5);
  display: flex;
  align-items: center;
  justify-content: space-between;
  cursor: pointer;
  font-size: 0.85rem;
  transition: background 0.15s;
}
.file-item:hover { background: var(--bg-card-hover); }
.file-item.active { background: #1f2937; border-left: 3px solid var(--accent); }
.file-info {
  display: flex;
  flex-direction: column;
  overflow: hidden;
  gap: 2px;
  max-width: 240px;
}
.file-path {
  font-family: var(--font-mono);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  color: #f0f6fc;
}
.file-meta {
  font-size: 0.75rem;
  color: var(--text-muted);
}
.file-mode-select {
  background: #0d1117;
  color: var(--text-main);
  border: 1px solid var(--border);
  border-radius: 4px;
  font-size: 0.75rem;
  padding: 2px 4px;
}
.include-toggle { accent-color: var(--accent); flex: 0 0 auto; }
.content-area {
  flex: 1;
  display: flex;
  flex-direction: column;
  overflow: hidden;
  background: var(--bg-dark);
}
.content-header {
  background: #161b22;
  border-bottom: 1px solid var(--border);
  padding: 8px 16px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  font-size: 0.85rem;
}
.diff-container {
  flex: 1;
  display: flex;
  overflow: hidden;
}
.pane {
  flex: 1;
  display: flex;
  flex-direction: column;
  overflow: hidden;
}
.pane:first-child { border-right: 1px solid var(--border); }
.pane-title {
  background: #12161c;
  padding: 6px 12px;
  font-size: 0.75rem;
  color: var(--text-muted);
  border-bottom: 1px solid var(--border);
  display: flex;
  justify-content: space-between;
}
pre {
  flex: 1;
  padding: 12px;
  overflow: auto;
  font-family: var(--font-mono);
  font-size: 0.82rem;
  line-height: 1.45;
  color: #d1d5db;
  white-space: pre;
}
.symbol-tag {
  display: inline-block;
  background: rgba(88, 166, 255, 0.15);
  color: var(--accent);
  padding: 1px 5px;
  border-radius: 3px;
  font-size: 0.7rem;
  margin-right: 4px;
}
.toast {
  position: fixed;
  bottom: 24px;
  right: 24px;
  background: #238636;
  color: #fff;
  padding: 10px 20px;
  border-radius: 6px;
  font-size: 0.9rem;
  box-shadow: 0 4px 12px rgba(0,0,0,0.5);
  display: none;
  animation: fadeIn 0.3s;
}
@keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
</style>
</head>
<body>
<header>
  <div class="brand">
    <span>🧊 TokenDiet</span>
    <span style="font-size: 0.75rem; color: var(--text-muted); font-weight: normal;">v1.3.1</span>
  </div>
  <div class="stats-bar">
    <div class="stat-pill">
      <span>Files:</span> <span id="stat-files">0</span>
    </div>
    <div class="stat-pill">
      <span>Original:</span> <span id="stat-orig">0</span>
    </div>
    <div class="stat-pill">
      <span>Compressed:</span> <span id="stat-comp">0</span>
    </div>
    <div class="stat-pill">
      <span>Saved:</span> <strong id="stat-saved">0%</strong>
    </div>
    <div class="stat-pill">
      <span>Cost Saved:</span> <span id="stat-cost" style="color: var(--green);">$0.00</span>
    </div>
  </div>
  <div class="actions">
    <select id="format-select" class="file-mode-select" style="padding: 6px 10px; font-size: 0.85rem;">
      <option value="xml">Anthropic XML</option>
      <option value="markdown">Markdown</option>
      <option value="json">JSON</option>
    </select>
    <button class="btn-primary" onclick="copyPrompt()">📋 Copy Prompt</button>
  </div>
</header>
<div class="main-container">
  <div class="sidebar">
    <div class="sidebar-header">
      <input type="text" id="search" class="search-input" placeholder="Filter files (press /)..." oninput="filterFiles()">
      <div style="display: flex; gap: 6px;">
        <button style="flex:1; font-size:0.75rem;" onclick="setAllMode('skeleton')">All Skeleton</button>
        <button style="flex:1; font-size:0.75rem;" onclick="setAllMode('full')">All Full</button>
        <button style="flex:1; font-size:0.75rem;" onclick="setAllMode('compact')">All Compact</button>
      </div>
      <div style="display: flex; gap: 6px; margin-top: 6px;">
        <button style="flex:1; font-size:0.75rem;" onclick="setAllIncluded(true)">Include all files</button>
        <button style="flex:1; font-size:0.75rem;" onclick="setAllIncluded(false)">Clear selection</button>
      </div>
    </div>
    <ul class="file-list" id="file-list"></ul>
  </div>
  <div class="content-area">
    <div class="content-header">
      <span id="active-filename" style="font-family: var(--font-mono); font-weight: 600;">Select a file</span>
      <span id="active-file-stats" style="color: var(--text-muted);"></span>
    </div>
    <div id="symbol-bar" style="padding: 6px 16px; background: #13171e; border-bottom: 1px solid var(--border); font-size: 0.75rem; display: none;">
      <span style="color: var(--text-muted); margin-right: 8px;">Exported Symbols:</span>
      <span id="symbol-list"></span>
    </div>
    <div class="diff-container">
      <div class="pane">
        <div class="pane-title">
          <span>SOURCE PREVIEW · SECRETS REDACTED</span>
          <span id="orig-tokens"></span>
        </div>
        <pre id="orig-code">Select a file from the left sidebar to preview comparison.</pre>
      </div>
      <div class="pane">
        <div class="pane-title">
          <span>COMPRESSED (LLM CONTEXT)</span>
          <span id="comp-tokens"></span>
        </div>
        <pre id="comp-code"></pre>
      </div>
    </div>
  </div>
</div>
<div class="toast" id="toast">Prompt copied to clipboard!</div>

<script>
let repoData = null;
let activeIndex = 0;
let fileModes = {};

async function loadData() {
  const res = await fetch('/api/scan');
  repoData = await res.json();
  repoData.files.forEach((f, idx) => {
    fileModes[f.path] = f.mode;
  });
  updateStats();
  renderFileList();
  if (repoData.files.length > 0) {
    selectFile(0);
  }
}

function updateStats() {
  let origTot = 0, compTot = 0, selectedCount = 0;
  repoData.files.forEach(f => {
    if (f.included === false) return;
    selectedCount += 1;
    origTot += f.original_tokens;
    compTot += f.compressed_tokens;
  });
  const savedPct = origTot > 0 ? (((origTot - compTot) / origTot) * 100).toFixed(1) : 0;
  const referenceRate = Number(repoData.price_per_million_usd ?? 3.0);
  const costSaved = ((origTot - compTot) / 1000000 * referenceRate).toFixed(3);

  document.getElementById('stat-files').innerText = selectedCount + ' / ' + repoData.files.length;
  document.getElementById('stat-orig').innerText = origTot.toLocaleString() + ' tok';
  document.getElementById('stat-comp').innerText = compTot.toLocaleString() + ' tok';
  document.getElementById('stat-saved').innerText = savedPct + '%';
  document.getElementById('stat-cost').innerText = '$' + costSaved;
}

function renderFileList() {
  const list = document.getElementById('file-list');
  const query = document.getElementById('search').value.toLowerCase();
  list.replaceChildren();
  repoData.files.forEach((f, idx) => {
    if (query && !f.path.toLowerCase().includes(query)) return;
    const li = document.createElement('li');
    li.className = 'file-item' + (idx === activeIndex ? ' active' : '');
    li.addEventListener('click', (event) => {
      if (event.target.tagName !== 'SELECT' && event.target.type !== 'checkbox') selectFile(idx);
    });
    const include = document.createElement('input');
    include.type = 'checkbox';
    include.className = 'include-toggle';
    include.checked = f.included !== false;
    include.setAttribute('aria-label', 'Include ' + f.path + ' in prompt');
    include.addEventListener('change', () => changeIncluded(f.path, include.checked));
    const info = document.createElement('div');
    info.className = 'file-info';
    const path = document.createElement('span');
    path.className = 'file-path';
    path.textContent = f.path;
    const meta = document.createElement('span');
    meta.className = 'file-meta';
    const reduction = f.reduction_pct ? f.reduction_pct.toFixed(0) : 0;
    meta.textContent = `${f.compressed_tokens.toLocaleString()} tok (${reduction}% saved)`;
    info.append(path, meta);
    const select = document.createElement('select');
    select.className = 'file-mode-select';
    [['skeleton', 'Skeleton'], ['compact', 'Compact'], ['full', 'Full']].forEach(([value, label]) => {
      const option = document.createElement('option');
      option.value = value;
      option.textContent = label;
      option.selected = f.mode === value;
      select.appendChild(option);
    });
    select.addEventListener('change', () => changeMode(f.path, select.value, idx));
    li.append(include, info, select);
    list.appendChild(li);
  });
}

function filterFiles() {
  renderFileList();
}

function selectFile(idx) {
  activeIndex = idx;
  const f = repoData.files[idx];
  document.getElementById('active-filename').innerText = f.path;
  document.getElementById('active-file-stats').innerText = `${f.original_tokens.toLocaleString()} → ${f.compressed_tokens.toLocaleString()} tokens (${f.reduction_pct.toFixed(1)}% reduction)`;
  document.getElementById('orig-tokens').innerText = `${f.original_tokens.toLocaleString()} tokens`;
  document.getElementById('comp-tokens').innerText = `${f.compressed_tokens.toLocaleString()} tokens`;
  document.getElementById('orig-code').innerText = f.original_content;
  document.getElementById('comp-code').innerText = f.compressed_content;

  const symBar = document.getElementById('symbol-bar');
  const symList = document.getElementById('symbol-list');
  if (f.symbols && f.symbols.length > 0) {
    symBar.style.display = 'block';
    symList.replaceChildren();
    f.symbols.forEach(symbol => {
      const tag = document.createElement('span');
      tag.className = 'symbol-tag';
      tag.textContent = symbol;
      symList.appendChild(tag);
    });
  } else {
    symBar.style.display = 'none';
  }

  document.querySelectorAll('.file-item').forEach((el, i) => {
    el.classList.toggle('active', i === idx);
  });
}

async function changeMode(path, newMode, idx) {
  fileModes[path] = newMode;
  const res = await fetch('/api/update_file', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({path: path, mode: newMode})
  });
  const updated = await res.json();
  repoData.files[idx] = updated;
  updateStats();
  if (idx === activeIndex) selectFile(idx);
}

async function setAllMode(mode) {
  for (let f of repoData.files) {
    fileModes[f.path] = mode;
  }
  const res = await fetch('/api/set_all_modes', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({mode: mode})
  });
  repoData = await res.json();
  updateStats();
  renderFileList();
  selectFile(activeIndex);
}

async function changeIncluded(path, included) {
  const res = await fetch('/api/set_included', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({path: path, included: included})
  });
  if (!res.ok) { showToast('Could not update file selection'); return; }
  repoData = await res.json();
  updateStats();
  renderFileList();
}

async function setAllIncluded(included) {
  const res = await fetch('/api/set_all_included', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({included: included})
  });
  if (!res.ok) { showToast('Could not update file selection'); return; }
  repoData = await res.json();
  updateStats();
  renderFileList();
}

async function copyPrompt() {
  const format = document.getElementById('format-select').value;
  const res = await fetch('/api/prompt?format=' + format);
  const data = await res.json();
  navigator.clipboard.writeText(data.prompt).then(() => {
    showToast('Prompt copied to clipboard (' + data.tokens.toLocaleString() + ' tokens)');
  });
}

function showToast(msg) {
  const t = document.getElementById('toast');
  t.innerText = msg;
  t.style.display = 'block';
  setTimeout(() => { t.style.display = 'none'; }, 2500);
}

window.addEventListener('keydown', (e) => {
  if (e.key === '/' && document.activeElement.id !== 'search') {
    e.preventDefault();
    document.getElementById('search').focus();
  }
  if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') {
    e.preventDefault();
    copyPrompt();
  }
});

loadData();
</script>
</body>
</html>
"""

class WebServerHandler(http.server.SimpleHTTPRequestHandler):
    summary: RepoSummary
    engine: TokenDietEngine

    def send_scan_data(self) -> None:
        data = {
            "root": self.summary.root_path,
            "total_files": self.summary.total_files,
            "price_per_million_usd": self.summary.price_per_million_usd,
            "files": [asdict(f) for f in self.summary.files],
        }
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.end_headers()
        self.wfile.write(json.dumps(data, ensure_ascii=False).encode("utf-8"))

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(WEB_UI_HTML.encode("utf-8"))
            return

        if parsed.path == "/api/scan":
            self.send_scan_data()
            return

        if parsed.path == "/api/prompt":
            qs = urllib.parse.parse_qs(parsed.query)
            fmt = qs.get("format", ["xml"])[0]
            if fmt not in ("xml", "markdown", "json"):
                self.send_error(400, "Invalid format")
                return
            if fmt == "markdown":
                prompt = PromptFormatter.to_markdown(self.summary)
            elif fmt == "json":
                prompt = PromptFormatter.to_json(self.summary)
            else:
                prompt = PromptFormatter.to_xml(self.summary)

            tokens = TokenEstimator.estimate(prompt)
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            self.wfile.write(json.dumps({"prompt": prompt, "tokens": tokens}).encode("utf-8"))
            return

        self.send_error(404, "Not Found")

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        try:
            content_len = int(self.headers.get("Content-Length", 0))
            if content_len < 0 or content_len > 65536:
                self.send_error(413, "Request too large")
                return
            body = self.rfile.read(content_len).decode("utf-8")
            payload = json.loads(body) if body else {}
            if not isinstance(payload, dict):
                self.send_error(400, "JSON object required")
                return
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
            self.send_error(400, "Invalid JSON request")
            return

        if parsed.path == "/api/update_file":
            path = payload.get("path")
            new_mode = payload.get("mode", "skeleton")
            if new_mode not in ("skeleton", "compact", "full"):
                self.send_error(400, "Invalid mode")
                return
            for i, f in enumerate(self.summary.files):
                if f.path == path:
                    compressed, _ = self.engine.process_file_content(f.original_content, f.language, new_mode)
                    redacted = f.secrets_redacted
                    f.mode = new_mode
                    f.compressed_content = compressed
                    f.compressed_lines = len(compressed.splitlines())
                    f.compressed_tokens = TokenEstimator.estimate(compressed)
                    f.secrets_redacted = redacted
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps(asdict(f)).encode("utf-8"))
                    return
            self.send_error(404, "File not found")
            return

        if parsed.path == "/api/set_all_modes":
            mode = payload.get("mode", "skeleton")
            if mode not in ("skeleton", "compact", "full"):
                self.send_error(400, "Invalid mode")
                return
            for f in self.summary.files:
                compressed, _ = self.engine.process_file_content(f.original_content, f.language, mode)
                redacted = f.secrets_redacted
                f.mode = mode
                f.compressed_content = compressed
                f.compressed_lines = len(compressed.splitlines())
                f.compressed_tokens = TokenEstimator.estimate(compressed)
                f.secrets_redacted = redacted

            self.send_scan_data()
            return

        if parsed.path == "/api/set_included":
            path = payload.get("path")
            included = payload.get("included")
            if not isinstance(path, str) or not isinstance(included, bool):
                self.send_error(400, "Path and boolean included value required")
                return
            for f in self.summary.files:
                if f.path == path:
                    f.included = included
                    self.send_scan_data()
                    return
            self.send_error(404, "File not found")
            return

        if parsed.path == "/api/set_all_included":
            included = payload.get("included")
            if not isinstance(included, bool):
                self.send_error(400, "Boolean included value required")
                return
            for f in self.summary.files:
                f.included = included
            self.send_scan_data()
            return

        self.send_error(404, "Endpoint not found")

    def log_message(self, format, *args):
        pass


def start_web_server(engine: TokenDietEngine, summary: RepoSummary, port: int = 8080, host: str = "127.0.0.1") -> None:
    handler = WebServerHandler
    handler.summary = summary
    handler.engine = engine

    class ThreadingHTTPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
        allow_reuse_address = True
        daemon_threads = True

    server = ThreadingHTTPServer((host, port), handler)
    print(f"\n🚀 TokenDiet Web Visualizer live at http://{host}:{port}")
    if host not in ("127.0.0.1", "localhost", "::1"):
        print("⚠ Warning: non-loopback binding exposes repository context to the network.")
    print("Press Ctrl+C to stop.\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping server...")
        server.shutdown()
    finally:
        server.server_close()


# ==============================================================================
# 9. CLI Interface & Terminal Reporting
# ==============================================================================

def print_summary_table(summary: RepoSummary, file=sys.stdout) -> None:
    print("\n" + "=" * 76, file=file)
    print(f" 🧊 TokenDiet Context Compression Report", file=file)
    print("=" * 76, file=file)
    print(f" Root Directory:      {summary.root_path}", file=file)
    print(f" Total Files:         {summary.total_files}", file=file)
    print(f" Secrets Redacted:    {summary.total_secrets_redacted}", file=file)
    print(f" Reference Input:     ${summary.price_per_million_usd:.2f} per 1M tokens", file=file)
    print("-" * 76, file=file)
    print(f" {'Metric':<24} | {'Before':<15} | {'After (Compressed)':<20} | {'Saved'}", file=file)
    print("-" * 76, file=file)
    print(f" {'Lines of Code':<24} | {summary.total_original_lines:<15,d} | {summary.total_compressed_lines:<20,d} | {100.0 - (summary.total_compressed_lines / max(1, summary.total_original_lines) * 100):.1f}%", file=file)
    print(f" {'Estimated Tokens':<24} | {summary.total_original_tokens:<15,d} | {summary.total_compressed_tokens:<20,d} | {summary.total_reduction_pct:.1f}%", file=file)
    print(f" {'Illustrative Cost':<24} | ${summary.cost_original_usd:<14.3f} | ${summary.cost_compressed_usd:<19.3f} | -${summary.cost_saved_usd:.3f}", file=file)
    print("=" * 76 + "\n", file=file)

def run_secret_audit(root_path: Path, engine: TokenDietEngine) -> int:
    """Executes a standalone security scan for credentials across the repository."""
    print(f"\n🔍 Auditing repository for leaked credentials: {root_path}")
    print("-" * 65)

    findings_count = 0
    for root, dirs, files in os.walk(root_path):
        dirs[:] = [d for d in dirs if not engine.ignore_engine.is_ignored(Path(root) / d)]
        for file in sorted(files):
            p = Path(root) / file
            ignored = engine.ignore_engine.is_ignored(p)
            # Environment files are excluded from prompt bundles by default, but the
            # dedicated security audit must inspect them when present.
            if ignored and not (file == ".env" or file.startswith(".env.")):
                continue
            try:
                if p.stat().st_size > 1024 * 1024:
                    continue
                rel = str(p.relative_to(root_path)).replace("\\", "/")
                with open(p, "rb") as f:
                    raw = f.read()
                if b"\x00" in raw:
                    continue
                content = raw.decode("utf-8", errors="replace")
                findings = SecretScrubber.audit(content)
                for f in findings:
                    findings_count += 1
                    print(f"  [!] {f.secret_type:<18} in {rel}:{f.line_number} (preview: {f.matched_preview})")
            except Exception:
                pass

    print("-" * 65)
    if findings_count > 0:
        print(f"⚠ Warning: Found {findings_count} potential secrets! Ensure TokenDiet scrubbing is enabled.\n")
        return 1
    else:
        print("✓ Clean! No obvious API keys or credentials detected.\n")
        return 0


def main() -> None:
    parser = argparse.ArgumentParser(
        description="TokenDiet 🧊 — Extreme AI Codebase Context Compressor (0 Dependencies, Single File)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 tokendiet.py .                         # Compress current directory (Anthropic XML to stdout)
  python3 tokendiet.py . -c                      # Compress and copy prompt directly to clipboard
  python3 tokendiet.py . --focus src/api.py      # Keep src/api.py full, skeletonize rest of repo
  python3 tokendiet.py . --changed               # Keep Git changes and untracked files full
  python3 tokendiet.py . --changed origin/main   # Compare against a branch or commit
  python3 tokendiet.py . --budget 8000           # Compress toward an estimated 8,000-token budget
  python3 tokendiet.py . --repomap               # Output architectural symbol map only
  python3 tokendiet.py . --audit-secrets         # Audit codebase for leaked credentials
  python3 tokendiet.py . --serve 8080            # Launch interactive browser visualizer & inspector
"""
    )
    parser.add_argument("path", nargs="?", default=".", help="Root directory of the codebase (default: current dir)")
    parser.add_argument("-m", "--mode", choices=["skeleton", "compact", "full"], default="skeleton",
                        help="Compression mode: skeleton (AST stubs, default), compact (strip blanks/comments), full")
    parser.add_argument("--focus", type=str, default="",
                        help="Comma-separated globs of files to keep in FULL mode (e.g. 'src/core/*,api.py')")
    parser.add_argument("--changed", nargs="?", const="HEAD", default=None, metavar="BASE",
                        help="Keep Git-changed and untracked files FULL (default comparison: HEAD)")
    parser.add_argument("-b", "--budget", type=int, default=None,
                        help="Target token budget: compresses non-focused files progressively (estimate; may exceed)")
    parser.add_argument("--price-per-million", type=float, default=3.0,
                        help="Reference input price in USD per 1M tokens for cost estimates (default: 3.00)")
    parser.add_argument("-f", "--format", choices=["xml", "markdown", "json"], default="xml",
                        help="Output format: xml (Anthropic optimal, default), markdown, json")
    parser.add_argument("-o", "--output", type=str, default="", help="Save output prompt to file path")
    parser.add_argument("-c", "--clip", action="store_true", help="Copy generated prompt to system clipboard")
    parser.add_argument("--serve", nargs="?", const=8080, type=int, help="Start local Web UI visualizer on port (default: 8080)")
    parser.add_argument("--host", default="127.0.0.1", help="Visualizer bind address (default: 127.0.0.1; non-local hosts expose code)")
    parser.add_argument("--stats", action="store_true", help="Print summary table and token savings only")
    parser.add_argument("--tree-only", action="store_true", help="Print repository directory tree only")
    parser.add_argument("--repomap", action="store_true", help="Print architectural symbol map only")
    parser.add_argument("--audit-secrets", action="store_true", help="Audit repository for leaked secrets and exit")
    parser.add_argument("--no-scrub", action="store_true", help="Disable secret and credential scrubbing")
    parser.add_argument("--max-size", type=int, default=512, help="Max file size in KB to process (default: 512)")
    parser.add_argument("--ignore", type=str, action="append", default=[], help="Additional glob pattern to ignore")
    parser.add_argument("-v", "--version", action="version", version=f"TokenDiet {__version__}")

    args = parser.parse_args()

    root_path = Path(args.path).resolve()
    if not root_path.exists() or not root_path.is_dir():
        print(f"Error: Path '{root_path}' is not an existing directory.", file=sys.stderr)
        sys.exit(1)
    if args.max_size <= 0:
        parser.error("--max-size must be greater than zero")
    if args.budget is not None and args.budget <= 0:
        parser.error("--budget must be greater than zero")
    if args.serve is not None and not 1 <= args.serve <= 65535:
        parser.error("--serve port must be between 1 and 65535")
    if not math.isfinite(args.price_per_million) or args.price_per_million < 0:
        parser.error("--price-per-million must be a finite, non-negative number")

    focus_list = [f.strip() for f in args.focus.split(",") if f.strip()]
    changed_paths: Set[str] = set()
    if args.changed is not None:
        try:
            changed_paths = git_changed_files(root_path, args.changed)
        except ValueError as exc:
            parser.error(str(exc))

    engine = TokenDietEngine(
        root=root_path,
        mode=args.mode,
        focus_patterns=focus_list,
        custom_ignores=args.ignore,
        max_file_size_kb=args.max_size,
        scrub_secrets=not args.no_scrub,
        token_budget=args.budget,
        price_per_million=args.price_per_million,
        changed_files=changed_paths,
    )

    if args.no_scrub:
        print("Warning: secret scrubbing is disabled; generated context may contain credentials.", file=sys.stderr)

    if args.audit_secrets:
        code = run_secret_audit(root_path, engine)
        sys.exit(code)

    summary = engine.scan()
    if args.budget is not None and summary.total_compressed_tokens > args.budget:
        print(
            "Warning: estimated file content remains above the requested budget "
            "({:,} > {:,} tokens); wrappers/metadata add more.".format(
                summary.total_compressed_tokens, args.budget
            ),
            file=sys.stderr,
        )

    if args.serve is not None:
        start_web_server(engine, summary, port=args.serve, host=args.host)
        return

    if args.tree_only:
        tree = PromptFormatter.build_ascii_tree([f.path for f in summary.files])
        print(tree)
        return

    if args.repomap:
        repomap = PromptFormatter.build_repomap(summary.files)
        print(repomap)
        return

    if args.stats:
        print_summary_table(summary)
        return

    # Render formatted prompt
    if args.format == "markdown":
        output_text = PromptFormatter.to_markdown(summary)
    elif args.format == "json":
        output_text = PromptFormatter.to_json(summary)
    else:
        output_text = PromptFormatter.to_xml(summary)

    # Keep machine-readable JSON clean on stdout; diagnostics stay on stderr.
    print_summary_table(summary, file=sys.stderr if args.format == "json" and not args.output else sys.stdout)

    if args.output:
        out_path = Path(args.output).resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(output_text)
        print(f"✓ Saved prompt to: {out_path} ({summary.total_compressed_tokens:,} tokens)")

    if args.clip:
        if copy_to_clipboard(output_text):
            print("✓ Successfully copied prompt to clipboard!")
        else:
            print("⚠ Note: Clipboard command not found on system. Outputting to stdout instead:")
            print(output_text)
    elif not args.output:
        print(output_text)


if __name__ == "__main__":
    main()
