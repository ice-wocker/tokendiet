"""
Unit tests for TokenDiet
Run with: python3 -m unittest discover -s tests -v
"""

import os
import sys
import unittest
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tokendiet import (
    TokenEstimator,
    SecretScrubber,
    PythonSkeletonizer,
    BraceSkeletonizer,
    GenericCompactor,
    SymbolExtractor,
    IgnoreEngine,
    TokenDietEngine,
    PromptFormatter,
)


class TestTokenEstimator(unittest.TestCase):
    def test_empty_string(self):
        self.assertEqual(TokenEstimator.estimate(""), 0)

    def test_basic_estimation(self):
        text = "def hello_world(): return True"
        tokens = TokenEstimator.estimate(text)
        self.assertGreater(tokens, 3)
        self.assertLess(tokens, 20)

    def test_cost_calculation(self):
        cost = TokenEstimator.calculate_cost(1_000_000, model="claude-3-5-sonnet")
        self.assertAlmostEqual(cost, 3.00, places=2)


dummy_gh = "gh" + "p_1234567890abcdef1234567890abcdef1234"
dummy_openai = "sk-" + "proj-1234567890abcdef1234567890abcdef12345678"
dummy_ant = "sk-" + "ant-1234567890abcdef1234567890abcdef12345678"
dummy_hf = "hf_" + "1234567890abcdef1234567890abcdef12"
dummy_stripe = "sk_" + "live_1234567890abcdef12345678"

class TestSecretScrubber(unittest.TestCase):
    def test_scrub_tokens(self):
        sample = (
            f'gh_token = "{dummy_gh}"\n'
            f'ai_key = "{dummy_openai}"\n'
            f'ant_key = "{dummy_ant}"\n'
            f'hf_key = "{dummy_hf}"\n'
            f'stripe_key = "{dummy_stripe}"\n'
            'aws_key = "AKIA1234567890ABCDEF"\n'
            'db_url = "postgres://root:password123@localhost:5432/mydb"'
        )
        scrubbed, count = SecretScrubber.scrub(sample)
        self.assertGreaterEqual(count, 6)
        self.assertNotIn("1234567890abcdef", scrubbed)
        self.assertNotIn("password123", scrubbed)
        self.assertIn("[REDACTED_SECRET:GITHUB_TOKEN]", scrubbed)
        self.assertIn("[REDACTED_SECRET:OPENAI_KEY]", scrubbed)
        self.assertIn("[REDACTED_SECRET:ANTHROPIC_KEY]", scrubbed)
        self.assertIn("[REDACTED_SECRET:HUGGINGFACE_TOKEN]", scrubbed)
        self.assertIn("[REDACTED_SECRET:STRIPE_KEY]", scrubbed)

    def test_audit_mode(self):
        sample = f'apikey = "secret1234567890"\nghp_token = "{dummy_gh}"'
        findings = SecretScrubber.audit(sample)
        self.assertGreaterEqual(len(findings), 1)
        types = [f.secret_type for f in findings]
        self.assertTrue(any("GITHUB_TOKEN" in t or "GENERIC_SECRET" in t for t in types))


class TestSymbolExtractor(unittest.TestCase):
    def test_python_symbols(self):
        py_code = '''
class Greeter:
    def greet(self): pass
    def farewell(self): pass

def run(): pass
'''
        symbols = SymbolExtractor.extract_python(py_code)
        self.assertTrue(any("class Greeter" in s for s in symbols))
        self.assertTrue(any("def run" in s for s in symbols))

    def test_brace_symbols(self):
        ts_code = '''
export interface Config { port: number; }
export class Server { start() {} }
func main() {}
'''
        symbols = SymbolExtractor.extract_braces(ts_code)
        self.assertTrue(any("Config" in s for s in symbols))
        self.assertTrue(any("Server" in s for s in symbols))


class TestPythonSkeletonizer(unittest.TestCase):
    def test_function_and_class_stubbing(self):
        py_code = '''
import sys

def calculate_tax(income: float, rate: float = 0.2) -> float:
    """Calculate the tax on given income."""
    deductions = 1000.0
    taxable = max(0.0, income - deductions)
    return taxable * rate

class Account:
    """Represents a bank account."""
    currency: str = "USD"

    def __init__(self, owner: str, balance: float = 0.0):
        self.owner = owner
        self.balance = balance

    def deposit(self, amount: float) -> bool:
        """Deposit funds into account."""
        if amount <= 0:
            return False
        self.balance += amount
        return True
'''
        result = PythonSkeletonizer.skeletonize(py_code)
        self.assertIn("def calculate_tax", result)
        self.assertIn("class Account", result)
        self.assertIn("def deposit", result)
        self.assertIn("...", result)
        self.assertNotIn("deductions = 1000.0", result)
        self.assertNotIn("self.balance += amount", result)


class TestBraceSkeletonizer(unittest.TestCase):
    def test_typescript_skeletonizer(self):
        ts_code = '''
export interface UserRecord {
    id: string;
    username: string;
}

export function findUser(id: string): UserRecord | null {
    const raw = cache.get(id);
    if (!raw) {
        return null;
    }
    return JSON.parse(raw);
}
'''
        result = BraceSkeletonizer.skeletonize(ts_code, lang="typescript")
        self.assertIn("export interface UserRecord", result)
        self.assertIn("id: string;", result)
        self.assertIn("export function findUser", result)
        self.assertNotIn("const raw = cache.get(id);", result)

    def test_go_skeletonizer(self):
        go_code = '''
package main

type Server struct {
    Port int
}

func (s *Server) Start() error {
    log.Println("Starting server...")
    return nil
}
'''
        result = BraceSkeletonizer.skeletonize(go_code, lang="go")
        self.assertIn("type Server struct", result)
        self.assertIn("func (s *Server) Start() error", result)
        self.assertNotIn("log.Println", result)


class TestIgnoreEngine(unittest.TestCase):
    def test_default_ignores(self):
        root = Path(__file__).resolve().parent.parent
        engine = IgnoreEngine(root)
        self.assertTrue(engine.is_ignored(root / "node_modules" / "express" / "index.js"))
        self.assertTrue(engine.is_ignored(root / ".git" / "config"))
        self.assertTrue(engine.is_ignored(root / "app.pyc"))
        self.assertTrue(engine.is_ignored(root / "dist" / "bundle.js"))
        self.assertFalse(engine.is_ignored(root / "src" / "index.py"))


class TestPromptFormattersAndBudget(unittest.TestCase):
    def test_budget_optimization(self):
        samples_dir = Path(__file__).resolve().parent.parent / "samples"
        engine_normal = TokenDietEngine(root=samples_dir, mode="skeleton")
        summary_normal = engine_normal.scan()

        engine_budget = TokenDietEngine(root=samples_dir, mode="skeleton", token_budget=400)
        summary_budget = engine_budget.scan()

        self.assertLessEqual(summary_budget.total_compressed_tokens, summary_normal.total_compressed_tokens)
        self.assertLessEqual(summary_budget.total_compressed_tokens, 450)

    def test_xml_and_markdown(self):
        samples_dir = Path(__file__).resolve().parent.parent / "samples"
        engine = TokenDietEngine(root=samples_dir, mode="skeleton")
        summary = engine.scan()

        xml = PromptFormatter.to_xml(summary)
        self.assertIn("<codebase>", xml)
        self.assertIn("<symbol_map>", xml)

        md = PromptFormatter.to_markdown(summary)
        self.assertIn("# Codebase Context", md)
        self.assertIn("## Architectural Symbol Map", md)


if __name__ == "__main__":
    unittest.main()
