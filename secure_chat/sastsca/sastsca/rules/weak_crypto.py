"""
SAST-005: Использование слабых или устаревших криптографических примитивов (MD5, SHA1, DES, RC4).
"""

import ast
import re
from typing import List
from ..models import Finding


class WeakCryptoVisitor(ast.NodeVisitor):
    WEAK_HASHES = {"md5", "sha1"}
    WEAK_CIPHERS = {"des", "arc4", "rc4", "blowfish"}

    def __init__(self, file_path: str, lines: List[str]):
        self.file_path = file_path
        self.lines = lines
        self.findings: List[Finding] = []

    def _is_suppressed(self, lineno: int) -> bool:
        if 1 <= lineno <= len(self.lines):
            line = self.lines[lineno - 1].lower()
            return any(m in line for m in ("# nosec", "# sast-ignore", "# noqa"))
        return False

    def visit_Call(self, node: ast.Call):
        lineno = getattr(node, "lineno", 1)
        col = getattr(node, "col_offset", 0) + 1

        if self._is_suppressed(lineno):
            self.generic_visit(node)
            return

        # 1. hashlib.md5() / hashlib.sha1()
        if isinstance(node.func, ast.Attribute):
            attr_name = node.func.attr.lower()
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "hashlib":
                if attr_name in self.WEAK_HASHES:
                    snippet = self.lines[lineno - 1].strip() if lineno <= len(self.lines) else f"hashlib.{attr_name}()"
                    self.findings.append(
                        Finding(
                            category="SAST",
                            rule_id="SAST-005",
                            title=f"Weak Cryptographic Hash Algorithm: '{attr_name.upper()}'",
                            severity="medium",
                            file_path=self.file_path,
                            line=lineno,
                            column=col,
                            snippet=snippet,
                            cwe="CWE-328",
                            remediation=f"Алгоритм {attr_name.upper()} уязвим к коллизиям. Используйте SHA-256, SHA-3 или современные алгоритмы.",
                        )
                    )

            # 2. hashlib.new("md5")
            elif attr_name == "new" and isinstance(node.func.value, ast.Name) and node.func.value.id == "hashlib":
                if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                    algo = node.args[0].value.lower()
                    if algo in self.WEAK_HASHES:
                        snippet = self.lines[lineno - 1].strip() if lineno <= len(self.lines) else f"hashlib.new('{algo}')"
                        self.findings.append(
                            Finding(
                                category="SAST",
                                rule_id="SAST-005",
                                title=f"Weak Cryptographic Hash: '{algo.upper()}'",
                                severity="medium",
                                file_path=self.file_path,
                                line=lineno,
                                column=col,
                                snippet=snippet,
                                cwe="CWE-328",
                                remediation="Используйте криптостойкие хэш-функции (SHA-256 / SHA-512).",
                            )
                        )

        self.generic_visit(node)


class WeakCryptoRule:
    RULE_ID = "SAST-005"
    TITLE = "Weak Cryptographic Primitive"
    SEVERITY = "medium"

    JS_CRYPTO_PATTERNS = [
        re.compile(r"""crypto\.createHash\(\s*["'](md5|sha1)["']\s*\)""", re.IGNORECASE),
    ]

    def check(self, file_path: str, content: str, lines: List[str]) -> List[Finding]:
        findings: List[Finding] = []

        # 1. AST для Python
        if file_path.endswith(".py"):
            try:
                tree = ast.parse(content, filename=file_path)
                visitor = WeakCryptoVisitor(file_path, lines)
                visitor.visit(tree)
                findings.extend(visitor.findings)
            except SyntaxError:
                pass

        # 2. Поиск для JavaScript
        elif file_path.endswith((".js", ".jsx", ".ts", ".tsx")):
            for lineno, line in enumerate(lines, start=1):
                if any(m in line.lower() for m in ("// sast-ignore", "/* sast-ignore */")):
                    continue
                for pat in self.JS_CRYPTO_PATTERNS:
                    m = pat.search(line)
                    if m:
                        algo = m.group(1).upper()
                        findings.append(
                            Finding(
                                category="SAST",
                                rule_id=self.RULE_ID,
                                title=f"Weak Hash in Node.js: '{algo}'",
                                severity="medium",
                                file_path=file_path,
                                line=lineno,
                                column=m.start() + 1,
                                snippet=line.strip(),
                                cwe="CWE-328",
                                remediation="Используйте SHA-256 (crypto.createHash('sha256')).",
                            )
                        )

        return findings
