"""
SAST-004: Обнаружение небезопасной десериализации (pickle, yaml.load, marshal) через AST.
"""

import ast
from typing import List
from ..models import Finding


class DeserializationVisitor(ast.NodeVisitor):
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

        func_name = ""
        mod_name = ""

        if isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
            if isinstance(node.func.value, ast.Name):
                mod_name = node.func.value.id

            # 1. pickle.loads / pickle.load / _pickle
            if mod_name in ("pickle", "_pickle", "cPickle") and func_name in ("loads", "load"):
                snippet = self.lines[lineno - 1].strip() if lineno <= len(self.lines) else f"{mod_name}.{func_name}(...)"
                self.findings.append(
                    Finding(
                        category="SAST",
                        rule_id="SAST-004",
                        title=f"Insecure Deserialization via '{mod_name}.{func_name}()'",
                        severity="critical",
                        file_path=self.file_path,
                        line=lineno,
                        column=col,
                        snippet=snippet,
                        cwe="CWE-502",
                        remediation="Модуль pickle подвержен RCE при десериализации данных. Используйте JSON, protobuf или подписанные токены HMAC.",
                    )
                )

            # 2. yaml.load без SafeLoader
            elif mod_name in ("yaml", "ruamel") and func_name == "load":
                has_safe_loader = False
                for kw in node.keywords:
                    if kw.arg == "Loader":
                        if isinstance(kw.value, ast.Attribute) and "Safe" in kw.value.attr:
                            has_safe_loader = True
                        elif isinstance(kw.value, ast.Name) and "Safe" in kw.value.id:
                            has_safe_loader = True

                if not has_safe_loader:
                    snippet = self.lines[lineno - 1].strip() if lineno <= len(self.lines) else "yaml.load(...)"
                    self.findings.append(
                        Finding(
                            category="SAST",
                            rule_id="SAST-004",
                            title="Unsafe YAML Deserialization (yaml.load without SafeLoader)",
                            severity="critical",
                            file_path=self.file_path,
                            line=lineno,
                            column=col,
                            snippet=snippet,
                            cwe="CWE-502",
                            remediation="Используйте yaml.safe_load(...) или явно передавайте Loader=yaml.SafeLoader.",
                        )
                    )

            # 3. marshal.loads / shelve.open
            elif mod_name == "marshal" and func_name in ("loads", "load"):
                snippet = self.lines[lineno - 1].strip() if lineno <= len(self.lines) else "marshal.loads(...)"
                self.findings.append(
                    Finding(
                        category="SAST",
                        rule_id="SAST-004",
                        title="Unsafe Deserialization via 'marshal.loads()'",
                        severity="critical",
                        file_path=self.file_path,
                        line=lineno,
                        column=col,
                        snippet=snippet,
                        cwe="CWE-502",
                        remediation="Формат marshal не предназначен для обработки непроверенных данных.",
                    )
                )

        self.generic_visit(node)


class InsecureDeserializationRule:
    RULE_ID = "SAST-004"
    TITLE = "Insecure Deserialization (AST)"
    SEVERITY = "critical"

    def check(self, file_path: str, content: str, lines: List[str]) -> List[Finding]:
        findings: List[Finding] = []
        if not file_path.endswith(".py"):
            return findings

        try:
            tree = ast.parse(content, filename=file_path)
            visitor = DeserializationVisitor(file_path, lines)
            visitor.visit(tree)
            findings.extend(visitor.findings)
        except SyntaxError:
            pass

        return findings
