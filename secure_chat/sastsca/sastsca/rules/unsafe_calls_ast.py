"""
SAST-002: Поиск небезопасных вызовов через AST-анализ (Python) и синтаксический анализ (JS).
Проверяет: eval, exec, os.system, subprocess.*(..., shell=True).
"""

import ast
import re
from typing import List
from ..models import Finding


class UnsafeCallsAstVisitor(ast.NodeVisitor):
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
        module_name = ""

        # Простой вызов: eval(), exec()
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
            if func_name in ("eval", "exec"):
                snippet = self.lines[lineno - 1].strip() if lineno <= len(self.lines) else f"{func_name}(...)"
                self.findings.append(
                    Finding(
                        category="SAST",
                        rule_id="SAST-002",
                        title=f"Unsafe Execution via '{func_name}()'",
                        severity="high",
                        file_path=self.file_path,
                        line=lineno,
                        column=col,
                        snippet=snippet,
                        cwe="CWE-95",
                        remediation=f"Избегайте вызова '{func_name}()'. Используйте ast.literal_eval() или безопасные парсеры данных.",
                    )
                )

        # Вызов метода: os.system(), subprocess.run(..., shell=True)
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
            if isinstance(node.func.value, ast.Name):
                module_name = node.func.value.id

            # os.system, os.popen
            if module_name == "os" and func_name in ("system", "popen"):
                snippet = self.lines[lineno - 1].strip() if lineno <= len(self.lines) else f"os.{func_name}(...)"
                self.findings.append(
                    Finding(
                        category="SAST",
                        rule_id="SAST-002",
                        title=f"Command Injection Vector: 'os.{func_name}()'",
                        severity="high",
                        file_path=self.file_path,
                        line=lineno,
                        column=col,
                        snippet=snippet,
                        cwe="CWE-78",
                        remediation="Используйте безопасный subprocess.run([...], shell=False) с передачей аргументов списком.",
                    )
                )

            # subprocess.*(..., shell=True)
            if module_name == "subprocess" and func_name in ("run", "Popen", "call", "check_call", "check_output"):
                for kw in node.keywords:
                    if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        snippet = self.lines[lineno - 1].strip() if lineno <= len(self.lines) else f"subprocess.{func_name}(..., shell=True)"
                        self.findings.append(
                            Finding(
                                category="SAST",
                                rule_id="SAST-002",
                                title=f"Command Injection via 'subprocess.{func_name}(shell=True)'",
                                severity="high",
                                file_path=self.file_path,
                                line=lineno,
                                column=col,
                                snippet=snippet,
                                cwe="CWE-78",
                                remediation="Установите shell=False и передавайте команду в виде списка отдельных аргументов.",
                            )
                        )

        self.generic_visit(node)


class UnsafeCallsAstRule:
    RULE_ID = "SAST-002"
    TITLE = "Unsafe Function Call (AST)"
    SEVERITY = "high"

    JS_PATTERNS = [
        re.compile(r"\beval\s*\("),
        re.compile(r"\bchild_process\.exec\s*\("),
    ]

    def check(self, file_path: str, content: str, lines: List[str]) -> List[Finding]:
        findings: List[Finding] = []

        # 1. AST-анализ для файлов Python
        if file_path.endswith(".py"):
            try:
                tree = ast.parse(content, filename=file_path)
                visitor = UnsafeCallsAstVisitor(file_path, lines)
                visitor.visit(tree)
                findings.extend(visitor.findings)
            except SyntaxError:
                pass

        # 2. Анализ для JavaScript / TypeScript
        elif file_path.endswith((".js", ".jsx", ".ts", ".tsx", ".mjs")):
            for lineno, line in enumerate(lines, start=1):
                if any(m in line.lower() for m in ("// sast-ignore", "/* sast-ignore */")):
                    continue
                for pat in self.JS_PATTERNS:
                    m = pat.search(line)
                    if m:
                        findings.append(
                            Finding(
                                category="SAST",
                                rule_id=self.RULE_ID,
                                title="Unsafe Call in JavaScript (eval / child_process.exec)",
                                severity="high",
                                file_path=file_path,
                                line=lineno,
                                column=m.start() + 1,
                                snippet=line.strip(),
                                cwe="CWE-95",
                                remediation="Избегайте выполнения динамического JS-кода через eval() или unescaped child_process.",
                            )
                        )

        return findings
