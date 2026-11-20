"""
SAST-003: Обнаружение потенциальных SQL-инъекций через динамическое форматирование запросов (AST).
Проверяет: cursor.execute(...) с f-строками, конкатенацией (+), % или .format().
"""

import ast
from typing import List
from ..models import Finding


class SqlInjectionAstVisitor(ast.NodeVisitor):
    SQL_KEYWORDS = {"select", "insert", "update", "delete", "drop", "alter", "create", "truncate"}

    def __init__(self, file_path: str, lines: List[str]):
        self.file_path = file_path
        self.lines = lines
        self.findings: List[Finding] = []

    def _is_suppressed(self, lineno: int) -> bool:
        if 1 <= lineno <= len(self.lines):
            line = self.lines[lineno - 1].lower()
            return any(m in line for m in ("# nosec", "# sast-ignore", "# noqa"))
        return False

    def _contains_sql_keyword(self, text: str) -> bool:
        words = set(text.lower().split())
        return bool(words.intersection(self.SQL_KEYWORDS))

    def visit_Call(self, node: ast.Call):
        lineno = getattr(node, "lineno", 1)
        col = getattr(node, "col_offset", 0) + 1

        if self._is_suppressed(lineno):
            self.generic_visit(node)
            return

        is_execute = False
        if isinstance(node.func, ast.Attribute) and node.func.attr in ("execute", "executescript"):
            is_execute = True

        if is_execute and node.args:
            first_arg = node.args[0]
            is_dynamic_sql = False
            desc = ""

            # 1. f-строка: execute(f"SELECT ... {user_input}")
            if isinstance(first_arg, ast.JoinedStr):
                raw_text = "".join(
                    part.value for part in first_arg.values if isinstance(part, ast.Constant) and isinstance(part.value, str)
                )
                if self._contains_sql_keyword(raw_text) or not raw_text:
                    is_dynamic_sql = True
                    desc = "Использование f-строки для формирования SQL-запроса"

            # 2. Конкатенация строк: execute("SELECT ... " + user_input)
            elif isinstance(first_arg, ast.BinOp) and isinstance(first_arg.op, ast.Add):
                is_dynamic_sql = True
                desc = "Конкатенация строк через оператор '+' в SQL-запросе"

            # 3. Оператор %: execute("SELECT ... %s" % user_input)
            elif isinstance(first_arg, ast.BinOp) and isinstance(first_arg.op, ast.Mod):
                is_dynamic_sql = True
                desc = "Форматирование SQL-запроса через оператор '%'"

            # 4. .format(): execute("SELECT ... {}".format(user_input))
            elif isinstance(first_arg, ast.Call) and isinstance(first_arg.func, ast.Attribute) and first_arg.func.attr == "format":
                is_dynamic_sql = True
                desc = "Форматирование SQL-запроса через метод .format()"

            if is_dynamic_sql:
                snippet = self.lines[lineno - 1].strip() if lineno <= len(self.lines) else "cursor.execute(...)"
                self.findings.append(
                    Finding(
                        category="SAST",
                        rule_id="SAST-003",
                        title=f"SQL Injection: {desc}",
                        severity="high",
                        file_path=self.file_path,
                        line=lineno,
                        column=col,
                        snippet=snippet,
                        cwe="CWE-89",
                        remediation="Используйте параметризованные запросы с плейсхолдерами ('?' или '%s') и передавайте параметры вторым кортежем/списком.",
                    )
                )

        self.generic_visit(node)


class SqlInjectionAstRule:
    RULE_ID = "SAST-003"
    TITLE = "SQL Injection Vulnerability (AST)"
    SEVERITY = "high"

    def check(self, file_path: str, content: str, lines: List[str]) -> List[Finding]:
        findings: List[Finding] = []
        if not file_path.endswith(".py"):
            return findings

        try:
            tree = ast.parse(content, filename=file_path)
            visitor = SqlInjectionAstVisitor(file_path, lines)
            visitor.visit(tree)
            findings.extend(visitor.findings)
        except SyntaxError:
            pass

        return findings
