"""
SAST-001: Поиск захардкоженных секретов, паролей, приватных ключей и токенов (Regex).
"""

import re
from typing import List
from ..models import Finding


class HardcodedSecretRule:
    RULE_ID = "SAST-001"
    TITLE = "Hardcoded Secret / Credential Leakage"
    SEVERITY = "high"
    CWE = "CWE-798"

    # Шаблоны поиска секретов
    PATTERNS = [
        # Пароли и секретные ключи в присваиваниях: password = "..."
        re.compile(
            r'(?i)\b(password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|jwt[_-]?secret)\b\s*[:=]\s*["\']([^"\']{6,})["\']'
        ),
        # Приватные ключи RSA/PEM в тексте
        re.compile(r"-----BEGIN (?:RSA|EC|OPENSSH|DSA|PGP) PRIVATE KEY-----"),
    ]

    # Игнорируемые плейсхолдеры и безопасные значения
    SAFE_VALUES = {
        "changeme",
        "password",
        "secret",
        "admin",
        "placeholder",
        "none",
        "null",
        "undefined",
        "your_api_key_here",
        "your_secret_here",
        "default",
        "example",
        "true",
        "false",
        "123456",
        "12345678",
    }

    # Маркеры подавления ложных срабатываний
    SUPPRESS_MARKERS = ("# nosec", "// sast-ignore", "# sast-ignore", "/* sast-ignore */", "# noqa")

    def check(self, file_path: str, content: str, lines: List[str]) -> List[Finding]:
        findings: List[Finding] = []

        for lineno, line in enumerate(lines, start=1):
            line_str = line.strip()

            # Проверка комментариев подавления
            if any(marker in line_str.lower() for marker in self.SUPPRESS_MARKERS):
                continue

            # Игнорируем строки, читающие переменные окружения
            if "os.getenv" in line_str or "os.environ" in line_str or "process.env" in line_str:
                continue

            # 1. Поиск присваиваний
            for m in self.PATTERNS[0].finditer(line):
                secret_val = m.group(2)
                if secret_val.lower() in self.SAFE_VALUES:
                    continue
                # Игнорируем плейсхолдеры и явные тесты
                if secret_val.startswith(("{", "<", "$")) and secret_val.endswith(("}", ">")):
                    continue

                col = m.start() + 1
                findings.append(
                    Finding(
                        category="SAST",
                        rule_id=self.RULE_ID,
                        title=self.TITLE,
                        severity=self.SEVERITY,
                        file_path=file_path,
                        line=lineno,
                        column=col,
                        snippet=line_str,
                        cwe=self.CWE,
                        remediation="Вынесите секреты в переменные окружения или защищенный Secret Manager / .env файл.",
                    )
                )

            # 2. Поиск заголовков приватных ключей
            if self.PATTERNS[1].search(line):
                findings.append(
                    Finding(
                        category="SAST",
                        rule_id=self.RULE_ID,
                        title="Embedded Private Key",
                        severity="critical",
                        file_path=file_path,
                        line=lineno,
                        column=1,
                        snippet=line_str,
                        cwe="CWE-312",
                        remediation="Никогда не храните закрытые криптографические ключи в открытом исходном коде.",
                    )
                )

        return findings
