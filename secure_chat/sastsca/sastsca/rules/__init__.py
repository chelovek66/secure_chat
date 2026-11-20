"""
Пакет правил статического анализа безопасности (SAST).
Каждое правило реализует интерфейс:
    check(file_path: str, content: str, lines: list[str]) -> list[Finding]
"""

from .hardcoded_secret import HardcodedSecretRule
from .unsafe_calls_ast import UnsafeCallsAstRule
from .sql_injection_ast import SqlInjectionAstRule
from .insecure_deserialization import InsecureDeserializationRule
from .weak_crypto import WeakCryptoRule

ALL_RULES = [
    HardcodedSecretRule(),
    UnsafeCallsAstRule(),
    SqlInjectionAstRule(),
    InsecureDeserializationRule(),
    WeakCryptoRule(),
]
