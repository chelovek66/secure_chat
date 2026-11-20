"""
Юнит-тесты для SAST/SCA анализатора sastsca.
Проверяют корректность срабатывания правил, отсутствие ложных срабатываний (false positives)
и работу механизмов подавления (# nosec, safe loaders, параметризация).
"""

import pytest
from pathlib import Path

from sastsca.rules.hardcoded_secret import HardcodedSecretRule
from sastsca.rules.unsafe_calls_ast import UnsafeCallsAstRule
from sastsca.rules.sql_injection_ast import SqlInjectionAstRule
from sastsca.rules.insecure_deserialization import InsecureDeserializationRule
from sastsca.rules.weak_crypto import WeakCryptoRule
from sastsca.parsers.requirements import parse_requirements
from sastsca.parsers.package_json import parse_package_json
from sastsca.sca import ScaScanner
from sastsca.parsers import DependencyItem
from sastsca.cli import main as cli_main


# ============================================================================
# 1. ТЕСТ: SAST-001 (Hardcoded Secrets)
# ============================================================================

def test_hardcoded_secret_rule_detects_real_secret():
    rule = HardcodedSecretRule()
    code = 'API_KEY = "sk_live_99238481239848123984123"\n'
    findings = rule.check("config.py", code, code.splitlines())
    assert len(findings) == 1
    assert findings[0].rule_id == "SAST-001"
    assert findings[0].severity == "high"


def test_hardcoded_secret_rule_ignores_placeholders_and_env():
    rule = HardcodedSecretRule()
    code = (
        'DB_PASS = os.getenv("DB_PASSWORD", "changeme")\n'
        'SAFE_TOKEN = "your_api_key_here"\n'
        'SECRET = "super_secret_token_123"  # nosec\n'
    )
    findings = rule.check("config.py", code, code.splitlines())
    assert len(findings) == 0, "Плейсхолдеры и подавленные строки не должны вызывать срабатываний"


# ============================================================================
# 2. ТЕСТ: SAST-002 (Unsafe Calls AST)
# ============================================================================

def test_unsafe_calls_ast_detects_eval_and_os_system():
    rule = UnsafeCallsAstRule()
    code = (
        "import os\n"
        "eval(user_payload)\n"
        "os.system('rm -rf /tmp')\n"
    )
    findings = rule.check("worker.py", code, code.splitlines())
    assert len(findings) == 2
    titles = [f.title for f in findings]
    assert any("eval" in t for t in titles)
    assert any("os.system" in t for t in titles)


def test_unsafe_calls_ast_subprocess_shell_flag():
    rule = UnsafeCallsAstRule()
    # Опасный вызов с shell=True vs безопасный shell=False
    code = (
        "import subprocess\n"
        "subprocess.run('ping ' + host, shell=True)\n"
        "subprocess.run(['ping', host], shell=False)\n"
        "eval('1+1')  # nosec\n"
    )
    findings = rule.check("network.py", code, code.splitlines())
    assert len(findings) == 1
    assert "shell=True" in findings[0].title


# ============================================================================
# 3. ТЕСТ: SAST-003 (SQL Injection AST)
# ============================================================================

def test_sql_injection_ast_detects_fstring_and_concatenation():
    rule = SqlInjectionAstRule()
    code = (
        "cursor.execute(f'SELECT * FROM users WHERE login = {user}')\n"
        "cursor.execute('SELECT * FROM users WHERE login = ' + user)\n"
        "cursor.execute('SELECT * FROM users WHERE login = ?', (user,))\n"  # Безопасно!
    )
    findings = rule.check("db.py", code, code.splitlines())
    assert len(findings) == 2
    assert findings[0].rule_id == "SAST-003"
    assert findings[1].rule_id == "SAST-003"


# ============================================================================
# 4. ТЕСТ: SAST-004 (Insecure Deserialization AST)
# ============================================================================

def test_insecure_deserialization_ast_pickle_and_yaml():
    rule = InsecureDeserializationRule()
    code = (
        "import pickle, yaml, json\n"
        "obj1 = pickle.loads(untrusted_bytes)\n"
        "obj2 = yaml.load(untrusted_yaml)\n"
        "obj3 = yaml.safe_load(untrusted_yaml)\n"  # Безопасно!
        "obj4 = json.loads(untrusted_json)\n"     # Безопасно!
    )
    findings = rule.check("handler.py", code, code.splitlines())
    assert len(findings) == 2
    assert findings[0].severity == "critical"
    assert findings[1].severity == "critical"


# ============================================================================
# 5. ТЕСТ: SAST-005 (Weak Cryptography AST)
# ============================================================================

def test_weak_crypto_ast_detects_md5_and_sha1():
    rule = WeakCryptoRule()
    code = (
        "import hashlib\n"
        "h1 = hashlib.md5(data).hexdigest()\n"
        "h2 = hashlib.sha1(data).digest()\n"
        "h3 = hashlib.sha256(data).digest()\n"  # Безопасно!
    )
    findings = rule.check("hasher.py", code, code.splitlines())
    assert len(findings) == 2
    assert findings[0].rule_id == "SAST-005"


# ============================================================================
# 6. ТЕСТ: SCA (Парсинг манифестов и проверка уязвимостей)
# ============================================================================

def test_sca_manifest_parsing_and_detection(tmp_path: Path):
    req_file = tmp_path / "requirements.txt"
    req_file.write_text(
        "urllib3==1.26.4\n"
        "pyyaml==5.3\n"
        "requests==2.28.1\n",
        encoding="utf-8",
    )

    deps = parse_requirements(req_file)
    assert len(deps) == 3
    names = {d.name: d.version for d in deps}
    assert names["urllib3"] == "1.26.4"
    assert names["pyyaml"] == "5.3"

    scanner = ScaScanner(use_offline_cache=True)
    findings = []
    for d in deps:
        findings.extend(scanner.check_dependency(d))

    assert len(findings) >= 2
    vuln_cves = [f.cve for f in findings]
    assert any("CVE-2021-33503" in c for c in vuln_cves)
    assert any("CVE-2020-14343" in c for c in vuln_cves)


# ============================================================================
# 7. ТЕСТ: CLI Interface & Exit Codes
# ============================================================================

def test_cli_scan_exit_codes(tmp_path: Path):
    safe_file = tmp_path / "safe.py"
    safe_file.write_text("x = 1 + 2\nprint(x)\n", encoding="utf-8")

    # 1. Сканирование чистого каталога -> код 0
    code_ok = cli_main(["scan", "--path", str(tmp_path), "--format", "json"])
    assert code_ok == 0

    # 2. Добавление уязвимого кода (eval) -> код 1
    vuln_file = tmp_path / "vuln.py"
    vuln_file.write_text("eval(input())\n", encoding="utf-8")

    code_fail = cli_main(["scan", "--path", str(tmp_path), "--fail-on", "high"])
    assert code_fail == 1

    # 3. Несуществующий каталог -> код 2
    code_err = cli_main(["scan", "--path", str(tmp_path / "non_existing_dir")])
    assert code_err == 2
