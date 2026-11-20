"""
Модуль SCA (Software Composition Analysis).
Сверка версий зависимостей с базой уязвимостей OSV API и локальным кэшем.
"""

import json
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional
import requests

from .parsers import DependencyItem
from .models import Finding

logger = logging.getLogger("sastsca.sca")

OSV_API_URL = "https://api.osv.dev/v1/query"

# Локальная база известных типовых уязвимостей (офлайн-кэш для надежности и автономности)
OFFLINE_VULN_DB: Dict[str, List[Dict[str, Any]]] = {
    "PyPI:urllib3": [
        {
            "id": "CVE-2023-45803",
            "affected_versions": ["1.26.17", "1.26.18", "2.0.0", "2.0.7"],
            "below_version": "2.0.7",
            "fixed": "2.0.7",
            "severity": "high",
            "title": "urllib3 HTTP Request Smuggling / Stream leakage",
            "cwe": "CWE-444",
        },
        {
            "id": "CVE-2021-33503",
            "affected_versions": ["1.26.4", "1.26.3", "1.25.9"],
            "below_version": "1.26.5",
            "fixed": "1.26.5",
            "severity": "medium",
            "title": "ReDoS via Catastrophic Backtracking in URL Authority parser",
            "cwe": "CWE-1333",
        },
    ],
    "PyPI:pyyaml": [
        {
            "id": "CVE-2020-14343",
            "affected_versions": ["5.3", "5.3.1", "5.1", "5.2"],
            "below_version": "5.4",
            "fixed": "5.4.1",
            "severity": "critical",
            "title": "Arbitrary Code Execution via FullLoader / Unsafe deserialization",
            "cwe": "CWE-502",
        }
    ],
    "PyPI:requests": [
        {
            "id": "CVE-2018-18074",
            "affected_versions": ["2.19.1", "2.18.4", "2.19.0"],
            "below_version": "2.20.0",
            "fixed": "2.20.0",
            "severity": "high",
            "title": "Cleartext HTTP Credential Leak on Cross-Domain Redirect",
            "cwe": "CWE-522",
        }
    ],
    "PyPI:cryptography": [
        {
            "id": "CVE-2023-49083",
            "affected_versions": ["41.0.0", "41.0.1", "41.0.5"],
            "below_version": "41.0.6",
            "fixed": "41.0.6",
            "severity": "medium",
            "title": "NULL-pointer dereference in PKCS7 loader",
            "cwe": "CWE-476",
        }
    ],
    "npm:lodash": [
        {
            "id": "CVE-2021-23337",
            "affected_versions": ["4.17.20", "4.17.19"],
            "below_version": "4.17.21",
            "fixed": "4.17.21",
            "severity": "high",
            "title": "Command Injection via template in lodash",
            "cwe": "CWE-78",
        }
    ],
}


class ScaScanner:
    """Движок анализа состава ПО и проверки известных уязвимостей библиотек."""

    def __init__(self, cache_dir: Optional[Path] = None, use_offline_cache: bool = True):
        self.use_offline_cache = use_offline_cache
        self.cache_dir = cache_dir or Path(".sastsca_cache")
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass

    def _query_osv_api(self, name: str, version: str, ecosystem: str) -> Optional[List[Dict[str, Any]]]:
        """Запрашивает OSV REST API для связки пакет + версия."""
        if not version or version == "latest":
            return None

        payload = {
            "version": version,
            "package": {
                "name": name,
                "ecosystem": ecosystem,
            },
        }

        try:
            resp = requests.post(OSV_API_URL, json=payload, timeout=3.5)
            if resp.status_code == 200:
                data = resp.json()
                return data.get("vulns", [])
        except Exception as exc:
            logger.debug(f"OSV API запрос не удался для {name}=={version}: {exc}")

        return None

    def check_dependency(self, dep: DependencyItem) -> List[Finding]:
        """Проверяет одну зависимость и возвращает список найденных уязвимостей."""
        findings: List[Finding] = []
        vulns = None

        # 1. Попытка запроса к удаленному API OSV
        try:
            vulns = self._query_osv_api(dep.name, dep.version, dep.ecosystem)
        except Exception:
            pass

        # 2. Если онлайн-запрос вернул уязвимости
        if vulns:
            for v in vulns:
                raw_id = v.get("id", "UNKNOWN")
                # Извлекаем CVE из aliases, если основной id это GHSA или PYSEC
                cve_id = raw_id
                for alias in v.get("aliases", []):
                    if alias.startswith("CVE-"):
                        cve_id = alias
                        break

                summary = v.get("summary") or v.get("details") or f"Vulnerability in {dep.name}"
                if len(summary) > 120:
                    summary = summary[:117] + "..."

                # Определение критичности
                severity = "medium"
                for s in v.get("severity", []):
                    score = s.get("score", "")
                    if "CVSS:3" in score:
                        severity = "high"

                # Определение безопасной версии
                fixed_ver = "latest"
                for aff in v.get("affected", []):
                    for r in aff.get("ranges", []):
                        for event in r.get("events", []):
                            if "fixed" in event:
                                fixed_ver = event["fixed"]

                findings.append(
                    Finding(
                        category="SCA",
                        rule_id=raw_id,
                        title=f"SCA: {summary}",
                        severity=severity,
                        file_path=dep.manifest_path,
                        line=dep.line,
                        cve=cve_id,
                        package_name=dep.name,
                        installed_version=dep.version,
                        fixed_version=fixed_ver,
                        remediation=f"Обновите пакет '{dep.name}' до версии {fixed_ver} или выше.",
                    )
                )

        # 3. Офлайн-сверка (локальная база) при отсутствии находок от API
        if not findings and self.use_offline_cache:
            db_key = f"{dep.ecosystem}:{dep.name}"
            if db_key in OFFLINE_VULN_DB:
                for rule in OFFLINE_VULN_DB[db_key]:
                    # Проверяем точное совпадение или версию ниже порога
                    is_hit = False
                    if dep.version in rule.get("affected_versions", []):
                        is_hit = True
                    elif rule.get("below_version") and dep.version != "latest":
                        try:
                            # Простое сравнение версий
                            dep_parts = [int(p) for p in dep.version.split(".") if p.isdigit()]
                            lim_parts = [int(p) for p in rule["below_version"].split(".") if p.isdigit()]
                            if dep_parts < lim_parts:
                                is_hit = True
                        except Exception:
                            pass

                    if is_hit:
                        findings.append(
                            Finding(
                                category="SCA",
                                rule_id=rule["id"],
                                title=f"SCA: {rule['title']}",
                                severity=rule.get("severity", "high"),
                                file_path=dep.manifest_path,
                                line=dep.line,
                                cve=rule["id"],
                                cwe=rule.get("cwe"),
                                package_name=dep.name,
                                installed_version=dep.version,
                                fixed_version=rule.get("fixed", "latest"),
                                remediation=f"Обновите пакет '{dep.name}' до версии {rule.get('fixed')} или выше.",
                            )
                        )

        return findings
