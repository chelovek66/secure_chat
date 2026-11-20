"""
Движок анализатора (Scan Engine).
Координирует обход файлов, запуск правил SAST, парсинг манифестов и SCA-проверку.
"""

from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional

from .models import Finding, ScanReport, ScanSummary, Severity
from .walker import collect_project_files
from .rules import ALL_RULES
from .parsers.requirements import parse_requirements
from .parsers.package_json import parse_package_json
from .sca import ScaScanner


class ScanEngine:
    def __init__(self, root_dir: Path | str, config: Dict[str, Any]):
        self.root_dir = Path(root_dir).resolve()
        self.config = config
        self.exclude_paths = config.get("exclude_paths", [])
        self.sast_enabled = config.get("sast", {}).get("enabled", True)
        self.sca_enabled = config.get("sca", {}).get("enabled", True)

        # Инициализация SCA
        use_offline = config.get("sca", {}).get("use_offline_cache", True)
        self.sca_scanner = ScaScanner(
            cache_dir=self.root_dir / ".sastsca_cache",
            use_offline_cache=use_offline,
        )

    def run_scan(self) -> ScanReport:
        """Выполняет полный цикл статического и компонентного анализа безопасности."""
        sast_files, sca_files = collect_project_files(self.root_dir, self.exclude_paths)

        findings: List[Finding] = []
        deps_count = 0

        # 1. Выполнение SAST-проверок
        if self.sast_enabled:
            for fpath in sast_files:
                try:
                    rel_p = fpath.relative_to(self.root_dir).as_posix()
                except ValueError:
                    rel_p = str(fpath)

                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        lines = f.readlines()
                    content = "".join(lines)
                except Exception:
                    continue

                for rule in ALL_RULES:
                    rule_conf = self.config.get("sast", {}).get("rules", {}).get(rule.RULE_ID, {})
                    if not rule_conf.get("enabled", True):
                        continue

                    rule_findings = rule.check(rel_p, content, lines)
                    for rf in rule_findings:
                        # Переопределение критичности из конфига, если задано
                        if "severity" in rule_conf:
                            rf.severity = rule_conf["severity"]
                        findings.append(rf)

        # 2. Выполнение SCA-проверок манифестов
        if self.sca_enabled:
            for mpath in sca_files:
                try:
                    rel_m = mpath.relative_to(self.root_dir).as_posix()
                except ValueError:
                    rel_m = str(mpath)

                deps = []
                if mpath.name.lower() == "requirements.txt":
                    deps = parse_requirements(mpath)
                elif mpath.name.lower() == "package.json":
                    deps = parse_package_json(mpath)

                deps_count += len(deps)
                for dep in deps:
                    dep.manifest_path = rel_m
                    sca_findings = self.sca_scanner.check_dependency(dep)
                    findings.extend(sca_findings)

        # 3. Подсчет статистики
        summary = ScanSummary(
            total_findings=len(findings),
            scanned_files_count=len(sast_files),
            scanned_dependencies_count=deps_count,
        )

        for f in findings:
            sev = Severity.from_str(f.severity)
            if sev == Severity.CRITICAL:
                summary.critical += 1
            elif sev == Severity.HIGH:
                summary.high += 1
            elif sev == Severity.MEDIUM:
                summary.medium += 1
            else:
                summary.low += 1

            if f.category == "SAST":
                summary.sast_count += 1
            elif f.category == "SCA":
                summary.sca_count += 1

        return ScanReport(
            target_path=str(self.root_dir),
            scan_timestamp=datetime.now(timezone.utc).isoformat(),
            summary=summary,
            findings=findings,
        )
