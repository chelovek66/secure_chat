"""
Генерация человекочитаемого отчета безопасности в формате Markdown.
"""

from ..models import ScanReport, Severity


def render_markdown_report(report: ScanReport) -> str:
    """Генерирует структурированный Markdown-отчет по результатам SAST/SCA анализа."""
    s = report.summary

    lines = [
        "# Отчет статического анализа безопасности (SAST / SCA)",
        "",
        f"- **Целевой каталог**: `{report.target_path}`",
        f"- **Дата и время сканирования**: `{report.scan_timestamp}`",
        f"- **Версия анализатора**: `{report.scanner}`",
        f"- **Проверено файлов кода**: {s.scanned_files_count}",
        f"- **Проверено зависимостей**: {s.scanned_dependencies_count}",
        "",
        "## Сводка по критичности уязвимостей",
        "",
        "| Уровень критичности | Количество находок |",
        "| :--- | :--- |",
        f"| 🚨 **CRITICAL** | **{s.critical}** |",
        f"| 🔴 **HIGH** | **{s.high}** |",
        f"| 🟡 **MEDIUM** | **{s.medium}** |",
        f"| 🔵 **LOW** | **{s.low}** |",
        f"| 📊 **Всего находок** | **{s.total_findings}** (SAST: {s.sast_count}, SCA: {s.sca_count}) |",
        "",
    ]

    if not report.findings:
        lines.append("### ✅ Уязвимостей не обнаружено. Проект соответствует требованиям безопасности.")
        return "\n".join(lines)

    lines.append("## Детализированный реестр находок")
    lines.append("")

    for idx, f in enumerate(report.findings, start=1):
        sev_badge = {
            "critical": "🚨 CRITICAL",
            "high": "🔴 HIGH",
            "medium": "🟡 MEDIUM",
            "low": "🔵 LOW",
        }.get(f.severity.lower(), f.severity.upper())

        lines.append(f"### {idx}. [{f.category}] {f.title} ({sev_badge})")
        lines.append(f"- **Правило / ID**: `{f.rule_id}`" + (f" ({f.cwe})" if f.cwe else ""))
        if f.cve:
            lines.append(f"- **Идентификатор CVE/OSV**: `{f.cve}`")
        if f.package_name:
            lines.append(f"- **Компонент**: `{f.package_name}=={f.installed_version}` (рекомендуемая версия: `{f.fixed_version}`)")
        
        loc = f"`{f.file_path}`"
        if f.line:
            loc += f": строка {f.line}"
        if f.column:
            loc += f", столбец {f.column}"
        lines.append(f"- **Расположение**: {loc}")

        if f.snippet:
            lines.append("- **Фрагмент кода**:")
            lines.append("```python")
            lines.append(f.snippet)
            lines.append("```")

        if f.remediation:
            lines.append(f"- **Рекомендация по устранению**: {f.remediation}")

        lines.append("")

    return "\n".join(lines)
