"""
Консольный интерфейс CLI анализатора sastsca.
Точка входа: sastsca scan --path <dir> --format json|md [--fail-on high]
Коды возврата:
  0 - находок выше порога нет;
  1 - обнаружены уязвимости выше порога;
  2 - ошибка выполнения (не найден путь, сбой парсинга).
"""

import sys
import argparse
from pathlib import Path

from .config import load_config
from .engine import ScanEngine
from .models import Severity, ScanReport
from .reporters import render_json_report, render_markdown_report


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        prog="sastsca",
        description="SAST/SCA Analyzer — Статический анализатор кода и состава зависимостей ПО.",
    )
    subparsers = parser.add_subparsers(dest="command", help="Команды")

    scan_parser = subparsers.add_parser("scan", help="Запуск сканирования проекта")
    scan_parser.add_argument(
        "--path",
        "-p",
        required=True,
        help="Путь к целевому каталогу проекта для анализа",
    )
    scan_parser.add_argument(
        "--format",
        "-f",
        choices=["json", "md", "markdown", "text"],
        default="text",
        help="Формат вывода отчета (text, json, md). По умолчанию: text",
    )
    scan_parser.add_argument(
        "--fail-on",
        choices=["low", "medium", "high", "critical"],
        default=None,
        help="Порог критичности для возврата кода 1 (low, medium, high, critical)",
    )
    scan_parser.add_argument(
        "--output",
        "-o",
        help="Путь к файлу для сохранения отчета (если не указан, вывод в stdout)",
    )
    scan_parser.add_argument(
        "--config",
        "-c",
        help="Пользовательский путь к файлу конфигурации .sastsca.yml",
    )

    return parser.parse_args(argv)


def print_terminal_summary(report: ScanReport, fail_threshold: Severity) -> None:
    """Выводит понятную сводку в терминал."""
    s = report.summary
    print("\n" + "=" * 70)
    print("      РЕЗУЛЬТАТЫ СКАНИРОВАНИЯ БЕЗОПАСНОСТИ (SAST / SCA)")
    print("=" * 70)
    print(f"[*] Целевой каталог:  {report.target_path}")
    print(f"[*] Проверено файлов: {s.scanned_files_count} | Зависимостей: {s.scanned_dependencies_count}")
    print(f"[*] Найдено угроз:    Всего {s.total_findings} (SAST: {s.sast_count}, SCA: {s.sca_count})")
    print("-" * 70)
    print(f"    🚨 CRITICAL: {s.critical}")
    print(f"    🔴 HIGH:     {s.high}")
    print(f"    🟡 MEDIUM:   {s.medium}")
    print(f"    🔵 LOW:      {s.low}")
    print("=" * 70)

    if report.findings:
        print("\n[!] Обнаруженные уязвимости:")
        for idx, f in enumerate(report.findings, start=1):
            print(f"  {idx}. [{f.severity.upper()}] [{f.category}] {f.title}")
            loc = f"{f.file_path}"
            if f.line:
                loc += f":{f.line}"
            print(f"     Локация: {loc}")
            if f.snippet:
                print(f"     Код:     {f.snippet}")
            if f.remediation:
                print(f"     Совет:   {f.remediation}")
            print()
    else:
        print("\n[+] Уязвимостей не обнаружено. Все проверки успешно пройдены!\n")


def main(argv=None) -> int:
    args = parse_args(argv)

    if not args.command:
        # Если команда не указана, выводим справку
        print("Использование: sastsca scan --path <директория_проекта> [--format json|md] [--fail-on high]")
        return 2

    target_dir = Path(args.path)
    if not target_dir.exists():
        print(f"[ERROR] Указанный путь не существует: {args.path}", file=sys.stderr)
        return 2

    try:
        config = load_config(target_dir, args.config)
        fail_on_str = args.fail_on or config.get("fail_on", "high")
        fail_threshold = Severity.from_str(fail_on_str)

        engine = ScanEngine(target_dir, config)
        report = engine.run_scan()

        # Форматирование вывода
        fmt = (args.format or "text").lower()
        output_text = ""

        if fmt == "json":
            output_text = render_json_report(report)
        elif fmt in ("md", "markdown"):
            output_text = render_markdown_report(report)
        else:
            # Текстовый интерактивный вывод + краткий markdown в файл при наличии --output
            print_terminal_summary(report, fail_threshold)
            output_text = render_markdown_report(report)

        # Вывод в файл или консоль
        if args.output:
            out_p = Path(args.output)
            out_p.parent.mkdir(parents=True, exist_ok=True)
            out_p.write_text(output_text, encoding="utf-8")
            print(f"[+] Отчет сохранен в файл: {out_p.resolve()}")
        elif fmt in ("json", "md", "markdown"):
            print(output_text)

        # Определение кода возврата (Exit code)
        # 1 - если есть находки >= порога fail-on
        has_blocking_findings = False
        for f in report.findings:
            sev = Severity.from_str(f.severity)
            if sev >= fail_threshold:
                has_blocking_findings = True
                break

        if has_blocking_findings:
            return 1
        return 0

    except Exception as exc:
        print(f"[FATAL ERROR] Сбой выполнения анализатора: {exc}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 2


if __name__ == "__main__":
    sys.exit(main())
