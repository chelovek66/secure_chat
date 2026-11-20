"""
Сериализация отчета анализатора в формат JSON.
"""

import json
from ..models import ScanReport


def render_json_report(report: ScanReport, indent: int = 2) -> str:
    """Формирует форматированный JSON-документ отчета."""
    return report.model_dump_json(indent=indent)
