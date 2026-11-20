"""
Парсер requirements.txt для экосистемы PyPI.
"""

import re
from pathlib import Path
from typing import List
from . import DependencyItem

# Регулярное выражение для извлечения имени пакета и точной версии
# Поддерживает pkg==1.2.3, pkg>=1.0, pkg~=2.0
REQ_PATTERN = re.compile(r"^([a-zA-Z0-9_\-\.]+)\s*(?:==|>=|<=|~=)\s*([a-zA-Z0-9_\-\.]+)")


def parse_requirements(manifest_path: Path | str) -> List[DependencyItem]:
    """Парсит файл requirements.txt и возвращает список зависимостей."""
    path = Path(manifest_path)
    if not path.is_file():
        return []

    deps: List[DependencyItem] = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for lineno, line in enumerate(f, start=1):
                raw = line.strip()
                if not raw or raw.startswith("#") or raw.startswith("-r") or raw.startswith("-i"):
                    continue

                # Отсекаем хэши и комментарии: package==1.0 --hash=... # comment
                clean = raw.split("#")[0].split(";")[0].strip()
                m = REQ_PATTERN.match(clean)
                if m:
                    pkg_name = m.group(1).lower()
                    pkg_version = m.group(2)
                    deps.append(
                        DependencyItem(
                            name=pkg_name,
                            version=pkg_version,
                            ecosystem="PyPI",
                            manifest_path=str(path),
                            line=lineno,
                        )
                    )
                else:
                    # Если версия не указана строго (например просто requests), берем без версии
                    simple_name = re.match(r"^([a-zA-Z0-9_\-\.]+)", clean)
                    if simple_name:
                        deps.append(
                            DependencyItem(
                                name=simple_name.group(1).lower(),
                                version="latest",
                                ecosystem="PyPI",
                                manifest_path=str(path),
                                line=lineno,
                            )
                        )
    except Exception:
        pass

    return deps
