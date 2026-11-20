"""
Парсер package.json для экосистемы npm.
"""

import json
import re
from pathlib import Path
from typing import List
from . import DependencyItem


def parse_package_json(manifest_path: Path | str) -> List[DependencyItem]:
    """Парсит package.json и извлекает dependencies и devDependencies."""
    path = Path(manifest_path)
    if not path.is_file():
        return []

    deps: List[DependencyItem] = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            data = json.load(f)

        dep_sections = [
            data.get("dependencies", {}),
            data.get("devDependencies", {}),
        ]

        for section in dep_sections:
            if not isinstance(section, dict):
                continue
            for name, ver in section.items():
                if not isinstance(ver, str):
                    continue
                # Очищаем семантические префиксы (^1.2.3, ~1.2.3, >=1.2.3)
                clean_ver = re.sub(r"[\^~>=<]", "", ver).strip()
                deps.append(
                    DependencyItem(
                        name=name.lower(),
                        version=clean_ver or "latest",
                        ecosystem="npm",
                        manifest_path=str(path),
                        line=1,
                    )
                )
    except Exception:
        pass

    return deps
