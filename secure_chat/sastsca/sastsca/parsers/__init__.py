"""
Парсеры манифестов зависимостей проектов (requirements.txt, package.json).
"""

from typing import Dict, List, Tuple
from pathlib import Path


class DependencyItem:
    def __init__(self, name: str, version: str, ecosystem: str, manifest_path: str, line: int = 1):
        self.name = name
        self.version = version
        self.ecosystem = ecosystem  # PyPI, npm
        self.manifest_path = manifest_path
        self.line = line

    def __repr__(self) -> str:
        return f"<Dep {self.ecosystem}:{self.name}=={self.version}>"
