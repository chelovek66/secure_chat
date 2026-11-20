"""
Модуль обхода файлов (File Walker) с поддержкой .gitignore и фильтрацией путей.
"""

import fnmatch
from pathlib import Path
from typing import List, Set, Iterable, Optional


SUPPORTED_SAST_EXTENSIONS = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".mjs",
    ".cjs",
    ".json",
    ".yml",
    ".yaml",
}

SUPPORTED_SCA_MANIFESTS = {
    "requirements.txt",
    "package.json",
    "pom.xml",
    "pipfile.lock",
}


def load_gitignore_patterns(root_dir: Path) -> List[str]:
    """Считывает шаблоны игнорирования из .gitignore."""
    patterns = []
    gitignore_file = root_dir / ".gitignore"
    if gitignore_file.is_file():
        try:
            with open(gitignore_file, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    stripped = line.strip()
                    if stripped and not stripped.startswith("#"):
                        patterns.append(stripped)
        except Exception:
            pass
    return patterns


def is_path_excluded(rel_path: Path, exclude_patterns: Iterable[str]) -> bool:
    """Проверяет, подходит ли относительный путь под правила исключения."""
    rel_str = rel_path.as_posix()
    parts = rel_path.parts

    for pat in exclude_patterns:
        clean_pat = pat.rstrip("/").lstrip("/")
        # Проверка отдельных сегментов пути
        if any(fnmatch.fnmatch(part, clean_pat) for part in parts):
            return True
        # Проверка полного относительного пути
        if fnmatch.fnmatch(rel_str, clean_pat) or fnmatch.fnmatch(rel_str, f"*{clean_pat}*"):
            return True

    return False


def collect_project_files(
    root_path: Path | str,
    exclude_patterns: Optional[Iterable[str]] = None,
) -> tuple[List[Path], List[Path]]:
    """
    Рекурсивно сканирует каталог проекта.
    Возвращает два списка: (список_исходников_для_SAST, список_манифестов_для_SCA).
    """
    root = Path(root_path).resolve()
    if not root.exists():
        raise FileNotFoundError(f"Каталог не найден: {root}")

    all_excludes = list(load_gitignore_patterns(root))
    if exclude_patterns:
        all_excludes.extend(exclude_patterns)

    # Стандартные обязательные исключения
    all_excludes.extend([
        ".git",
        "__pycache__",
        ".pytest_cache",
        "venv",
        ".venv",
        "node_modules",
        "dist",
        "build",
        "*.pyc",
        "*.pyo",
        "*.exe",
        "*.dll",
    ])

    sast_files: List[Path] = []
    sca_files: List[Path] = []

    for file_path in root.rglob("*"):
        if not file_path.is_file():
            continue

        try:
            rel = file_path.relative_to(root)
        except ValueError:
            continue

        if is_path_excluded(rel, all_excludes):
            continue

        # Проверка на манифест SCA
        if file_path.name.lower() in SUPPORTED_SCA_MANIFESTS:
            sca_files.append(file_path)

        # Проверка на исходный код SAST
        ext = file_path.suffix.lower()
        if ext in SUPPORTED_SAST_EXTENSIONS:
            sast_files.append(file_path)

    return sorted(sast_files), sorted(sca_files)
