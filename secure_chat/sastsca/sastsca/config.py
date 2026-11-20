"""
Загрузка и нормализация конфигурации анализатора (.sastsca.yml).
"""

import os
from pathlib import Path
from typing import List, Dict, Any, Optional

try:
    import yaml
except ImportError:
    yaml = None


DEFAULT_CONFIG: Dict[str, Any] = {
    "version": "1.0",
    "fail_on": "high",
    "exclude_paths": [
        ".git",
        ".pytest_cache",
        "__pycache__",
        "venv",
        ".venv",
        "node_modules",
        "dist",
        "build",
        "*.egg-info",
        "keys",
        "*.db",
        "*.db-wal",
        "*.db-shm",
        "fuzz",
        "tests",
    ],
    "sast": {
        "enabled": True,
        "rules": {
            "SAST-001": {"enabled": True, "severity": "high"},
            "SAST-002": {"enabled": True, "severity": "high"},
            "SAST-003": {"enabled": True, "severity": "high"},
            "SAST-004": {"enabled": True, "severity": "critical"},
            "SAST-005": {"enabled": True, "severity": "medium"},
        },
    },
    "sca": {
        "enabled": True,
        "use_offline_cache": True,
        "manifest_files": ["requirements.txt", "package.json"],
    },
}


def load_config(root_dir: Path | str, explicit_config_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Загружает файл конфигурации .sastsca.yml.
    При его отсутствии или сбое парсинга возвращает конфигурацию по умолчанию.
    """
    config = dict(DEFAULT_CONFIG)
    root = Path(root_dir).resolve()

    candidate = None
    if explicit_config_path and Path(explicit_config_path).is_file():
        candidate = Path(explicit_config_path)
    elif (root / ".sastsca.yml").is_file():
        candidate = root / ".sastsca.yml"
    elif (root / ".sastsca.yaml").is_file():
        candidate = root / ".sastsca.yaml"

    if candidate and yaml:
        try:
            with open(candidate, "r", encoding="utf-8") as f:
                loaded = yaml.safe_load(f)
                if isinstance(loaded, dict):
                    # Мержим с дефолтными настройками
                    for k, v in loaded.items():
                        if isinstance(v, dict) and isinstance(config.get(k), dict):
                            config[k].update(v)
                        else:
                            config[k] = v
        except Exception:
            pass

    return config
