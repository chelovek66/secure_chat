#!/usr/bin/env python3
"""Точка вызова сборки релиза из корня secure_chat."""
import sys
from pathlib import Path

script = Path(__file__).resolve().parent / "scripts" / "build_release.py"
if script.is_file():
    exec(script.read_text(encoding="utf-8"))
else:
    raise FileNotFoundError("scripts/build_release.py не найден")
