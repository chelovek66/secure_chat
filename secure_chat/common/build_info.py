"""
Модуль формирования и управления метаданными сборки и версии «Secure Chat».
Реализует спецификацию стандартов Республики Беларусь:
  * СТБ 34.101.45-2013 (bign, выработка ключевых пар, ЭЦП, KEM)
  * СТБ 34.101.31-2011 (belt-che, симметричное шифрование и имитозащита)
  * СТБ 34.101.47-2017 (bash256, криптографическое хэширование)
  * СТБ 34.101.78-2017 (belt-kwp, ключевые контейнеры)
"""

import json
import logging
import os
import platform
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from pydantic import BaseModel, Field

logger = logging.getLogger("secure_chat.build_info")

APP_NAME = "Secure Chat (СТБ 34.101.45/31/47)"
VERSION = "2.1.0-STB"
BUILD_NUMBER = 105
OFFICIAL_RELEASE_DATE = "24.10.2026 09:55:00"

DEFAULT_STB_STANDARDS: List[str] = [
    "СТБ 34.101.45-2013 (bign)",
    "СТБ 34.101.31-2011 (belt-che)",
    "СТБ 34.101.47-2017 (bash256)",
    "СТБ 34.101.78-2017 (belt-kwp)",
]


class BuildInfo(BaseModel):
    """
    Структурированные метаданные сборки и версии приложения «Secure Chat».
    Содержит системные параметры среды исполнения, статус криптодвижка и перечень стандартов.
    """
    app_name: str = Field(default=APP_NAME, description="Официальное наименование программного комплекса")
    version: str = Field(default=VERSION, description="Версия релиза по стандарту SemVer")
    build_number: int = Field(default=100, description="Инкрементальный номер сборки")
    build_date: str = Field(default="", description="Временная метка сборки в формате ISO 8601 UTC")
    git_commit: str = Field(default="unknown", description="Хэш коммита системы контроля версий Git")
    git_branch: str = Field(default="unknown", description="Ветка репозитория Git")
    python_version: str = Field(default="", description="Версия интерпретатора Python")
    platform: str = Field(default="", description="Информация об операционной системе и архитектуре")
    crypto_engine: str = Field(default="", description="Статус национальной библиотеки Bee2 / fallback")
    stb_standards: List[str] = Field(
        default_factory=lambda: list(DEFAULT_STB_STANDARDS),
        description="Перечень поддерживаемых государственных стандартов Республики Беларусь",
    )

    def to_dict(self) -> dict:
        """Преобразование метаданных сборки в словарь."""
        return self.model_dump()

    def to_json(self, indent: int = 4) -> str:
        """Сериализация метаданных в форматированный JSON."""
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)


def _detect_git_commit() -> str:
    """Определяет хэш последнего коммита Git с безопасным fallback."""
    env_commit = os.getenv("GIT_COMMIT")
    if env_commit:
        return env_commit.strip()

    try:
        res = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            timeout=2.0,
            check=True,
        )
        commit = res.stdout.strip()
        if commit:
            return commit
    except Exception:
        pass
    return "unknown"


def _detect_git_branch() -> str:
    """Определяет текущую ветку Git с безопасным fallback."""
    env_branch = os.getenv("GIT_BRANCH")
    if env_branch:
        return env_branch.strip()

    try:
        res = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True,
            text=True,
            timeout=2.0,
            check=True,
        )
        branch = res.stdout.strip()
        if branch:
            return branch
    except Exception:
        pass
    return "unknown"


def _detect_crypto_engine() -> str:
    """
    Определяет статус и тип криптографического ядра:
    родная C-библиотека bee2.dll либо сертифицированный Python-fallback.
    """
    env_engine = os.getenv("SECURE_CHAT_CRYPTO_ENGINE")
    if env_engine:
        return env_engine

    try:
        from client.crypto.bee2_wrapper import _find_bee2_library
        lib = _find_bee2_library()
        if lib and Path(lib).is_file():
            return f"Bee2 Native C-FFI ({Path(lib).name})"
    except Exception as err:
        logger.debug(f"Ошибка при проверке наличия bee2: {err}")

    return "Fallback Software Engine (СТБ 34.101.хх / 256-bit)"


def format_display_date(val: str) -> str:
    """
    Преобразует дату сборки в нормальный человекочитаемый формат:
    ДД.ММ.ГГГГ ЧЧ:ММ:СС (например: 24.10.2026 09:55:00).
    """
    if not val or val == "-":
        return "-"
    if "." in val and len(val.split(".")[0]) <= 2:
        return val
    try:
        clean = val.replace("Z", "+00:00")
        if "T" in clean:
            dt = datetime.fromisoformat(clean)
            from datetime import timedelta
            tz_local = timezone(timedelta(hours=3))
            dt_local = dt.astimezone(tz_local)
            return dt_local.strftime("%d.%m.%Y %H:%M:%S")
    except Exception:
        pass
    return val.replace("T", " ").rstrip("Z")


def get_build_info() -> BuildInfo:
    """
    Формирует актуальный снимок информации о сборке в текущем окружении.
    Фиксирует дату и номер официального релиза программы.
    """
    build_num = BUILD_NUMBER
    build_date = OFFICIAL_RELEASE_DATE

    # Проверяем наличие файла фиксированных метаданных сборки build_info.json
    build_file = Path(__file__).resolve().parent.parent / "build_info.json"
    if build_file.is_file():
        try:
            data = json.loads(build_file.read_text(encoding="utf-8"))
            build_date = data.get("build_date", build_date)
            build_num = int(data.get("build_number", build_num))
        except Exception:
            pass

    env_build_num = os.getenv("BUILD_NUMBER")
    if env_build_num:
        try:
            build_num = int(env_build_num)
        except ValueError:
            pass

    env_build_date = os.getenv("BUILD_DATE")
    if env_build_date:
        build_date = env_build_date

    return BuildInfo(
        app_name=APP_NAME,
        version=VERSION,
        build_number=build_num,
        build_date=build_date,
        git_commit=_detect_git_commit(),
        git_branch=_detect_git_branch(),
        python_version=platform.python_version(),
        platform=platform.platform(),
        crypto_engine=_detect_crypto_engine(),
        stb_standards=list(DEFAULT_STB_STANDARDS),
    )


def generate_build_metadata(output_file: str = "build_info.json") -> dict:
    """
    Генерирует JSON-файл метаданных сборки и возвращает полученный словарь.
    """
    info = get_build_info()
    data = info.to_dict()
    out_path = Path(output_file)
    if out_path.parent != Path("."):
        out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(info.to_json(indent=4), encoding="utf-8")
    logger.info(f"Метаданные сборки сохранены в {out_path}")
    return data


def format_build_summary(info: Optional[BuildInfo] = None) -> str:
    """
    Формирует человекочитаемую сводку информации о сборке и стандартах.
    """
    if info is None:
        info = get_build_info()

    standards_lines = "\n".join(f"    * {std}" for std in info.stb_standards)
    summary = (
        f"======================================================================\n"
        f"  {info.app_name}\n"
        f"  Версия ПО:       {info.version} (Сборка #{info.build_number})\n"
        f"  Дата релиза:     {format_display_date(info.build_date)}\n"
        f"  Ветка Git:       {info.git_branch}\n"
        f"  Коммит Git:      {info.git_commit}\n"
        f"  Python:          {info.python_version}\n"
        f"  Платформа:       {info.platform}\n"
        f"  Криптодвижок:    {info.crypto_engine}\n"
        f"  Стандарты СТБ РБ:\n"
        f"{standards_lines}\n"
        f"======================================================================"
    )
    return summary
