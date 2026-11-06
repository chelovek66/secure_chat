"""
Тесты модулей управления конфигурацией (ConfigManager) и сборки/версионирования (BuildInfo),
а также серверного эндпоинта GET /version.
Проверяют требования ТЗ:
  * Надежная загрузка, сохранение, сброс к умолчаниям, экспорт и импорт настроек;
  * Корректная обработка поврежденных/невалидных файлов JSON;
  * Механизм подписки на события изменения конфигурации;
  * Генерация метаданных сборки, поддержка стандартов СТБ РБ;
  * Устойчивость к отсутствию репозитория Git (fallback) и корректная детекция криптодвижка;
  * REST API эндпоинт GET /version.
"""

import json
import os
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from common.config_manager import ClientConfig, ConfigManager, ConfigError
from common.build_info import (
    BuildInfo,
    get_build_info,
    generate_build_metadata,
    format_build_summary,
    DEFAULT_STB_STANDARDS,
    _detect_git_commit,
    _detect_git_branch,
    _detect_crypto_engine,
)
from server.app import app


# ============================================================================
# Тесты ClientConfig
# ============================================================================

def test_client_config_defaults():
    """Проверка эталонных значений по умолчанию в ClientConfig."""
    cfg = ClientConfig()
    assert cfg.server_url == "http://127.0.0.1:8000"
    assert cfg.poll_interval_sec == 2.0
    assert cfg.request_timeout_sec == 10.0
    assert cfg.keys_dir == "keys"
    assert cfg.theme == "dark"
    assert cfg.log_level == "INFO"
    assert cfg.verify_integrity_on_startup is True
    assert cfg.auto_reconnect is True


def test_client_config_validation():
    """Проверка валидации полей ClientConfig."""
    # Недопустимый URL
    with pytest.raises(Exception):
        ClientConfig(server_url="ftp://invalid-scheme.com")

    with pytest.raises(Exception):
        ClientConfig(server_url="")

    # Отрицательный poll_interval_sec
    with pytest.raises(Exception):
        ClientConfig(poll_interval_sec=-1.0)

    with pytest.raises(Exception):
        ClientConfig(poll_interval_sec=0.0)

    # Отрицательный request_timeout_sec
    with pytest.raises(Exception):
        ClientConfig(request_timeout_sec=-5.0)

    # Недопустимый log_level
    with pytest.raises(Exception):
        ClientConfig(log_level="VERBOSE")


def test_client_config_serialization():
    """Проверка сериализации в dict и JSON, и десериализации."""
    cfg = ClientConfig(
        server_url="https://secure.example.com",
        poll_interval_sec=3.5,
        theme="light",
        log_level="DEBUG",
    )
    d = cfg.to_dict()
    assert d["server_url"] == "https://secure.example.com"
    assert d["poll_interval_sec"] == 3.5
    assert d["theme"] == "light"
    assert d["log_level"] == "DEBUG"

    json_str = cfg.to_json()
    reloaded = ClientConfig.from_json(json_str)
    assert reloaded.server_url == cfg.server_url
    assert reloaded.poll_interval_sec == cfg.poll_interval_sec
    assert reloaded.theme == cfg.theme


# ============================================================================
# Тесты ConfigManager
# ============================================================================

def test_config_manager_creates_defaults_if_missing(tmp_path):
    """Если файл конфигурации отсутствует, ConfigManager создает его с defaults."""
    cfg_file = tmp_path / "config.json"
    assert not cfg_file.exists()

    mgr = ConfigManager(cfg_file)
    cfg = mgr.load_config()

    assert cfg_file.exists()
    assert cfg.server_url == "http://127.0.0.1:8000"
    assert cfg.poll_interval_sec == 2.0

    # Проверяем, что файл содержит корректный JSON
    saved_data = json.loads(cfg_file.read_text(encoding="utf-8"))
    assert saved_data["server_url"] == "http://127.0.0.1:8000"


def test_config_manager_save_and_reload(tmp_path):
    """Проверка сохранения измененной конфигурации и повторной загрузки."""
    cfg_file = tmp_path / "custom_config.json"
    mgr = ConfigManager(cfg_file)

    modified_cfg = ClientConfig(
        server_url="http://192.168.1.100:9000",
        poll_interval_sec=1.5,
        request_timeout_sec=15.0,
        keys_dir="my_keys",
        theme="light",
        log_level="DEBUG",
        verify_integrity_on_startup=False,
        auto_reconnect=False,
    )
    mgr.save_config(modified_cfg)

    # Создаем новый менеджер и читаем с диска
    mgr2 = ConfigManager(cfg_file)
    loaded = mgr2.load_config()

    assert loaded.server_url == "http://192.168.1.100:9000"
    assert loaded.poll_interval_sec == 1.5
    assert loaded.request_timeout_sec == 15.0
    assert loaded.keys_dir == "my_keys"
    assert loaded.theme == "light"
    assert loaded.log_level == "DEBUG"
    assert loaded.verify_integrity_on_startup is False
    assert loaded.auto_reconnect is False


def test_config_manager_reset_defaults(tmp_path):
    """Проверка сброса параметров к значениям по умолчанию."""
    cfg_file = tmp_path / "config.json"
    mgr = ConfigManager(cfg_file)
    mgr.save_config(ClientConfig(server_url="http://changed.com:8000", theme="light"))

    assert mgr.get_config().theme == "light"

    # Сброс
    reset_cfg = mgr.reset_defaults()
    assert reset_cfg.server_url == "http://127.0.0.1:8000"
    assert reset_cfg.theme == "dark"

    # Проверка на диске
    disk_cfg = ClientConfig.from_json(cfg_file.read_text(encoding="utf-8"))
    assert disk_cfg.server_url == "http://127.0.0.1:8000"
    assert disk_cfg.theme == "dark"


def test_config_manager_export_and_import(tmp_path):
    """Проверка экспорта и импорта файла конфигурации."""
    main_file = tmp_path / "main_config.json"
    export_file = tmp_path / "backup" / "exported_config.json"

    mgr = ConfigManager(main_file)
    initial_cfg = ClientConfig(server_url="http://alpha.internal:8000", theme="light")
    mgr.save_config(initial_cfg)

    # Экспорт
    mgr.export_config(export_file)
    assert export_file.is_file()

    # Изменяем основной файл
    mgr.save_config(ClientConfig(server_url="http://beta.internal:8000", theme="dark"))
    assert mgr.get_config().server_url == "http://beta.internal:8000"

    # Импортируем из экспортированного файла
    imported_cfg = mgr.import_config(export_file)
    assert imported_cfg.server_url == "http://alpha.internal:8000"
    assert imported_cfg.theme == "light"
    assert mgr.get_config().server_url == "http://alpha.internal:8000"

    # Проверяем, что импорт несуществующего файла вызывает FileNotFoundError
    with pytest.raises(FileNotFoundError):
        mgr.import_config(tmp_path / "does_not_exist.json")


def test_config_manager_invalid_json_handling(tmp_path):
    """Проверка обработки поврежденного и некорректного JSON."""
    cfg_file = tmp_path / "corrupted_config.json"

    # 1. Синтаксически битый JSON
    cfg_file.write_text("{\n  \"server_url\": \"http://127.0.0.1:8000\",\n  BROKEN_SYNTAX", encoding="utf-8")

    mgr = ConfigManager(cfg_file)
    # По умолчанию без fallback должен поднимать ConfigError (наследник ValueError)
    with pytest.raises((ConfigError, ValueError)):
        mgr.load_config(fallback_on_error=False)

    # С fallback_on_error=True должен корректно восстановиться в defaults
    fallback_cfg = mgr.load_config(fallback_on_error=True)
    assert fallback_cfg.server_url == "http://127.0.0.1:8000"

    # 2. Невалидные значения полей (например отрицательный таймаут)
    cfg_file.write_text(json.dumps({"poll_interval_sec": -100}), encoding="utf-8")
    with pytest.raises((ConfigError, ValueError)):
        mgr.load_config(fallback_on_error=False)


def test_config_manager_callbacks(tmp_path):
    """Проверка уведомления слушателей при изменении конфигурации."""
    cfg_file = tmp_path / "config.json"
    mgr = ConfigManager(cfg_file)

    events = []

    def on_change(cfg: ClientConfig):
        events.append(cfg.server_url)

    mgr.add_change_listener(on_change)

    # 1. Вызов save_config приводит к уведомлению
    mgr.save_config(ClientConfig(server_url="http://node1:8000"))
    assert len(events) == 1
    assert events[-1] == "http://node1:8000"

    # 2. Вызов save_config еще раз
    mgr.save_config(ClientConfig(server_url="http://node2:8000"))
    assert len(events) == 2
    assert events[-1] == "http://node2:8000"

    # 3. Отписка от событий
    mgr.remove_change_listener(on_change)
    mgr.save_config(ClientConfig(server_url="http://node3:8000"))
    assert len(events) == 2  # Не изменилось


# ============================================================================
# Тесты BuildInfo и common/build_info
# ============================================================================

def test_build_info_generation():
    """Проверка генерации метаданных сборки с реальными параметрами среды."""
    info = get_build_info()

    assert info.app_name == "Secure Chat (СТБ 34.101.45/31/47)"
    assert info.version == "2.1.0-STB"
    assert isinstance(info.build_number, int)
    assert len(info.build_date) > 0
    assert len(info.python_version) > 0
    assert len(info.platform) > 0
    assert len(info.crypto_engine) > 0

    # Проверка списка стандартов
    for std in DEFAULT_STB_STANDARDS:
        assert std in info.stb_standards


def test_git_fallback_handling():
    """Проверка безопасной работы при отсутствии Git-репозитория или ошибках."""
    # 1. Принудительный сбой вызова git rev-parse (например, каталог не под git)
    with patch("subprocess.run", side_effect=subprocess.CalledProcessError(1, "git")):
        with patch.dict(os.environ, {}, clear=True):
            commit = _detect_git_commit()
            branch = _detect_git_branch()
            assert commit == "unknown"
            assert branch == "unknown"

    # 2. Отсутствие установленной утилиты git (FileNotFoundError)
    with patch("subprocess.run", side_effect=FileNotFoundError("git not found")):
        with patch.dict(os.environ, {}, clear=True):
            commit = _detect_git_commit()
            branch = _detect_git_branch()
            assert commit == "unknown"
            assert branch == "unknown"

    # 3. Чтение переменных окружения GIT_COMMIT и GIT_BRANCH
    with patch.dict(os.environ, {"GIT_COMMIT": "abc1234", "GIT_BRANCH": "feature/stb"}):
        commit = _detect_git_commit()
        branch = _detect_git_branch()
        assert commit == "abc1234"
        assert branch == "feature/stb"

    # 4. Успешный запуск git (имитация вызова)
    mock_res = MagicMock()
    mock_res.stdout = "fedcba9\n"
    with patch("subprocess.run", return_value=mock_res):
        with patch.dict(os.environ, {}, clear=True):
            commit = _detect_git_commit()
            assert commit == "fedcba9"


def test_crypto_engine_detection():
    """Проверка корректной детекции статуса криптодвижка."""
    # 1. При явном отсутствии bee2.dll активируется сертифицированный fallback
    with patch("client.crypto.bee2_wrapper._find_bee2_library", return_value=None):
        engine_name = _detect_crypto_engine()
        assert "Fallback Software Engine" in engine_name

    # 2. Имитация обнаружения библиотеки bee2.dll
    with patch("client.crypto.bee2_wrapper._find_bee2_library", return_value=Path("C:/lib/bee2.dll")):
        with patch.object(Path, "is_file", return_value=True):
            detected = _detect_crypto_engine()
            assert "Bee2 Native C-FFI" in detected

    # 3. Переопределение через переменную окружения
    with patch.dict(os.environ, {"SECURE_CHAT_CRYPTO_ENGINE": "Custom Test Engine"}):
        assert _detect_crypto_engine() == "Custom Test Engine"


def test_generate_build_metadata(tmp_path):
    """Проверка экспорта метаданных сборки в JSON-файл."""
    meta_file = tmp_path / "build_info.json"
    data = generate_build_metadata(str(meta_file))

    assert meta_file.is_file()
    assert data["app_name"] == "Secure Chat (СТБ 34.101.45/31/47)"
    assert data["version"] == "2.1.0-STB"
    assert "stb_standards" in data
    assert len(data["stb_standards"]) == 4

    saved = json.loads(meta_file.read_text(encoding="utf-8"))
    assert saved["version"] == "2.1.0-STB"


def test_format_build_summary():
    """Проверка текстовой сводки информации о сборке."""
    summary = format_build_summary()
    assert "Secure Chat (СТБ 34.101.45/31/47)" in summary
    assert "2.1.0-STB" in summary
    assert "СТБ 34.101.45-2013" in summary
    assert "СТБ 34.101.31-2011" in summary


# ============================================================================
# Тесты REST API эндпоинта GET /version
# ============================================================================

def test_api_version_endpoint():
    """Проверка эндпоинта сервера GET /version."""
    client = TestClient(app)
    resp = client.get("/version")

    assert resp.status_code == 200
    data = resp.json()

    assert data["app_name"] == "Secure Chat (СТБ 34.101.45/31/47)"
    assert data["version"] == "2.1.0-STB"
    assert isinstance(data["build_number"], int)
    assert len(data["stb_standards"]) == 4
    assert "СТБ 34.101.45-2013 (bign)" in data["stb_standards"]
    assert "СТБ 34.101.31-2011 (belt-che)" in data["stb_standards"]
    assert "СТБ 34.101.47-2017 (bash256)" in data["stb_standards"]
    assert "СТБ 34.101.78-2017 (belt-kwp)" in data["stb_standards"]
    assert "crypto_engine" in data
