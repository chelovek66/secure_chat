"""
Тесты модуля контроля целостности и подлинности ПО (common/integrity.py).
Проверяют алгоритмы ЭЦП bign-sign (СТБ 34.101.45-2013) и bash256 (СТБ 34.101.47-2017).
"""

import json
from pathlib import Path
import pytest

from common.integrity import SoftwareIntegrityManager, IntegrityReport
from client.crypto.bign import BignCrypto


@pytest.fixture
def temp_project(tmp_path: Path):
    """Создает временное дерево проекта с защищенными файлами."""
    client_dir = tmp_path / "client"
    client_dir.mkdir(parents=True)
    (client_dir / "app.py").write_text("print('Secure Chat App')", encoding="utf-8")
    (client_dir / "styles.json").write_text('{"theme": "dark"}', encoding="utf-8")

    server_dir = tmp_path / "server"
    server_dir.mkdir(parents=True)
    (server_dir / "main.py").write_text("# Server entrypoint", encoding="utf-8")

    common_dir = tmp_path / "common"
    common_dir.mkdir(parents=True)
    (common_dir / "utils.py").write_text("def helper(): pass", encoding="utf-8")

    return tmp_path


def test_manifest_generation_and_valid_verification(temp_project: Path):
    manager = SoftwareIntegrityManager(root_dir=temp_project)
    dev_kp = manager.get_or_create_developer_keys()

    # Генерация манифеста
    manifest = manager.generate_manifest(dev_kp)
    assert manifest["format_version"] == "1.0-STB"
    assert manifest["files_count"] == 4
    assert len(manifest["signature_hex"]) == 128  # 64 байта в hex

    # Сохранение манифеста
    saved_path = manager.save_manifest(manifest)
    assert saved_path.is_file()

    # Проверка целостности и ЭЦП
    report: IntegrityReport = manager.verify_integrity()
    assert report.is_valid is True
    assert report.signature_verified is True
    assert report.status == "AUTHENTIC_AND_INTACT"
    assert report.total_files_checked == 4
    assert len(report.tampered_files) == 0
    assert len(report.missing_files) == 0


def test_tamper_detection(temp_project: Path):
    manager = SoftwareIntegrityManager(root_dir=temp_project)
    dev_kp = manager.get_or_create_developer_keys()

    manifest = manager.generate_manifest(dev_kp)
    manager.save_manifest(manifest)

    # Симулируем вмешательство злоумышленника в файл
    target_file = temp_project / "client" / "app.py"
    target_file.write_text("print('TAMPERED BY ATTACKER!')", encoding="utf-8")

    # Проверка должна обнаружить факт модификации
    report = manager.verify_integrity()
    assert report.is_valid is False
    assert report.signature_verified is True  # ЭЦП манифеста верна, но файл изменен!
    assert report.status == "TAMPERED"
    assert len(report.tampered_files) == 1
    assert report.tampered_files[0]["rel_path"] == "client/app.py"


def test_invalid_signature_detection(temp_project: Path):
    manager = SoftwareIntegrityManager(root_dir=temp_project)
    dev_kp = manager.get_or_create_developer_keys()

    manifest = manager.generate_manifest(dev_kp)
    # Злоумышленник подменяет ЭЦП в манифесте
    manifest["signature_hex"] = "aa" * 64
    manager.save_manifest(manifest)

    report = manager.verify_integrity()
    assert report.is_valid is False
    assert report.signature_verified is False
    assert report.status == "SIGNATURE_INVALID"


def test_missing_file_detection(temp_project: Path):
    manager = SoftwareIntegrityManager(root_dir=temp_project)
    dev_kp = manager.get_or_create_developer_keys()

    manifest = manager.generate_manifest(dev_kp)
    manager.save_manifest(manifest)

    # Удаляем один из файлов
    (temp_project / "common" / "utils.py").unlink()

    report = manager.verify_integrity()
    assert report.is_valid is False
    assert report.status == "MISSING_FILES"
    assert "common/utils.py" in report.missing_files
