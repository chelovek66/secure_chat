"""
Набор тестов для ПЗ-4: «Механизм безопасного обновления ПО (подкачка приложений и обновлений)».
Проверяет:
  1. Верификацию цифровой подписи манифеста Ed25519 (валидная / подмененная / поврежденная);
  2. Контроль целостности пакета по хэшу SHA-256 (корректный / искаженный);
  3. Верификацию SBOM CycloneDX 1.5 и фиксацию статуса sbom_mismatch;
  4. Блокировку обновления при min_supported > current_version;
  5. Полный цикл успешного обновления (staging -> backup -> app swap);
  6. Автоматический откат (rollback) из backup/ при возникновении сбоев;
  7. Серверные REST-эндпоинты /updates/* (check, manifest, request_token, download, sbom, report).
"""

import hashlib
import json
import shutil
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from common.update_crypto import (
    calculate_sha256,
    generate_keypair,
    load_private_key,
    load_public_key,
    sign_manifest,
    validate_cyclonedx_sbom,
    verify_manifest,
    verify_sha256,
)
from client.updater import (
    ChecksumMismatchError,
    FileSource,
    HttpSource,
    MinSupportedVersionError,
    SbomMismatchError,
    SignatureVerificationError,
    Updater,
)
from server.app import app
from server.database import db_manager
from server.update_router import create_update_jwt, publish_release


@pytest.fixture(autouse=True)
def clean_db():
    """Очищает базу данных перед каждым тестом."""
    db_manager.clear_all()
    yield
    db_manager.clear_all()


def _make_sample_sbom() -> dict:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": "SecureClient",
                "version": "2.2.0",
            }
        },
        "components": [
            {
                "type": "library",
                "name": "cryptography",
                "version": "50.0.1",
                "purl": "pkg:pypi/cryptography@50.0.1",
            },
            {
                "type": "library",
                "name": "requests",
                "version": "2.32.0",
                "purl": "pkg:pypi/requests@2.32.0",
            },
        ],
    }


def _create_package_zip(pkg_path: Path, files: dict, sbom_dict: dict = None) -> str:
    """Создает тестовый zip-пакет и возвращает его sha256."""
    pkg_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(pkg_path, "w", zipfile.ZIP_DEFLATED) as z:
        for fname, content in files.items():
            z.writestr(fname, content)
        if sbom_dict is not None:
            z.writestr("sbom.json", json.dumps(sbom_dict, ensure_ascii=False))
    return calculate_sha256(pkg_path)


# ============================================================================
# 1. ТЕСТ: Проверка цифровой подписи манифеста Ed25519
# ============================================================================


def test_manifest_signature_verification():
    priv, pub = generate_keypair()

    manifest = {
        "version": "2.2.0",
        "min_supported": "1.0.0",
        "os": "windows",
        "arch": "x64",
        "package_sha256": "abcdef1234567890",
    }

    # 1.1 Валидная подпись
    signed = sign_manifest(manifest, private_key=priv)
    assert "signature" in signed
    assert verify_manifest(signed, public_key=pub) is True

    # 1.2 Подмена данных в манифесте
    tampered = dict(signed)
    tampered["version"] = "9.9.9"
    assert verify_manifest(tampered, public_key=pub) is False

    # 1.3 Поврежденная подпись
    corrupted_sig = dict(signed)
    corrupted_sig["signature"] = "AAAABBBBCCCC"
    assert verify_manifest(corrupted_sig, public_key=pub) is False

    # 1.4 Отсутствующая подпись
    unsigned = dict(manifest)
    assert verify_manifest(unsigned, public_key=pub) is False


# ============================================================================
# 2. ТЕСТ: Контроль целостности пакета по SHA-256
# ============================================================================


def test_package_sha256_verification(tmp_path):
    app_dir = tmp_path / "app"
    app_dir.mkdir()
    (app_dir / "main.py").write_text("print('v1.0')", encoding="utf-8")

    pkg_path = tmp_path / "package.zip"
    actual_sha = _create_package_zip(pkg_path, {"main.py": "print('v2.2')"})

    # Корректный SHA-256
    assert verify_sha256(pkg_path, actual_sha) is True

    # Поддельный хэш
    fake_sha = "0000000000000000000000000000000000000000000000000000000000000000"
    assert verify_sha256(pkg_path, fake_sha) is False

    # Updater должен выбросить ChecksumMismatchError
    manifest = {
        "version": "2.2.0",
        "min_supported": "1.0.0",
        "os": "windows",
        "arch": "x64",
        "package_url": "package.zip",
        "package_sha256": fake_sha,  # заведомо неверный хэш
    }
    signed_manifest = sign_manifest(manifest)
    man_file = tmp_path / "manifest.json"
    man_file.write_text(json.dumps(signed_manifest), encoding="utf-8")

    source = FileSource(man_file)
    updater = Updater(source=source, current_version="1.0.0", app_dir=app_dir)

    with pytest.raises(ChecksumMismatchError):
        updater.run_update()


# ============================================================================
# 3. ТЕСТ: Проверка SBOM (CycloneDX 1.5) и реакция на расхождение
# ============================================================================


def test_sbom_verification_and_mismatch(tmp_path):
    app_dir = tmp_path / "app"
    app_dir.mkdir()
    (app_dir / "main.py").write_text("print('v1.0')", encoding="utf-8")

    sbom = _make_sample_sbom()
    valid_format, msg = validate_cyclonedx_sbom(sbom)
    assert valid_format is True

    # Невалидный SBOM
    bad_sbom = {"bomFormat": "UnknownFormat", "components": "not-a-list"}
    invalid_format, _ = validate_cyclonedx_sbom(bad_sbom)
    assert invalid_format is False

    # Создаем пакет со сломанным SBOM
    pkg_path = tmp_path / "package.zip"
    pkg_sha = _create_package_zip(pkg_path, {"main.py": "print('v2.2')"}, sbom_dict=bad_sbom)

    manifest = {
        "version": "2.2.0",
        "min_supported": "1.0.0",
        "os": "windows",
        "arch": "x64",
        "package_url": "package.zip",
        "package_sha256": pkg_sha,
        "sbom": {
            "format": "CycloneDX-1.5",
            "url": "sbom.json",
            "sha256": calculate_sha256(json.dumps(bad_sbom, ensure_ascii=False).encode("utf-8")),
        },
    }
    signed_manifest = sign_manifest(manifest)
    man_file = tmp_path / "manifest.json"
    man_file.write_text(json.dumps(signed_manifest), encoding="utf-8")

    source = FileSource(man_file)
    updater = Updater(source=source, current_version="1.0.0", app_dir=app_dir)

    with pytest.raises(SbomMismatchError):
        updater.run_update()


# ============================================================================
# 4. ТЕСТ: Блокировка обновления при min_supported > current_version
# ============================================================================


def test_min_supported_blocking(tmp_path):
    app_dir = tmp_path / "app"
    app_dir.mkdir()
    (app_dir / "main.py").write_text("print('v1.0')", encoding="utf-8")

    pkg_path = tmp_path / "package.zip"
    pkg_sha = _create_package_zip(pkg_path, {"main.py": "print('v3.0')"})

    manifest = {
        "version": "3.0.0",
        "min_supported": "2.0.0",  # Требуется минимум 2.0.0, а у клиента 1.0.0
        "os": "windows",
        "arch": "x64",
        "package_url": "package.zip",
        "package_sha256": pkg_sha,
    }
    signed_manifest = sign_manifest(manifest)
    man_file = tmp_path / "manifest.json"
    man_file.write_text(json.dumps(signed_manifest), encoding="utf-8")

    source = FileSource(man_file)
    updater = Updater(source=source, current_version="1.0.0", app_dir=app_dir)

    # Должен заблокировать обновление
    with pytest.raises((MinSupportedVersionError, ValueError)):
        updater.run_update()

    # Файлы приложения должны остаться нетронутыми
    assert (app_dir / "main.py").read_text(encoding="utf-8") == "print('v1.0')"


# ============================================================================
# 5. ТЕСТ: Успешный цикл обновления (staging -> backup -> app)
# ============================================================================


def test_successful_update_lifecycle(tmp_path):
    app_dir = tmp_path / "app"
    app_dir.mkdir()
    (app_dir / "main.py").write_text("print('v1.0-OLD')", encoding="utf-8")
    (app_dir / "config.txt").write_text("old_config", encoding="utf-8")

    sbom = _make_sample_sbom()
    sbom_bytes = json.dumps(sbom, ensure_ascii=False).encode("utf-8")
    sbom_sha = calculate_sha256(sbom_bytes)

    pkg_path = tmp_path / "package.zip"
    pkg_sha = _create_package_zip(
        pkg_path,
        {
            "main.py": "print('v2.2-NEW')",
            "new_feature.py": "print('feature')",
        },
        sbom_dict=sbom,
    )

    manifest = {
        "version": "2.2.0",
        "min_supported": "1.0.0",
        "os": "windows",
        "arch": "x64",
        "package_url": "package.zip",
        "package_sha256": pkg_sha,
        "sbom": {
            "format": "CycloneDX-1.5",
            "url": "sbom.json",
            "sha256": sbom_sha,
        },
    }
    signed_manifest = sign_manifest(manifest)
    man_file = tmp_path / "manifest.json"
    man_file.write_text(json.dumps(signed_manifest), encoding="utf-8")

    source = FileSource(man_file)
    updater = Updater(source=source, current_version="1.0.0", app_dir=app_dir)

    success = updater.run_update()
    assert success is True

    # Проверяем, что файлы в app_dir обновились
    assert (app_dir / "main.py").read_text(encoding="utf-8") == "print('v2.2-NEW')"
    assert (app_dir / "new_feature.py").is_file()
    assert (app_dir / "sbom.json").is_file()


# ============================================================================
# 6. ТЕСТ: Автоматический откат (rollback) из backup/ при сбое
# ============================================================================


def test_rollback_on_failure(tmp_path, monkeypatch):
    app_dir = tmp_path / "app"
    app_dir.mkdir()
    (app_dir / "main.py").write_text("print('STABLE_ORIGINAL')", encoding="utf-8")
    (app_dir / "database.db").write_text("SQLITE_ORIGINAL_DATA", encoding="utf-8")

    pkg_path = tmp_path / "package.zip"
    pkg_sha = _create_package_zip(pkg_path, {"main.py": "print('NEW_BROKEN')"})

    manifest = {
        "version": "2.2.0",
        "min_supported": "1.0.0",
        "os": "windows",
        "arch": "x64",
        "package_url": "package.zip",
        "package_sha256": pkg_sha,
    }
    signed_manifest = sign_manifest(manifest)
    man_file = tmp_path / "manifest.json"
    man_file.write_text(json.dumps(signed_manifest), encoding="utf-8")

    source = FileSource(man_file)
    updater = Updater(source=source, current_version="1.0.0", app_dir=app_dir)

    # Имитируем сбой во время шага распаковки / валидации после создания backup
    original_verify = updater._verify_sbom_step

    def mock_fail_step(m):
        # Имитируем падение с вызовом отката
        raise RuntimeError("Искусственный сбой во время обновления!")

    monkeypatch.setattr(updater, "_verify_sbom_step", mock_fail_step)

    # Запуск должен упасть с RuntimeError
    with pytest.raises(RuntimeError):
        updater.run_update()

    # Проверяем, что исходные файлы приложения восстановлены из backup/
    assert (app_dir / "main.py").read_text(encoding="utf-8") == "print('STABLE_ORIGINAL')"
    assert (app_dir / "database.db").read_text(encoding="utf-8") == "SQLITE_ORIGINAL_DATA"


# ============================================================================
# 7. ТЕСТ: Серверные REST-эндпоинты /updates/*
# ============================================================================


def test_server_updates_endpoints(tmp_path):
    client = TestClient(app)

    # 7.1 Генерация JWT-токена доступа
    jwt_token = create_update_jwt(user_id="test_admin", device_id="test_dev_01")
    headers = {"Authorization": f"Bearer {jwt_token}"}

    # 7.2 Публикация тестового релиза
    pkg_file = tmp_path / "SecureClient-2.5.0-win-x64.zip"
    sbom = _make_sample_sbom()
    pkg_sha = _create_package_zip(pkg_file, {"client.py": "print('v2.5.0')"}, sbom_dict=sbom)

    sbom_file = tmp_path / "sbom.json"
    sbom_file.write_text(json.dumps(sbom, ensure_ascii=False), encoding="utf-8")

    manifest = {
        "version": "2.5.0",
        "min_supported": "1.0.0",
        "os": "windows",
        "arch": "x64",
        "package_url": "/updates/download/2.5.0",
        "package_sha256": pkg_sha,
        "sbom": {
            "format": "CycloneDX-1.5",
            "url": "/updates/sbom/2.5.0.json",
            "sha256": calculate_sha256(sbom_file),
        },
    }
    signed_man = sign_manifest(manifest)
    man_file = tmp_path / "manifest.json"
    man_file.write_text(json.dumps(signed_man), encoding="utf-8")

    # Публикуем релиз
    pub_ok = publish_release(
        version="2.5.0",
        os_name="windows",
        arch="x64",
        package_path=str(pkg_file),
        manifest_path=str(man_file),
        sbom_path=str(sbom_file),
        package_sha256=pkg_sha,
        signature=signed_man["signature"],
    )
    assert pub_ok is True

    # 7.3 GET /updates/check
    resp = client.get("/updates/check?os=windows&arch=x64&version=1.0.0", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["update_available"] is True
    assert data["version"] == "2.5.0"
    assert data["manifest_url"] == "/updates/manifest/2.5.0"

    # Если уже установлена версия 2.5.0
    resp_same = client.get("/updates/check?os=windows&arch=x64&version=2.5.0", headers=headers)
    assert resp_same.status_code == 200
    assert resp_same.json()["update_available"] is False

    # 7.4 GET /updates/manifest/2.5.0
    resp_m = client.get("/updates/manifest/2.5.0", headers=headers)
    assert resp_m.status_code == 200
    m_data = resp_m.json()
    assert m_data["version"] == "2.5.0"
    assert "signature" in m_data
    assert verify_manifest(m_data) is True

    # 7.5 POST /updates/request_token -> выдача download_token
    resp_tok = client.post(
        "/updates/request_token",
        json={"version": "2.5.0", "device_id": "test_dev_01"},
        headers=headers,
    )
    assert resp_tok.status_code == 200
    dl_tok = resp_tok.json()["download_token"]
    assert len(dl_tok) > 10

    # 7.6 GET /updates/download/2.5.0 со скачиванием пакета
    # Попытка без download_token -> 403
    resp_no_tok = client.get("/updates/download/2.5.0", headers=headers)
    assert resp_no_tok.status_code == 403

    # Скачивание с валидным download_token
    resp_dl = client.get(f"/updates/download/2.5.0?token={dl_tok}", headers=headers)
    assert resp_dl.status_code == 200
    assert len(resp_dl.content) > 0

    # Повторная попытка с тем же токеном (одноразовый токен) -> 403
    resp_dl_again = client.get(f"/updates/download/2.5.0?token={dl_tok}", headers=headers)
    assert resp_dl_again.status_code == 403

    # 7.7 GET /updates/sbom/2.5.0.json
    resp_sbom = client.get("/updates/sbom/2.5.0.json", headers=headers)
    assert resp_sbom.status_code == 200
    sbom_data = resp_sbom.json()
    assert sbom_data["bomFormat"] == "CycloneDX"

    # 7.8 POST /updates/report
    report_payload = {
        "device_id": "test_dev_01",
        "from_version": "1.0.0",
        "to_version": "2.5.0",
        "status": "installed",
    }
    resp_rep = client.post("/updates/report", json=report_payload, headers=headers)
    assert resp_rep.status_code == 200

    # Проверяем запись в update_audit
    audit_logs = db_manager.get_update_audit_logs(limit=10)
    assert len(audit_logs) >= 1
    latest_audit = audit_logs[0]
    assert latest_audit["status"] == "installed"
    assert latest_audit["to_version"] == "2.5.0"
    assert latest_audit["device_id"] == "test_dev_01"
