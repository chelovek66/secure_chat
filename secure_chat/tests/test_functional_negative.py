"""
Негативные функциональные тесты защищенного мессенджера «Secure Chat».
Практическая работа «Тестирование разрабатываемого ПО».

Набор тестов:
  * test_login_invalid_password: отказ при неверном пароле (HTTP 401);
  * test_login_nonexistent_user: отказ при несуществующем логине;
  * test_login_lockout_after_5_failed_attempts: блокировка учетной записи после 5 неверных паролей, отказ на 6-й попытке;
  * test_device_fingerprint_mismatch: отказ HTTP 403 при входе с незнакомого устройства;
  * test_tampered_ciphertext_detection: обнаружение подмены шифротекста (BeltIntegrityError);
  * test_tampered_signature_detection: обнаружение поддельной ЭЦП (is_valid_sig is False);
  * test_tampered_update_manifest_rejected: манифест обновления с поврежденной подписью Ed25519 отклоняется;
  * test_tampered_update_package_rejected: архив обновления с несоответствующим хэшем SHA-256 отклоняется.
"""

import json
import zipfile
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from server.app import app
from server.database import DatabaseManager
from server.storage import storage
from client.crypto.belt import BeltCrypto, BeltIntegrityError
from client.crypto.bign import BignCrypto
from client.crypto.hybrid import HybridCrypto
from client.updater import (
    Updater,
    FileSource,
    SignatureVerificationError,
    ChecksumMismatchError,
)
from common.update_crypto import (
    generate_keypair,
    sign_manifest,
    verify_manifest,
    calculate_sha256,
    verify_sha256,
)


@pytest.fixture
def temp_db(tmp_path):
    """Изолированная тестовая база данных SQLite и чистое состояние хранилища."""
    orig_db = storage.db
    db_file = str(tmp_path / "test_negative.db")
    db = DatabaseManager(db_path=db_file, enabled=True)
    storage.db = db
    storage.reset()
    yield db
    storage.reset()
    storage.db = orig_db


@pytest.fixture
def test_client(temp_db):
    """Автономный клиент FastAPI TestClient с изолированной БД."""
    with TestClient(app) as client:
        yield client


def test_login_invalid_password(test_client):
    """
    Негативный тест: отказ при вводе неверного пароля (HTTP 401 Unauthorized).
    """
    kp = BignCrypto.generate_keypair()
    username = "victim_user"
    correct_pass = "CorrectPassword123!"
    wrong_pass = "TotallyWrongPassword999!"
    device_id = "device-neg-01"

    # Регистрация
    reg_resp = test_client.post(
        "/register",
        json={
            "login": username,
            "password": correct_pass,
            "public_key": kp.public_hex,
            "device_id": device_id,
        },
    )
    assert reg_resp.status_code == 200

    # Попытка входа с некорректным паролем
    login_resp = test_client.post(
        "/login",
        json={
            "login": username,
            "password": wrong_pass,
            "device_id": device_id,
        },
    )
    assert login_resp.status_code == 401
    detail = login_resp.json()["detail"].lower()
    assert "неверный пароль" in detail


def test_login_nonexistent_user(test_client):
    """
    Негативный тест: отказ при попытке входа несуществующего пользователя (HTTP 401 Unauthorized).
    """
    login_resp = test_client.post(
        "/login",
        json={
            "login": "phantom_ghost_nonexistent",
            "password": "SomePassword123!",
            "device_id": "random-device-id",
        },
    )
    assert login_resp.status_code == 401
    detail = login_resp.json()["detail"].lower()
    assert "не найден" in detail


def test_login_lockout_after_5_failed_attempts(test_client):
    """
    Негативный тест: при 5 последовательных неверных паролях учетная запись блокируется.
    Шестая попытка (даже с правильным паролем) отклоняется со статусом 423 Locked
    и сообщением о блокировке.
    """
    kp = BignCrypto.generate_keypair()
    username = "lockout_target"
    correct_pass = "TargetSuperSecret2026!"
    wrong_pass = "BadPassAttempt!"
    device_id = "device-lockout-test"

    # Регистрация
    reg_resp = test_client.post(
        "/register",
        json={
            "login": username,
            "password": correct_pass,
            "public_key": kp.public_hex,
            "device_id": device_id,
        },
    )
    assert reg_resp.status_code == 200

    # Попытки 1-4: неудачные попытки с уменьшением счетчика
    for attempt in range(1, 5):
        resp = test_client.post(
            "/login",
            json={"login": username, "password": wrong_pass, "device_id": device_id},
        )
        assert resp.status_code == 401
        assert f"осталось попыток: {5 - attempt}" in resp.json()["detail"].lower()

    # Попытка 5: пятая ошибка приводит к блокировке аккаунта
    resp5 = test_client.post(
        "/login",
        json={"login": username, "password": wrong_pass, "device_id": device_id},
    )
    assert resp5.status_code in (401, 423)
    assert "заблокирован" in resp5.json()["detail"].lower()

    # Попытка 6: учетная запись заблокирована, вход отклоняется даже с верным паролем
    resp6 = test_client.post(
        "/login",
        json={"login": username, "password": correct_pass, "device_id": device_id},
    )
    assert resp6.status_code == 423  # HTTP 423 Locked
    detail6 = resp6.json()["detail"].lower()
    assert "заблокирован" in detail6 or "превышено максимальное число попыток" in detail6


def test_device_fingerprint_mismatch(test_client):
    """
    Негативный тест: вход с чужого / несовпадающего device_id возвращает отказ
    (HTTP 403 Forbidden «Вход с незнакомого устройства»).
    """
    kp = BignCrypto.generate_keypair()
    username = "fingerprint_user"
    password = "UserValidPassword2026!"
    trusted_device_id = "legitimate-workstation-sha256-uuid"
    alien_device_id = "attacker-machine-sha256-uuid"

    # Регистрация на доверенном устройстве
    reg_resp = test_client.post(
        "/register",
        json={
            "login": username,
            "password": password,
            "public_key": kp.public_hex,
            "device_id": trusted_device_id,
        },
    )
    assert reg_resp.status_code == 200

    # Попытка входа с верным паролем, но с неизвестного устройства
    login_resp = test_client.post(
        "/login",
        json={
            "login": username,
            "password": password,
            "device_id": alien_device_id,
        },
    )
    assert login_resp.status_code == 403
    assert "вход с незнакомого устройства" in login_resp.json()["detail"].lower()


def test_tampered_ciphertext_detection():
    """
    Негативный тест имитозащиты Belt (СТБ 34.101.31-2011 belt-che):
    модификация хотя бы одного бита шифротекста или имитовставки
    вызывает исключение BeltIntegrityError.
    """
    key = BeltCrypto.generate_key()
    original_data = b"Confidential banking message: transfer 100 BYN."

    ciphertext, mac, iv = BeltCrypto.encrypt(original_data, key)

    # 1. Подмена байта в шифротексте
    corrupted_ciphertext = bytearray(ciphertext)
    corrupted_ciphertext[0] ^= 0x01
    with pytest.raises(BeltIntegrityError):
        BeltCrypto.decrypt(bytes(corrupted_ciphertext), mac, key, iv)

    # 2. Подмена байта в имитовставке MAC
    corrupted_mac = bytearray(mac)
    corrupted_mac[0] ^= 0xFF
    with pytest.raises(BeltIntegrityError):
        BeltCrypto.decrypt(ciphertext, bytes(corrupted_mac), key, iv)

    # 3. Использование чужого ключа
    alien_key = BeltCrypto.generate_key()
    with pytest.raises(BeltIntegrityError):
        BeltCrypto.decrypt(ciphertext, mac, alien_key, iv)


def test_tampered_signature_detection():
    """
    Негативный тест ЭЦП Bign (СТБ 34.101.45-2013):
    обнаружение подделки документа, повреждения подписи или проверки на чужом ключе.
    """
    alice_kp = BignCrypto.generate_keypair()
    mallory_kp = BignCrypto.generate_keypair()

    original_doc = b"Contract terms: payment 500 BYN."
    tampered_doc = b"Contract terms: payment 50000 BYN."

    signature = BignCrypto.sign(original_doc, alice_kp.private_key)

    # 1. Проверка ЭЦП на модифицированном документе
    is_valid_modified = BignCrypto.verify(tampered_doc, signature, alice_kp.public_key)
    assert is_valid_modified is False

    # 2. Проверка поврежденной подписи
    corrupted_sig = bytearray(signature)
    corrupted_sig[10] ^= 0xAA
    is_valid_corrupted = BignCrypto.verify(original_doc, bytes(corrupted_sig), alice_kp.public_key)
    assert is_valid_corrupted is False

    # 3. Проверка на чужом открытом ключе
    is_valid_alien_key = BignCrypto.verify(original_doc, signature, mallory_kp.public_key)
    assert is_valid_alien_key is False

    # 4. Проверка через высокоуровневый HybridCrypto.decrypt_message
    payload, valid_sig = HybridCrypto.encrypt_message(
        plaintext="Test message",
        recipient_pubkey=mallory_kp.public_key,
        sender_privkey=alice_kp.private_key,
    )
    fake_sig = bytes(corrupted_sig)
    _, is_sig_valid = HybridCrypto.decrypt_message(
        payload=payload,
        recipient_privkey=mallory_kp.private_key,
        sender_pubkey=alice_kp.public_key,
        signature=fake_sig,
    )
    assert is_sig_valid is False


def test_tampered_update_manifest_rejected(tmp_path):
    """
    Негативный тест системы обновлений:
    манифест с поддельной/поврежденной цифровой подписью Ed25519 отклоняется
    (verify_manifest -> False, Updater -> SignatureVerificationError).
    """
    priv_key, pub_key = generate_keypair()
    alien_priv, alien_pub = generate_keypair()

    app_dir = tmp_path / "app"
    app_dir.mkdir()
    (app_dir / "main.py").write_text("print('v1.0')", encoding="utf-8")

    manifest = {
        "version": "2.3.0",
        "min_supported": "1.0.0",
        "os": "windows",
        "arch": "x64",
        "package_url": "package.zip",
        "package_sha256": "1122334455667788990011223344556677889900112233445566778899001122",
    }

    signed_manifest = sign_manifest(manifest, private_key=priv_key)

    # 1. Подмена содержимого манифеста при сохранении оригинальной подписи
    tampered_manifest = dict(signed_manifest)
    tampered_manifest["version"] = "9.9.9"
    assert verify_manifest(tampered_manifest, public_key=pub_key) is False

    # 2. Повреждение значения самой подписи
    corrupted_sig_manifest = dict(signed_manifest)
    corrupted_sig_manifest["signature"] = "AA" * 64
    assert verify_manifest(corrupted_sig_manifest, public_key=pub_key) is False

    # 3. Подписание чужим ключом
    signed_by_alien = sign_manifest(manifest, private_key=alien_priv)
    assert verify_manifest(signed_by_alien, public_key=pub_key) is False

    # 4. Проверка отклонения в клиенте Updater
    man_file = tmp_path / "manifest.json"
    man_file.write_text(json.dumps(tampered_manifest), encoding="utf-8")

    updater = Updater(
        source=FileSource(man_file),
        current_version="1.0.0",
        app_dir=app_dir,
        public_key=pub_key,
    )
    with pytest.raises(SignatureVerificationError):
        updater.run_update()


def test_tampered_update_package_rejected(tmp_path):
    """
    Негативный тест системы обновлений:
    архив обновления с несоответствующим хэшем SHA-256 отклоняется
    (verify_sha256 -> False, Updater -> ChecksumMismatchError).
    """
    priv_key, pub_key = generate_keypair()

    app_dir = tmp_path / "app"
    app_dir.mkdir()
    (app_dir / "main.py").write_text("print('v1.0')", encoding="utf-8")

    # Создание zip-пакета
    pkg_path = tmp_path / "package.zip"
    with zipfile.ZipFile(pkg_path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("main.py", "print('v2.3')")

    actual_sha = calculate_sha256(pkg_path)
    fake_sha = "0" * 64

    # 1. Проверка функции verify_sha256
    assert verify_sha256(pkg_path, actual_sha) is True
    assert verify_sha256(pkg_path, fake_sha) is False

    # 2. Попытка обновления с несовпадающим хэшем через Updater
    manifest = {
        "version": "2.3.0",
        "min_supported": "1.0.0",
        "os": "windows",
        "arch": "x64",
        "package_url": "package.zip",
        "package_sha256": fake_sha,  # Поддельный хэш в манифесте
    }
    signed_manifest = sign_manifest(manifest, private_key=priv_key)
    man_file = tmp_path / "manifest.json"
    man_file.write_text(json.dumps(signed_manifest), encoding="utf-8")

    updater = Updater(
        source=FileSource(man_file),
        current_version="1.0.0",
        app_dir=app_dir,
        public_key=pub_key,
    )

    with pytest.raises(ChecksumMismatchError):
        updater.run_update()
