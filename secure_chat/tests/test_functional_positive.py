"""
Позитивные функциональные тесты защищенного мессенджера «Secure Chat».
Практическая работа «Тестирование разрабатываемого ПО».

Набор тестов:
  * test_login_positive: успешная регистрация и вход пользователя;
  * test_key_generation_and_export_positive: генерация ключевой пары bign и сохранение контейнеров bkey;
  * test_belt_che_encryption_roundtrip: корректное сквозное шифрование и дешифрование сообщений (belt-che);
  * test_bign_signature_positive: выработка и успешная проверка ЭЦП;
  * test_message_send_and_pop_positive: успешная отправка сообщения адресату через очередь сервера и его извлечение (pop);
  * test_updater_signature_verification_positive: корректная валидация подписанного манифеста обновления Ed25519.
"""

import base64
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from server.app import app
from server.database import DatabaseManager
from server.storage import storage
from client.crypto.belt import BeltCrypto
from client.crypto.bign import BignCrypto, BignKeyPair
from client.crypto.hybrid import HybridCrypto
from client.crypto.keystore import KeyStore
from common.update_crypto import generate_keypair, sign_manifest, verify_manifest


@pytest.fixture
def temp_db(tmp_path):
    """Изолированная тестовая база данных SQLite и чистое состояние хранилища."""
    orig_db = storage.db
    db_file = str(tmp_path / "test_positive.db")
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


def test_login_positive(test_client):
    """
    Позитивный тест аутентификации:
    1. Успешная регистрация пользователя с открытым ключом bign и отпечатком устройства.
    2. Успешный вход в систему с выдачей сессионного Bearer-токена.
    3. Подтверждение активной сессии через запрос GET /me.
    """
    kp = BignCrypto.generate_keypair()
    username = "alice_positive"
    password = "CorrectStrongPass_2026!"
    device_id = "test-device-uuid-positive-01"

    # 1. Регистрация нового пользователя
    reg_resp = test_client.post(
        "/register",
        json={
            "login": username,
            "password": password,
            "public_key": kp.public_hex,
            "device_id": device_id,
        },
    )
    assert reg_resp.status_code == 200, f"Ошибка регистрации: {reg_resp.text}"
    reg_data = reg_resp.json()
    assert reg_data["success"] is True
    assert reg_data["user_id"] == username
    assert reg_data["public_key"] == kp.public_hex
    assert reg_data["device_id"] == device_id

    # 2. Успешный вход пользователя
    login_resp = test_client.post(
        "/login",
        json={
            "login": username,
            "password": password,
            "device_id": device_id,
        },
    )
    assert login_resp.status_code == 200, f"Ошибка входа: {login_resp.text}"
    login_data = login_resp.json()
    assert "token" in login_data
    assert len(login_data["token"]) == 64  # SHA-256 токен сессии
    assert login_data["token_type"].lower() == "bearer"
    assert login_data["user_id"] == username
    assert login_data["public_key"] == kp.public_hex
    assert login_data["device_id"] == device_id

    # 3. Доступ к защищенному профилю GET /me по выданному токену
    token = login_data["token"]
    me_resp = test_client.get(
        "/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert me_resp.status_code == 200
    me_data = me_resp.json()
    assert me_data["user_id"] == username
    assert me_data["public_key"] == kp.public_hex
    assert me_data["device_id"] == device_id
    assert me_data["status"] == "active"


def test_key_generation_and_export_positive(tmp_path):
    """
    Позитивный тест генерации ключевой пары bign (СТБ 34.101.45-2013)
    и сохранения контейнеров bkey (СТБ 34.101.78-2017) с парольной защитой belt-kwp.
    """
    username = "bob_key_user"
    password = "KeyProtectionPassword123!"

    # 1. Генерация асимметричной ключевой пары
    kp = BignCrypto.generate_keypair()
    assert isinstance(kp, BignKeyPair)
    assert len(kp.private_key) == 32  # 256 бит закрытый ключ
    assert len(kp.public_key) == 64   # 512 бит открытый ключ (X, Y)
    assert len(kp.public_hex) == 128
    assert len(kp.private_hex) == 64

    # 2. Экспорт и сохранение контейнеров в каталог
    pub_file, priv_file = KeyStore.save_keys(
        target_dir=tmp_path,
        keypair=kp,
        password=password,
        username=username,
    )

    assert pub_file.is_file(), f"Файл открытого ключа не найден: {pub_file}"
    assert priv_file.is_file(), f"Файл закрытого ключа не найден: {priv_file}"
    assert pub_file.name == f"{username}_public.bkey"
    assert priv_file.name == f"{username}_private.bkey"

    # 3. Проверка формата содержимого файлов
    pub_bytes = pub_file.read_bytes()
    assert pub_bytes.startswith(b"BKEY_PUB_V1\n")
    assert f"USER:{username}".encode("utf-8") in pub_bytes

    priv_bytes = priv_file.read_bytes()
    assert priv_bytes.startswith(b"BKEY_META_V1\n")
    assert b"BKEY_STB78_V1" in priv_bytes

    # 4. Успешный импорт открытого и закрытого ключей
    loaded_pub = KeyStore.load_public_key(pub_file, expected_username=username)
    assert loaded_pub == kp.public_key

    loaded_priv = KeyStore.load_private_key(priv_file, password=password, expected_username=username)
    assert loaded_priv == kp.private_key

    # Полная загрузка пары через KeyStore.load_keys
    loaded_pair = KeyStore.load_keys(tmp_path, password=password, expected_username=username)
    assert loaded_pair.public_key == kp.public_key
    assert loaded_pair.private_key == kp.private_key


def test_belt_che_encryption_roundtrip():
    """
    Позитивный тест симметричного блочного шифрования и имитозащиты Belt
    в режиме аутентифицированного шифрования belt-che (СТБ 34.101.31-2011).
    """
    # 1. Генерация 256-битного ключа и 128-битного вектора IV
    key = BeltCrypto.generate_key()
    iv = BeltCrypto.generate_iv()
    assert len(key) == 32
    assert len(iv) == 16

    original_message = "Безопасная передача данных по протоколу СТБ 34.101.31-2011 belt-che!".encode("utf-8")

    # 2. Аутентифицированное шифрование
    ciphertext, mac, used_iv = BeltCrypto.encrypt(original_message, key, iv=iv)

    assert used_iv == iv
    assert len(ciphertext) == len(original_message)
    assert len(mac) == 16  # 128-битная имитовставка
    assert ciphertext != original_message

    # 3. Дешифрование и проверка целостности имитовставки
    decrypted = BeltCrypto.decrypt(ciphertext, mac, key, used_iv)
    assert decrypted == original_message

    # 4. Проверка с автоматически сгенерированным IV
    ct2, mac2, iv2 = BeltCrypto.encrypt(original_message, key)
    assert len(iv2) == 16
    assert BeltCrypto.decrypt(ct2, mac2, key, iv2) == original_message


def test_bign_signature_positive():
    """
    Позитивный тест выработки и проверки электронной цифровой подписи (ЭЦП)
    по стандарту СТБ 34.101.45-2013 на эллиптических кривых.
    """
    kp = BignCrypto.generate_keypair()
    document = "Приказ об утверждении регламента защищенного обмена сообщениями 2026.".encode("utf-8")

    # 1. Формирование ЭЦП закрытым ключом
    signature = BignCrypto.sign(document, kp.private_key)
    assert isinstance(signature, bytes)
    assert len(signature) == 64  # 512 бит (2 x 256-битные координаты r, s)

    # 2. Проверка ЭЦП открытым ключом автора
    is_valid = BignCrypto.verify(document, signature, kp.public_key)
    assert is_valid is True, "Верификация корректной ЭЦП должна завершиться успешно"


def test_message_send_and_pop_positive(test_client):
    """
    Позитивный тест сквозной отправки сообщения адресату через очередь сервера
    и его деструктивного извлечения (POP).
    """
    alice_kp = BignCrypto.generate_keypair()
    bob_kp = BignCrypto.generate_keypair()

    # 1. Регистрация Алисы и Боба
    test_client.post(
        "/register",
        json={"login": "alice_sender", "public_key": alice_kp.public_hex, "password": "SenderPass123!"},
    )
    test_client.post(
        "/register",
        json={"login": "bob_receiver", "public_key": bob_kp.public_hex, "password": "ReceiverPass123!"},
    )

    # 2. Формирование зашифрованного сообщения через HybridCrypto
    raw_text = "Секретная директива: провести аудит безопасности узла №42."
    payload, signature = HybridCrypto.encrypt_message(
        plaintext=raw_text,
        recipient_pubkey=bob_kp.public_key,
        sender_privkey=alice_kp.private_key,
    )

    packet = {
        "from_id": "alice_sender",
        "to_id": "bob_receiver",
        "ciphertext": base64.b64encode(payload.ciphertext).decode("ascii"),
        "nonce": base64.b64encode(payload.nonce).decode("ascii"),
        "mac": base64.b64encode(payload.mac).decode("ascii"),
        "encrypted_key": base64.b64encode(payload.encrypted_key).decode("ascii"),
        "signature": base64.b64encode(signature).decode("ascii"),
    }

    # 3. Отправка сообщения на сервер
    send_resp = test_client.post("/send", json=packet)
    assert send_resp.status_code == 200
    assert send_resp.json()["status"] == "delivered"

    # 4. Извлечение входящего сообщения получателем (POP)
    inbox_resp = test_client.get("/inbox/bob_receiver")
    assert inbox_resp.status_code == 200
    messages = inbox_resp.json()
    assert len(messages) == 1
    received = messages[0]
    assert received["from_id"] == "alice_sender"
    assert received["ciphertext"] == packet["ciphertext"]
    assert received["nonce"] == packet["nonce"]
    assert received["mac"] == packet["mac"]

    # 5. Проверка деструктивности (очередь очищена после извлечения)
    inbox_empty_resp = test_client.get("/inbox/bob_receiver")
    assert inbox_empty_resp.status_code == 200
    assert len(inbox_empty_resp.json()) == 0

    # 6. Успешное расшифрование полученного сообщения Бобом
    rec_payload = HybridCrypto.decrypt_message(
        payload=payload,
        recipient_privkey=bob_kp.private_key,
        sender_pubkey=alice_kp.public_key,
        signature=signature,
    )
    decrypted_text, is_sig_valid = rec_payload
    assert decrypted_text == raw_text
    assert is_sig_valid is True


def test_updater_signature_verification_positive():
    """
    Позитивный тест валидации цифровой подписи Ed25519 манифеста обновления ПО.
    """
    priv_key, pub_key = generate_keypair()

    manifest = {
        "version": "2.2.0",
        "min_supported": "1.0.0",
        "os": "windows",
        "arch": "x64",
        "package_sha256": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
    }

    # 1. Подписание манифеста закрытым ключом релиза
    signed_manifest = sign_manifest(manifest, private_key=priv_key)
    assert "signature" in signed_manifest
    assert isinstance(signed_manifest["signature"], str)

    # 2. Успешная валидация открытым ключом релиза
    is_valid = verify_manifest(signed_manifest, public_key=pub_key)
    assert is_valid is True, "Подписанный манифест должен успешно проходить проверку Ed25519"
