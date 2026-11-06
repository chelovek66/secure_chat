"""
Комплексные тесты Практического занятия №3 (ПЗ-3):
«Аутентификация пользователей и привязка к устройству (Device Fingerprint)».

Проверяют:
  1. Вычисление Device Fingerprint стабильно и возвращает корректный SHA-256;
  2. Регистрация с PBKDF2-HMAC-SHA256 (200 000 итераций) и сохранение соли в БД;
  3. Вход с верным паролем и совпадающим device_id -> успех, выдача сессионного токена;
  4. Вход с неверным паролем -> отказ 401 Unauthorized;
  5. Вход с чужого / измененного device_id -> отказ 403 Forbidden («Вход с незнакомого устройства»);
  6. Проверка текущей сессии GET /me с Bearer токеном -> 200 OK;
  7. Выход POST /logout и последующий GET /me -> 401 Unauthorized;
  8. Интеграция с высокоуровневым ApiClient (хранение токена в ОЗУ, автопередача заголовка).
"""

import hashlib
import pytest
from fastapi.testclient import TestClient

from server.app import app
from server.database import DatabaseManager, hash_password_pbkdf2, verify_password_pbkdf2
from server.storage import storage
from client.crypto.bign import BignCrypto
from client.network.api_client import ApiClient, ApiClientError
from common.fingerprint import get_device_fingerprint, get_device_details


@pytest.fixture
def test_client(tmp_path):
    """Изолированная тестовая среда с временной базой данных SQLite."""
    orig_db = storage.db
    db_file = str(tmp_path / "test_pz3_auth.db")
    db = DatabaseManager(db_path=db_file, enabled=True)
    storage.db = db
    storage.reset()
    client = TestClient(app)
    yield client
    storage.reset()
    storage.db = orig_db


def test_fingerprint_calculation_stable_sha256():
    """Тест 1: Вычисление fingerprint стабильно и возвращает валидный SHA-256 хэш."""
    fp1 = get_device_fingerprint()
    fp2 = get_device_fingerprint()

    # Стабильность при повторном вызове
    assert fp1 == fp2, "Отпечаток устройства должен быть детерминированным"

    # Формат SHA-256 (64 hex символа)
    assert len(fp1) == 64, f"Длина хэша SHA-256 должна быть 64 символа, получено {len(fp1)}"
    assert int(fp1, 16) > 0, "Отпечаток должен являться валидной шестнадцатеричной строкой"

    # Детальная структура параметров
    details = get_device_details()
    assert "hostname" in details
    assert "platform" in details
    assert "mac" in details
    assert "machine_id" in details
    assert "raw_string" in details
    assert "device_id" in details

    # Проверка алгоритмической формулы: SHA256(hostname|platform|mac|machine_id)
    expected_raw = f"{details['hostname']}|{details['platform']}|{details['mac']}|{details['machine_id']}"
    assert details["raw_string"] == expected_raw
    assert hashlib.sha256(expected_raw.encode("utf-8")).hexdigest() == fp1


def test_pbkdf2_registration_and_salt_storage(test_client):
    """Тест 2: Регистрация с PBKDF2-HMAC-SHA256 (200 000 итераций) и сохранение соли в БД."""
    pwd = "Secr3t_P@ssword_2026!"
    digest, salt = hash_password_pbkdf2(pwd, iterations=200_000)

    assert len(salt) == 32  # 16 байт в hex
    assert len(digest) == 64  # 32 байта SHA-256 в hex
    assert verify_password_pbkdf2(pwd, salt, digest, iterations=200_000) is True
    assert verify_password_pbkdf2("Wrong_Pwd", salt, digest, iterations=200_000) is False

    # Регистрация через API
    kp = BignCrypto.generate_keypair()
    resp = test_client.post(
        "/register",
        json={
            "login": "agent_pz3_pbkdf2",
            "password": pwd,
            "public_key": kp.public_hex,
            "device_id": "test-device-uuid-001",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True
    assert data["user_id"] == "agent_pz3_pbkdf2"
    assert data["device_id"] == "test-device-uuid-001"

    # Проверка хранения соли и хэша в SQLite
    user_row = storage.db.get_user("agent_pz3_pbkdf2")
    assert user_row is not None
    assert user_row["device_id"] == "test-device-uuid-001"

    # Прямая проверка в БД
    raw_user = storage.db._conn.execute(
        "SELECT password_hash, password_salt, device_id FROM users WHERE user_id = ?",
        ("agent_pz3_pbkdf2",),
    ).fetchone()
    assert raw_user["password_hash"] is not None
    assert len(raw_user["password_hash"]) == 64
    assert raw_user["password_salt"] is not None
    assert len(raw_user["password_salt"]) == 32
    assert raw_user["device_id"] == "test-device-uuid-001"

    # Проверка совпадения хэша через PBKDF2
    assert verify_password_pbkdf2(pwd, raw_user["password_salt"], raw_user["password_hash"]) is True


def test_login_success_with_same_device_id(test_client):
    """Тест 3: Вход с правильным паролем и тем же device_id -> успех, выдача токена."""
    kp = BignCrypto.generate_keypair()
    pwd = "ValidPassword_2026!"
    device_id = "trusted-laptop-device-99"

    # 1. Регистрация
    reg = test_client.post(
        "/register",
        json={
            "login": "agent_alice",
            "password": pwd,
            "public_key": kp.public_hex,
            "device_id": device_id,
        },
    )
    assert reg.status_code == 200

    # 2. Успешный вход
    login_resp = test_client.post(
        "/login",
        json={
            "login": "agent_alice",
            "password": pwd,
            "device_id": device_id,
        },
    )
    assert login_resp.status_code == 200
    login_data = login_resp.json()
    assert "token" in login_data
    assert len(login_data["token"]) == 64
    assert login_data["token_type"].lower() == "bearer"
    assert login_data["user_id"] == "agent_alice"
    assert login_data["device_id"] == device_id
    assert login_data["public_key"] == kp.public_hex


def test_login_failure_wrong_password(test_client):
    """Тест 4: Вход с неправильным паролем -> отказ 401 Unauthorized."""
    kp = BignCrypto.generate_keypair()
    pwd = "CorrectPassword_123!"
    device_id = "device-dev-01"

    test_client.post(
        "/register",
        json={
            "login": "agent_bob",
            "password": pwd,
            "public_key": kp.public_hex,
            "device_id": device_id,
        },
    )

    # Попытка входа с ложным паролем
    resp = test_client.post(
        "/login",
        json={
            "login": "agent_bob",
            "password": "WrongPassword_999",
            "device_id": device_id,
        },
    )
    assert resp.status_code in (401, 400)
    assert "неверный пароль" in resp.json()["detail"].lower()


def test_login_failure_foreign_device_id_forbidden_403(test_client):
    """Тест 5: Вход с чужого / измененного device_id -> отказ 403 «Вход с незнакомого устройства»."""
    kp = BignCrypto.generate_keypair()
    pwd = "CorrectPassword_123!"
    trusted_device_id = "legitimate-workstation-sha256"
    attacker_device_id = "alien-attacker-device-sha256"

    # Регистрация на доверенном ПК
    test_client.post(
        "/register",
        json={
            "login": "agent_carol",
            "password": pwd,
            "public_key": kp.public_hex,
            "device_id": trusted_device_id,
        },
    )

    # Попытка входа с верным паролем, но с чужого устройства
    resp = test_client.post(
        "/login",
        json={
            "login": "agent_carol",
            "password": pwd,
            "device_id": attacker_device_id,
        },
    )
    assert resp.status_code == 403, "При несовпадении device_id должен возвращаться статус 403 Forbidden"
    detail = resp.json()["detail"]
    assert "незнакомого устройства" in detail.lower()


def test_get_me_with_valid_token(test_client):
    """Тест 6: Проверка /me с Bearer токеном -> 200 OK и возвращение профиля пользователя."""
    kp = BignCrypto.generate_keypair()
    pwd = "SecretPassword_777"
    device_id = "device-me-test"

    test_client.post(
        "/register",
        json={
            "login": "agent_dave",
            "password": pwd,
            "public_key": kp.public_hex,
            "device_id": device_id,
        },
    )

    login_resp = test_client.post(
        "/login",
        json={
            "login": "agent_dave",
            "password": pwd,
            "device_id": device_id,
        },
    )
    token = login_resp.json()["token"]

    # Вызов GET /me
    me_resp = test_client.get(
        "/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert me_resp.status_code == 200
    me_data = me_resp.json()
    assert me_data["user_id"] == "agent_dave"
    assert me_data["public_key"] == kp.public_hex
    assert me_data["device_id"] == device_id
    assert me_data["status"] == "active"


def test_logout_and_subsequent_get_me_unauthorized_401(test_client):
    """Тест 7: Выход /logout и последующий /me -> 401 Unauthorized."""
    kp = BignCrypto.generate_keypair()
    pwd = "SessionPass_999!"
    device_id = "session-device"

    test_client.post(
        "/register",
        json={
            "login": "agent_eve",
            "password": pwd,
            "public_key": kp.public_hex,
            "device_id": device_id,
        },
    )

    login_resp = test_client.post(
        "/login",
        json={
            "login": "agent_eve",
            "password": pwd,
            "device_id": device_id,
        },
    )
    token = login_resp.json()["token"]

    # Проверяем, что токен активен
    assert test_client.get("/me", headers={"Authorization": f"Bearer {token}"}).status_code == 200

    # 1. Выполняем logout
    logout_resp = test_client.post(
        "/logout",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert logout_resp.status_code == 200
    assert logout_resp.json()["status"] == "ok"

    # 2. Повторный вызов /me с отозванным токеном
    after_me_resp = test_client.get(
        "/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert after_me_resp.status_code == 401
    assert "недействительна" in after_me_resp.json()["detail"].lower() or "истек" in after_me_resp.json()["detail"].lower()


def test_api_client_high_level_flow(test_client):
    """Тест 8: Интеграция ApiClient (токен в ОЗУ, автозаголовок Authorization, logout)."""
    api = ApiClient(base_url="http://testserver")
    api._session = test_client  # Перенаправляем requests на TestClient

    kp = BignCrypto.generate_keypair()
    pwd = "ClientFlowPass_123"

    # Проверка отсутствия токена в ОЗУ до входа
    assert api.token is None

    # Регистрация
    reg_ok = api.register(
        user_id="agent_frank",
        password=pwd,
        public_key_hex=kp.public_hex,
        device_id="frank-laptop-01",
    )
    assert reg_ok is not None

    # Вход
    login_data = api.login(
        login="agent_frank",
        password=pwd,
        device_id="frank-laptop-01",
    )
    assert "token" in login_data
    assert api.token == login_data["token"]  # Токен хранится в ОЗУ api._token

    # Вызов get_me (токен подставляется автоматически в заголовок)
    me = api.get_me()
    assert me["user_id"] == "agent_frank"
    assert me["device_id"] == "frank-laptop-01"

    # Выход
    logout_ok = api.logout()
    assert logout_ok is True
    assert api.token is None  # Токен стерт из ОЗУ

    # Попытка запроса после logout без токена
    with pytest.raises(ApiClientError):
        api.get_me()
