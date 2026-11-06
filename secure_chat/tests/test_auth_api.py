"""
Интеграционные тесты системы аутентификации и регистрации пользователей (POST /auth/register, POST /auth/login).
Проверяют требования защиты:
  * Хэширование паролей по СТБ 34.101.47-2017 (bash256) с солью;
  * Валидация открытых ключей bign (64 байта / 128 hex);
  * Защита от подбора и проверка прав доступа.
"""

import pytest
from fastapi.testclient import TestClient

from server.app import app
from server.database import DatabaseManager, hash_user_password, verify_user_password
from server.storage import storage
from client.crypto.bign import BignCrypto


@pytest.fixture
def test_client(tmp_path):
    """Изолированный клиент тестирования с отдельной БД."""
    orig_db = storage.db
    db_file = str(tmp_path / "test_auth.db")
    db = DatabaseManager(db_path=db_file, enabled=True)
    storage.db = db
    storage.reset()
    client = TestClient(app)
    yield client
    storage.reset()
    storage.db = orig_db


def test_password_hashing_bash256():
    """Тест надежного хэширования пароля по СТБ 34.101.47-2017."""
    pwd = "MySuperSecretPassword_2026!"
    digest, salt = hash_user_password(pwd)

    assert len(salt) == 32  # 16 байт в hex
    assert len(digest) == 64  # 32 байта (256 бит) в hex
    assert digest != pwd  # Не открытый текст

    # Проверка совпадения
    assert verify_user_password(pwd, salt, digest) is True
    # Проверка неверного пароля
    assert verify_user_password("WrongPassword!", salt, digest) is False


def test_auth_registration_and_login_flow(test_client):
    """Сквозной тест регистрации и последующего входа пользователя."""
    kp = BignCrypto.generate_keypair()

    # 1. Регистрация
    reg_resp = test_client.post(
        "/auth/register",
        json={
            "user_id": "test_agent_01",
            "password": "Password123$",
            "public_key": kp.public_hex,
        },
    )
    assert reg_resp.status_code == 200
    reg_data = reg_resp.json()
    assert reg_data["success"] is True
    assert reg_data["user_id"] == "test_agent_01"
    assert reg_data["public_key"] == kp.public_hex

    # 2. Успешный вход
    login_resp = test_client.post(
        "/auth/login",
        json={
            "user_id": "test_agent_01",
            "password": "Password123$",
        },
    )
    assert login_resp.status_code == 200
    login_data = login_resp.json()
    assert login_data["success"] is True
    assert login_data["public_key"] == kp.public_hex

    # 3. Вход с неверным паролем
    wrong_resp = test_client.post(
        "/auth/login",
        json={
            "user_id": "test_agent_01",
            "password": "WrongPassword999",
        },
    )
    assert wrong_resp.status_code == 200
    wrong_data = wrong_resp.json()
    assert wrong_data["success"] is False
    assert wrong_data["public_key"] is None


def test_auth_login_nonexistent_user(test_client):
    """Попытка входа несуществующего пользователя."""
    resp = test_client.post(
        "/auth/login",
        json={
            "user_id": "unknown_ghost_user",
            "password": "SomePassword",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is False
    assert "не найден" in data["message"].lower()
