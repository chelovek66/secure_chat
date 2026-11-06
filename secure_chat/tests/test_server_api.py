"""
Интеграционные тесты REST API сервера «Secure Chat».
Проверяют требования ПМИ:
  * П-03: Регистрация открытого ключа на сервере;
  * П-08: Деструктивность очереди сообщений (POP).
"""

import pytest
from fastapi.testclient import TestClient
from server.app import app
from server.storage import storage


@pytest.fixture(autouse=True)
def reset_storage():
    """Очищает хранилище и тестовую БД перед каждым тестом."""
    storage.reset()


client = TestClient(app)


def test_health_endpoint():
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "healthy"
    assert data["registered_users"] == 0


def test_register_and_get_users():
    """Тест П-03: Регистрация пользователей и получение списка."""
    # Регистрация Алисы
    r1 = client.post("/register", json={"user_id": "alice", "public_key": "aabbccdd" * 8})
    assert r1.status_code == 200
    assert r1.json()["status"] == "ok"

    # Регистрация Боба
    r2 = client.post("/register", json={"user_id": "bob", "public_key": "11223344" * 8})
    assert r2.status_code == 200

    # Проверка списка
    r_list = client.get("/users")
    assert r_list.status_code == 200
    users = r_list.json()
    assert len(users) == 2
    user_ids = [u["user_id"] for u in users]
    assert "alice" in user_ids
    assert "bob" in user_ids


def test_get_specific_user():
    client.post("/register", json={"user_id": "alice", "public_key": "aabb" * 16})
    resp = client.get("/users/alice")
    assert resp.status_code == 200
    assert resp.json()["user_id"] == "alice"
    assert resp.json()["public_key"] == "aabb" * 16

    # Несуществующий пользователь
    resp_404 = client.get("/users/unknown")
    assert resp_404.status_code == 404


def test_send_and_pop_inbox_destructive():
    """Тест П-08: Отправка сообщения и его деструктивное извлечение (POP)."""
    # Регистрируем Алису и Боба
    client.post("/register", json={"user_id": "alice", "public_key": "aa" * 32})
    client.post("/register", json={"user_id": "bob", "public_key": "bb" * 32})

    # Алиса отправляет сообщение Бобу
    payload = {
        "from_id": "alice",
        "to_id": "bob",
        "ciphertext": "Y2lwaGVydGV4dA==",
        "nonce": "bm9uY2UxMjM0NTY3OA==",
        "mac": "bWFjMTIzNDU2Nzg5MDEy",
        "encrypted_key": "ZW5jX2tleQ==",
        "signature": "c2lnbmF0dXJl",
    }
    r_send = client.post("/send", json=payload)
    assert r_send.status_code == 200
    assert r_send.json()["status"] == "delivered"

    # Боб забирает входящие
    r_inbox = client.get("/inbox/bob")
    assert r_inbox.status_code == 200
    messages = r_inbox.json()
    assert len(messages) == 1
    assert messages[0]["from_id"] == "alice"
    assert messages[0]["ciphertext"] == payload["ciphertext"]

    # П-08: Повторный запрос должен вернуть пустой список (сообщение удалено)
    r_inbox_2 = client.get("/inbox/bob")
    assert r_inbox_2.status_code == 200
    assert len(r_inbox_2.json()) == 0


def test_send_to_unregistered_user():
    """Отправка сообщения незарегистрированному пользователю возвращает 404."""
    client.post("/register", json={"user_id": "alice", "public_key": "aa" * 32})
    payload = {
        "from_id": "alice",
        "to_id": "ghost",
        "ciphertext": "Y2lwaGVydGV4dA==",
        "nonce": "bm9uY2UxMjM0NTY3OA==",
        "mac": "bWFjMTIzNDU2Nzg5MDEy",
        "encrypted_key": "ZW5jX2tleQ==",
        "signature": "c2lnbmF0dXJl",
    }
    resp = client.post("/send", json=payload)
    assert resp.status_code == 404
