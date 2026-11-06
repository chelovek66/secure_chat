"""
Тесты модуля управления базой данных SQLite («DatabaseManager»)
и связанных административных конечных точек сервера «Secure Chat».
"""

import csv
import io
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from server.app import app
from server.database import DatabaseManager
from server.storage import Storage, storage


@pytest.fixture
def temp_db(tmp_path: Path):
    """Создает отдельный экземпляр DatabaseManager во временном файле."""
    db_file = tmp_path / "test_secure_chat.db"
    manager = DatabaseManager(db_path=str(db_file))
    yield manager
    manager.close()


@pytest.fixture
def api_client():
    """Тестовый клиент FastAPI с гарантированной очисткой перед каждым тестом."""
    if storage.db is not None:
        storage.db.set_enabled(True)
    storage.reset()
    client = TestClient(app)
    yield client
    storage.reset()
    if storage.db is not None:
        storage.db.set_enabled(True)


def test_database_init(temp_db: DatabaseManager):
    """Проверка создания таблиц, колонок и индексов в SQLite."""
    conn = temp_db._conn
    assert conn is not None

    # Проверка существования таблиц
    tables = [
        row[0]
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    ]
    assert "users" in tables
    assert "audit_log" in tables

    # Проверка колонок таблицы users
    users_cols = [
        row[1] for row in conn.execute("PRAGMA table_info(users)").fetchall()
    ]
    expected_users_cols = [
        "user_id",
        "public_key",
        "registered_at",
        "last_seen_at",
        "status",
        "client_version",
        "ip_address",
    ]
    for col in expected_users_cols:
        assert col in users_cols

    # Проверка колонок таблицы audit_log
    audit_cols = [
        row[1] for row in conn.execute("PRAGMA table_info(audit_log)").fetchall()
    ]
    expected_audit_cols = ["id", "timestamp", "event_type", "user_id", "details"]
    for col in expected_audit_cols:
        assert col in audit_cols

    # Проверка индексов
    indexes = [
        row[0]
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index'"
        ).fetchall()
    ]
    assert "idx_audit_log_timestamp" in indexes
    assert "idx_audit_log_user_id" in indexes
    assert "idx_users_status" in indexes


def test_user_registration_and_retrieval(temp_db: DatabaseManager):
    """Проверка регистрации пользователя, обновления ключа и выборки."""
    # Регистрация нового пользователя
    success = temp_db.register_user(
        user_id="alice",
        public_key="04" + "aa" * 32,
        ip_address="192.168.1.100",
        client_version="2.1.0",
    )
    assert success is True

    user = temp_db.get_user("alice")
    assert user is not None
    assert user["user_id"] == "alice"
    assert user["public_key"] == "04" + "aa" * 32
    assert user["ip_address"] == "192.168.1.100"
    assert user["client_version"] == "2.1.0"
    assert user["status"] == "active"
    orig_registered_at = user["registered_at"]
    assert orig_registered_at is not None

    # Повторная регистрация с обновлением ключа и IP
    success_update = temp_db.register_user(
        user_id="alice",
        public_key="04" + "bb" * 32,
        ip_address="192.168.1.200",
        client_version="2.2.0",
    )
    assert success_update is True

    updated_user = temp_db.get_user("alice")
    assert updated_user["public_key"] == "04" + "bb" * 32
    assert updated_user["ip_address"] == "192.168.1.200"
    assert updated_user["client_version"] == "2.2.0"
    # Дата первой регистрации не должна измениться
    assert updated_user["registered_at"] == orig_registered_at

    # Регистрация второго пользователя
    temp_db.register_user("bob", "04" + "cc" * 32)
    all_users = temp_db.get_all_users()
    assert len(all_users) == 2
    uids = [u["user_id"] for u in all_users]
    assert "alice" in uids
    assert "bob" in uids


def test_user_status_update(temp_db: DatabaseManager):
    """Проверка смены административного статуса пользователя."""
    temp_db.register_user("charlie", "pk_charlie")
    assert temp_db.get_user("charlie")["status"] == "active"

    # Смена на suspended
    res = temp_db.update_user_status("charlie", "suspended")
    assert res is True
    assert temp_db.get_user("charlie")["status"] == "suspended"

    # Проверка журнала аудита на наличие события смены статуса
    logs = temp_db.get_audit_logs(user_id="charlie")
    assert any(log["event_type"] == "STATUS_CHANGE" for log in logs)

    # Попытка смены статуса несуществующего пользователя
    res_unknown = temp_db.update_user_status("unknown_user", "active")
    assert res_unknown is False


def test_update_last_seen(temp_db: DatabaseManager):
    """Проверка обновления отметки времени активности."""
    temp_db.register_user("david", "pk_david")
    u1 = temp_db.get_user("david")

    res = temp_db.update_last_seen("david", ip_address="10.10.10.10")
    assert res is True

    u2 = temp_db.get_user("david")
    assert u2["ip_address"] == "10.10.10.10"
    assert u2["last_seen_at"] >= u1["last_seen_at"]

    assert temp_db.update_last_seen("nonexistent") is False


def test_delete_user(temp_db: DatabaseManager):
    """Проверка удаления профиля пользователя."""
    temp_db.register_user("eve", "pk_eve")
    assert temp_db.get_user("eve") is not None

    res = temp_db.delete_user("eve")
    assert res is True
    assert temp_db.get_user("eve") is None

    # Повторное удаление возвращает False
    assert temp_db.delete_user("eve") is False

    # В аудите должно быть событие USER_DELETE
    logs = temp_db.get_audit_logs(user_id="eve")
    assert any(log["event_type"] == "USER_DELETE" for log in logs)


def test_audit_logging(temp_db: DatabaseManager):
    """Проверка записи и выборки журналов аудита."""
    temp_db.log_event("CUSTOM_LOGIN", "user1", "Login from client")
    temp_db.log_event("CUSTOM_LOGOUT", "user1", "Logout successful")
    temp_db.log_event("SECURITY_ALERT", "user2", "Invalid signature")

    logs_all = temp_db.get_audit_logs(limit=10)
    assert len(logs_all) >= 3

    logs_u1 = temp_db.get_audit_logs(user_id="user1")
    assert len(logs_u1) == 2
    types = [l["event_type"] for l in logs_u1]
    assert "CUSTOM_LOGIN" in types
    assert "CUSTOM_LOGOUT" in types

    logs_limited = temp_db.get_audit_logs(limit=1)
    assert len(logs_limited) == 1


def test_get_stats(temp_db: DatabaseManager):
    """Проверка расчета агрегированных метрик базы данных."""
    temp_db.register_user("user_a", "key_a")
    temp_db.register_user("user_b", "key_b")
    temp_db.update_user_status("user_b", "blocked")

    stats = temp_db.get_stats()
    assert stats["user_count"] == 2
    assert stats["active_count"] == 1
    assert stats["log_count"] >= 3  # 2 регистрации + 1 смена статуса
    assert stats["db_size_bytes"] > 0


def test_export_users_json_and_csv(temp_db: DatabaseManager):
    """Проверка экспорта реестра пользователей в JSON и CSV форматы."""
    temp_db.register_user("user_j", "key_json", "1.1.1.1", "2.1.0")
    temp_db.register_user("user_c", "key_csv", "2.2.2.2", "2.1.0")

    # Проверка экспорта в JSON
    json_str = temp_db.export_users_json()
    data = json.loads(json_str)
    assert isinstance(data, list)
    assert len(data) == 2
    user_ids = [item["user_id"] for item in data]
    assert "user_j" in user_ids
    assert "user_c" in user_ids

    # Проверка экспорта в CSV
    csv_str = temp_db.export_users_csv()
    reader = csv.DictReader(io.StringIO(csv_str))
    rows = list(reader)
    assert len(rows) == 2
    csv_uids = [r["user_id"] for r in rows]
    assert "user_j" in csv_uids
    assert "user_c" in csv_uids
    assert "public_key" in rows[0]
    assert "status" in rows[0]


def test_concurrent_access_safety(temp_db: DatabaseManager):
    """Проверка потокобезопасности SQLite при параллельных запросах."""
    def worker(idx: int):
        uid = f"concurrent_user_{idx}"
        temp_db.register_user(uid, f"key_{idx}", ip_address=f"10.0.0.{idx}")
        temp_db.update_last_seen(uid)
        temp_db.log_event("THREAD_TEST", uid, f"Worker {idx} finished")
        return temp_db.get_user(uid)

    total_workers = 30
    with ThreadPoolExecutor(max_workers=10) as executor:
        results = list(executor.map(worker, range(total_workers)))

    assert len(results) == total_workers
    for res in results:
        assert res is not None

    stats = temp_db.get_stats()
    assert stats["user_count"] == total_workers


def test_storage_persistence_across_restart(tmp_path: Path):
    """
    Проверка синхронизации Storage с DatabaseManager
    и персистентного восстановления пользователей при 'перезапуске'.
    """
    db_file = tmp_path / "persistence_test.db"
    db_mgr = DatabaseManager(db_path=str(db_file))

    # Первый запуск сервера
    st1 = Storage(db=db_mgr)
    st1.register_user("alice_persist", "key_alice_123")
    st1.register_user("bob_persist", "key_bob_456")

    assert len(st1.get_users()) == 2

    # Симулируем перезапуск сервера (новый инстанс Storage с той же БД)
    st2 = Storage(db=db_mgr)
    assert st2.user_exists("alice_persist") is True
    assert st2.user_exists("bob_persist") is True

    u_alice = st2.get_user("alice_persist")
    assert u_alice is not None
    assert u_alice.public_key == "key_alice_123"

    # Удаление через storage удаляет и из БД
    st2.delete_user("alice_persist")
    assert st2.user_exists("alice_persist") is False
    assert db_mgr.get_user("alice_persist") is None

    db_mgr.close()


def test_admin_rest_api_endpoints(api_client: TestClient):
    """Комплексная проверка всех 5 административных REST API эндпоинтов."""
    # 1. Регистрация пользователей через API
    r_reg1 = api_client.post("/register", json={"user_id": "admin_alice", "public_key": "aa" * 32})
    assert r_reg1.status_code == 200

    r_reg2 = api_client.post("/register", json={"user_id": "admin_bob", "public_key": "bb" * 32})
    assert r_reg2.status_code == 200

    # 2. GET /admin/db/stats
    r_stats = api_client.get("/admin/db/stats")
    assert r_stats.status_code == 200
    stats = r_stats.json()
    assert stats["user_count"] >= 2
    assert stats["active_count"] >= 2
    assert stats["log_count"] >= 2
    assert stats["db_size_bytes"] > 0

    # 3. GET /admin/db/users (JSON и CSV)
    r_users = api_client.get("/admin/db/users")
    assert r_users.status_code == 200
    user_list = r_users.json()
    user_ids = [u["user_id"] for u in user_list]
    assert "admin_alice" in user_ids
    assert "admin_bob" in user_ids

    r_users_csv = api_client.get("/admin/db/users?format=csv")
    assert r_users_csv.status_code == 200
    assert "text/csv" in r_users_csv.headers["content-type"]
    assert "admin_alice" in r_users_csv.text

    # 4. GET /admin/db/audit
    r_audit = api_client.get("/admin/db/audit?limit=50")
    assert r_audit.status_code == 200
    logs = r_audit.json()
    assert len(logs) >= 2
    assert any(log["user_id"] == "admin_alice" for log in logs)

    # 5. POST /admin/db/users/{user_id}/status
    r_status = api_client.post(
        "/admin/db/users/admin_alice/status",
        json={"status": "suspended"},
    )
    assert r_status.status_code == 200
    assert r_status.json()["status"] == "ok"

    # Проверка несуществующего пользователя -> 404
    r_status_404 = api_client.post(
        "/admin/db/users/ghost/status",
        json={"status": "blocked"},
    )
    assert r_status_404.status_code == 404

    # 6. DELETE /admin/db/users/{user_id}
    r_del = api_client.delete("/admin/db/users/admin_alice")
    assert r_del.status_code == 200
    assert r_del.json()["status"] == "ok"

    # Проверка, что удаленный пользователь больше не отдается /users/admin_alice
    r_get = api_client.get("/users/admin_alice")
    assert r_get.status_code == 404

    # Повторное удаление -> 404
    r_del_404 = api_client.delete("/admin/db/users/admin_alice")
    assert r_del_404.status_code == 404


def test_database_enabled_toggle_logic(temp_db: DatabaseManager):
    """
    Проверка, что база данных сохраняет открытые ключи только когда она включена:
    - При enabled=True ключи записываются в таблицу users.
    - При enabled=False вызовы register_user игнорируются и не попадают на диск.
    """
    assert temp_db.is_enabled() is True

    # 1. Запись при включенной БД
    ok1 = temp_db.register_user("user_on", "key_on_1234567890abcdef")
    assert ok1 is True
    assert temp_db.get_user("user_on") is not None

    # 2. Выключение БД
    temp_db.set_enabled(False)
    assert temp_db.is_enabled() is False

    # 3. Попытка записи при выключенной БД
    ok2 = temp_db.register_user("user_off", "key_off_1234567890abcdef")
    assert ok2 is False
    assert temp_db.get_user("user_off") is None

    # 4. Повторное включение БД
    temp_db.set_enabled(True)
    assert temp_db.is_enabled() is True
    ok3 = temp_db.register_user("user_reenabled", "key_re_1234567890abcdef")
    assert ok3 is True
    assert temp_db.get_user("user_reenabled") is not None


def test_database_toggle_via_api(api_client):
    """
    Проверка переключения режима персистентности базы данных через REST API:
    GET /admin/db/status, POST /admin/db/toggle, POST /admin/db/status.
    """
    # 1. Проверяем статус по умолчанию
    r_status = api_client.get("/admin/db/status")
    assert r_status.status_code == 200
    data = r_status.json()
    assert data["enabled"] is True

    # 2. Выключаем БД через POST /admin/db/toggle
    r_toggle = api_client.post("/admin/db/toggle")
    assert r_toggle.status_code == 200
    assert r_toggle.json()["enabled"] is False

    # 3. Регистрируем пользователя при выключенной БД
    r_reg = api_client.post(
        "/register",
        json={"user_id": "ephemeral_user", "public_key": "pub_ephemeral_key_12345678901234567890"},
    )
    assert r_reg.status_code == 200

    # В оперативной памяти (/users) пользователь есть
    r_users = api_client.get("/users")
    assert any(u["user_id"] == "ephemeral_user" for u in r_users.json())

    # В SQLite базе данных пользователя НЕТ (так как БД выключена)
    assert storage.db.get_user("ephemeral_user") is None

    # 4. Включаем БД обратно через POST /admin/db/status с sync_memory_to_db=True
    r_enable = api_client.post(
        "/admin/db/status",
        json={"enabled": True, "sync_memory_to_db": True},
    )
    assert r_enable.status_code == 200
    assert r_enable.json()["enabled"] is True

    # Теперь пользователь синхронизирован и сохранен в SQLite
    db_u = storage.db.get_user("ephemeral_user")
    assert db_u is not None
    assert db_u["public_key"] == "pub_ephemeral_key_12345678901234567890"

