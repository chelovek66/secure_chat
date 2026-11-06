"""
Модуль управления реляционной базой данных SQLite для сервера «Secure Chat».
Обеспечивает персистентное хранение учетных записей абонентов, их открытых ключей bign,
статусов, метаданных активности и системных журналов аудита.
"""

import csv
import io
import json
import logging
import os
import sqlite3
import threading
import secrets
import hmac
import hashlib
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

from .config import settings

logger = logging.getLogger("secure_chat.database")


def hash_password_pbkdf2(password: str, salt: Optional[str] = None, iterations: int = 200_000) -> tuple[str, str]:
    """
    Хэширует пароль алгоритмом PBKDF2-HMAC-SHA256 (не менее 200 000 итераций)
    с криптографически стойкой уникальной солью (secrets.token_hex(16)).
    Возвращает (хэш_hex: str, соль_hex: str).
    """
    if salt is None:
        salt = secrets.token_hex(16)
    salt_bytes = bytes.fromhex(salt)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt_bytes, iterations).hex()
    return digest, salt


def verify_password_pbkdf2(password: str, salt: str, expected_hash: str, iterations: int = 200_000) -> bool:
    """Проверяет пароль пользователя по алгоритму PBKDF2-HMAC-SHA256."""
    try:
        salt_bytes = bytes.fromhex(salt)
        computed = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt_bytes, iterations).hex()
        return hmac.compare_digest(computed, expected_hash)
    except Exception:
        return False


def hash_user_password(password: str, salt: Optional[str] = None) -> tuple[str, str]:
    """Хэширует пароль алгоритмом bash256 (СТБ 34.101.47-2017) с криптографической солью."""
    from client.crypto.bee2_wrapper import engine
    if salt is None:
        salt = secrets.token_hex(16)
    digest = engine.bash256(f"STB_PWD_SALT:{salt}:{password}".encode("utf-8")).hex()
    return digest, salt


def verify_user_password(password: str, salt: str, expected_hash: str) -> bool:
    """
    Проверяет пароль пользователя.
    Сначала проверяет по PBKDF2-HMAC-SHA256 (200 000 итераций).
    При несовпадении выполняет проверку по bash256 (СТБ 34.101.47-2017) для поддержки миграции.
    """
    if verify_password_pbkdf2(password, salt, expected_hash):
        return True
    try:
        from client.crypto.bee2_wrapper import engine
        computed = engine.bash256(f"STB_PWD_SALT:{salt}:{password}".encode("utf-8")).hex()
        if hmac.compare_digest(computed, expected_hash):
            return True
    except Exception:
        pass
    return False


class DatabaseManager:
    """
    Потокобезопасный менеджер базы данных SQLite.
    Поддерживает WAL-режим (Write-Ahead Logging) и синхронизацию через блокировки
    для надежного параллельного доступа в многопоточной среде FastAPI/Uvicorn.
    """

    def __init__(self, db_path: Optional[str] = None, enabled: Optional[bool] = None):
        if db_path is None:
            self.db_path = getattr(settings, "database_path", "server/secure_chat.db")
        else:
            self.db_path = db_path

        self._enabled = enabled if enabled is not None else getattr(settings, "database_enabled", True)

        if self.db_path != ":memory:":
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)

        self._lock = threading.RLock()
        self._conn: Optional[sqlite3.Connection] = sqlite3.connect(
            self.db_path,
            check_same_thread=False,
            timeout=30.0,
        )
        self._conn.row_factory = sqlite3.Row

        self.init_db()

    def is_enabled(self) -> bool:
        """Возвращает флаг активности базы данных для персистентного хранения ключей."""
        with self._lock:
            return self._enabled

    def set_enabled(self, value: bool) -> bool:
        """Включает или выключает персистентное сохранение открытых ключей в БД."""
        with self._lock:
            self._enabled = bool(value)
            if self._enabled:
                logger.info(
                    f"База данных SQLite ВКЛЮЧЕНА ({self.db_path}). "
                    f"Открытые ключи пользователей персистентно сохраняются на диске."
                )
            else:
                logger.info(
                    "База данных SQLite ВЫКЛЮЧЕНА. "
                    "Открытые ключи пользователей хранятся только в оперативной памяти (ОЗУ)."
                )
            return self._enabled

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def init_db(self) -> None:
        """Создает таблицы и индексы в базе данных, если они отсутствуют."""
        with self._lock:
            if self._conn is None:
                return

            if self.db_path != ":memory:":
                try:
                    self._conn.execute("PRAGMA journal_mode=WAL;")
                    self._conn.execute("PRAGMA synchronous=NORMAL;")
                except Exception as e:
                    logger.warning(f"Не удалось настроить journal_mode/synchronous в SQLite: {e}")

            try:
                self._conn.execute("PRAGMA foreign_keys=ON;")
            except Exception as e:
                logger.warning(f"Не удалось включить foreign_keys: {e}")

            with self._conn:
                self._conn.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        user_id TEXT PRIMARY KEY,
                        public_key TEXT NOT NULL,
                        registered_at TEXT NOT NULL,
                        last_seen_at TEXT NOT NULL,
                        status TEXT DEFAULT 'active',
                        client_version TEXT,
                        ip_address TEXT,
                        password_hash TEXT,
                        password_salt TEXT,
                        device_id TEXT
                    );
                """)

                # Миграция: добавляем колонки password_hash и password_salt если они отсутствуют
                try:
                    cols = [c[1] for c in self._conn.execute("PRAGMA table_info(users)").fetchall()]
                    if "password_hash" not in cols:
                        self._conn.execute("ALTER TABLE users ADD COLUMN password_hash TEXT;")
                    if "password_salt" not in cols:
                        self._conn.execute("ALTER TABLE users ADD COLUMN password_salt TEXT;")
                    if "device_id" not in cols:
                        self._conn.execute("ALTER TABLE users ADD COLUMN device_id TEXT;")
                except Exception as m_err:
                    logger.debug(f"Миграция колонок users: {m_err}")

                self._conn.execute("""
                    CREATE TABLE IF NOT EXISTS sessions (
                        token TEXT PRIMARY KEY,
                        user_id TEXT NOT NULL,
                        device_id TEXT,
                        created_at TEXT NOT NULL,
                        expires_at TEXT NOT NULL,
                        FOREIGN KEY(user_id) REFERENCES users(user_id) ON DELETE CASCADE
                    );
                """)
                self._conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_sessions_token
                    ON sessions(token);
                """)
                self._conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_sessions_user_id
                    ON sessions(user_id);
                """)

                self._conn.execute("""
                    CREATE TABLE IF NOT EXISTS audit_log (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        event_type TEXT NOT NULL,
                        user_id TEXT,
                        details TEXT
                    );
                """)

                self._conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp
                    ON audit_log(timestamp);
                """)
                self._conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_audit_log_user_id
                    ON audit_log(user_id);
                """)
                self._conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_users_status
                    ON users(status);
                """)

                # Таблицы безопасного обновления ПО (ПЗ-4)
                self._conn.execute("""
                    CREATE TABLE IF NOT EXISTS releases (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        version TEXT UNIQUE NOT NULL,
                        os TEXT NOT NULL,
                        arch TEXT NOT NULL,
                        min_supported TEXT DEFAULT '1.0.0',
                        package_path TEXT NOT NULL,
                        package_sha256 TEXT NOT NULL,
                        manifest_path TEXT NOT NULL,
                        sbom_path TEXT,
                        signature TEXT NOT NULL,
                        created_at TEXT NOT NULL
                    );
                """)
                self._conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_releases_version
                    ON releases(version);
                """)
                self._conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_releases_os_arch
                    ON releases(os, arch);
                """)

                self._conn.execute("""
                    CREATE TABLE IF NOT EXISTS update_audit (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id TEXT,
                        device_id TEXT,
                        from_version TEXT,
                        to_version TEXT,
                        status TEXT,
                        ip TEXT,
                        ts TEXT NOT NULL
                    );
                """)
                self._conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_update_audit_ts
                    ON update_audit(ts);
                """)
                self._conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_update_audit_user
                    ON update_audit(user_id);
                """)

        logger.info(f"База данных SQLite успешно инициализирована: {self.db_path}")

    def register_user_with_password(
        self,
        user_id: str,
        public_key: str,
        password: str,
        device_id: Optional[str] = None,
        ip_address: str = "127.0.0.1",
        client_version: str = "2.1.0",
    ) -> bool:
        """Регистрирует нового пользователя с хэшированием пароля по PBKDF2-HMAC-SHA256 (200 000 итераций)."""
        with self._lock:
            pwd_hash, pwd_salt = hash_password_pbkdf2(password)
            now = datetime.now(timezone.utc).isoformat()
            if self._conn is None:
                return False

            with self._conn:
                existing = self._conn.execute(
                    "SELECT user_id, device_id FROM users WHERE user_id = ?",
                    (user_id,),
                ).fetchone()

                if existing is None:
                    self._conn.execute(
                        """
                        INSERT INTO users (
                            user_id, public_key, registered_at, last_seen_at, status, client_version, ip_address, password_hash, password_salt, device_id
                        ) VALUES (?, ?, ?, ?, 'active', ?, ?, ?, ?, ?)
                        """,
                        (user_id, public_key, now, now, client_version, ip_address, pwd_hash, pwd_salt, device_id),
                    )
                    self._conn.execute(
                        "INSERT INTO audit_log (timestamp, event_type, user_id, details) VALUES (?, ?, ?, ?)",
                        (now, "USER_REGISTER", user_id, f"Регистрация учетной записи абонента (привязка устройства: {device_id})"),
                    )
                else:
                    dev_id_to_store = device_id if device_id is not None else existing["device_id"]
                    self._conn.execute(
                        """
                        UPDATE users
                        SET public_key = ?, last_seen_at = ?, client_version = ?, ip_address = ?, password_hash = ?, password_salt = ?, device_id = ?
                        WHERE user_id = ?
                        """,
                        (public_key, now, client_version, ip_address, pwd_hash, pwd_salt, dev_id_to_store, user_id),
                    )
            return True

    def verify_user_credentials(
        self,
        user_id: str,
        password: str,
        device_id: Optional[str] = None,
    ) -> tuple[bool, Optional[str], str]:
        """
        Проверяет подлинность пароля пользователя по хэшу PBKDF2-HMAC-SHA256 или bash256.
        Проверяет привязку к отпечатку устройства (device_id):
          * если device_id в базе отсутствует -> привязывает переданный device_id;
          * если совпадает -> успешный вход;
          * если не совпадает -> возвращает отказ "Вход с незнакомого устройства".
        Возвращает (успех: bool, открытый_ключ: Optional[str], сообщение: str).
        """
        with self._lock:
            if self._conn is None:
                return False, None, "База данных сервера недоступна"

            row = self._conn.execute(
                "SELECT user_id, public_key, status, password_hash, password_salt, device_id FROM users WHERE user_id = ?",
                (user_id,),
            ).fetchone()

            if not row:
                return False, None, f"Пользователь '{user_id}' не найден. Пожалуйста, пройдите регистрацию."

            if row["status"] != "active":
                return False, None, f"Учетная запись '{user_id}' заблокирована."

            pwd_hash = row["password_hash"]
            pwd_salt = row["password_salt"]

            if not pwd_hash or not pwd_salt:
                # Автоматически фиксируем хэш пароля при первом входе для существующих тестовых записей
                now = datetime.now(timezone.utc).isoformat()
                new_hash, new_salt = hash_password_pbkdf2(password)
                with self._conn:
                    self._conn.execute(
                        "UPDATE users SET password_hash = ?, password_salt = ?, last_seen_at = ?, device_id = COALESCE(device_id, ?) WHERE user_id = ?",
                        (new_hash, new_salt, now, device_id, user_id),
                    )
                return True, row["public_key"], "Вход выполнен успешно"

            if not verify_user_password(password, pwd_salt, pwd_hash):
                now = datetime.now(timezone.utc).isoformat()
                with self._conn:
                    self._conn.execute(
                        "INSERT INTO audit_log (timestamp, event_type, user_id, details) VALUES (?, ?, ?, ?)",
                        (now, "USER_LOGIN_FAILED", user_id, "Ошибка аутентификации: неверный пароль"),
                    )
                return False, None, "Неверный пароль! Проверьте правильность ввода."

            # Проверка Device Fingerprint
            stored_device_id = row["device_id"]
            if not stored_device_id:
                # У пользователя не был привязан отпечаток: привязываем переданный (если передан)
                if device_id:
                    with self._conn:
                        self._conn.execute(
                            "UPDATE users SET device_id = ? WHERE user_id = ?",
                            (device_id, user_id),
                        )
                        self._conn.execute(
                            "INSERT INTO audit_log (timestamp, event_type, user_id, details) VALUES (?, ?, ?, ?)",
                            (datetime.now(timezone.utc).isoformat(), "DEVICE_BIND", user_id, f"Первичная привязка устройства: {device_id}"),
                        )
            else:
                # У пользователя уже есть сохраненный device_id
                if not device_id or device_id != stored_device_id:
                    now = datetime.now(timezone.utc).isoformat()
                    with self._conn:
                        self._conn.execute(
                            "INSERT INTO audit_log (timestamp, event_type, user_id, details) VALUES (?, ?, ?, ?)",
                            (now, "DEVICE_MISMATCH", user_id, f"Вход с незнакомого устройства: получено '{device_id}', ожидалось '{stored_device_id}'"),
                        )
                    return False, None, "Вход с незнакомого устройства"

            now = datetime.now(timezone.utc).isoformat()
            with self._conn:
                self._conn.execute("UPDATE users SET last_seen_at = ? WHERE user_id = ?", (now, user_id))
                self._conn.execute(
                    "INSERT INTO audit_log (timestamp, event_type, user_id, details) VALUES (?, ?, ?, ?)",
                    (now, "USER_LOGIN_SUCCESS", user_id, f"Успешная проверка учетных данных (устройство: {device_id or stored_device_id})"),
                )
            return True, row["public_key"], "Вход выполнен успешно"

    def create_session(
        self,
        user_id: str,
        device_id: Optional[str] = None,
        expires_in_seconds: int = 1800,
    ) -> str:
        """
        Создает сессионный криптографический токен с привязкой к user_id и device_id.
        Срок действия по умолчанию: 30 минут (1800 сек).
        """
        with self._lock:
            token = secrets.token_hex(32)  # 64 hex символа
            now = datetime.now(timezone.utc)
            created_at = now.isoformat()
            expires_at = (now + timedelta(seconds=expires_in_seconds)).isoformat()

            if self._conn is not None:
                with self._conn:
                    self._conn.execute(
                        """
                        INSERT INTO sessions (token, user_id, device_id, created_at, expires_at)
                        VALUES (?, ?, ?, ?, ?)
                        """,
                        (token, user_id, device_id, created_at, expires_at),
                    )
            return token

    def get_session(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Возвращает сессию по токену, если она существует и не истекла.
        Истекшие сессии автоматически удаляются.
        """
        with self._lock:
            if self._conn is None:
                return None
            try:
                row = self._conn.execute(
                    "SELECT token, user_id, device_id, created_at, expires_at FROM sessions WHERE token = ?",
                    (token,),
                ).fetchone()
                if not row:
                    return None

                # Проверка срока действия
                expires_at = datetime.fromisoformat(row["expires_at"])
                if datetime.now(timezone.utc) > expires_at:
                    with self._conn:
                        self._conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
                    return None

                return dict(row)
            except Exception as e:
                logger.error(f"Ошибка проверки сессии '{token}': {e}")
                return None

    def delete_session(self, token: str) -> bool:
        """Удаляет сессионный токен из базы данных (logout)."""
        with self._lock:
            if self._conn is None:
                return False
            try:
                with self._conn:
                    cursor = self._conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
                    return cursor.rowcount > 0
            except Exception as e:
                logger.error(f"Ошибка удаления сессии: {e}")
                return False

    def delete_user_sessions(self, user_id: str) -> bool:
        """Удаляет все активные сессии указанного пользователя."""
        with self._lock:
            if self._conn is None:
                return False
            try:
                with self._conn:
                    cursor = self._conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
                    return cursor.rowcount > 0
            except Exception as e:
                logger.error(f"Ошибка удаления сессий пользователя '{user_id}': {e}")
                return False

    def register_user(
        self,
        user_id: str,
        public_key: str,
        ip_address: str = "127.0.0.1",
        client_version: str = "2.1.0",
    ) -> bool:
        """
        Регистрирует нового пользователя или обновляет открытый ключ и метаданные сессии.
        Возвращает True в случае успеха (если БД включена и запись зафиксирована).
        """
        with self._lock:
            if not self._enabled:
                logger.debug(f"База данных выключена: персистентная запись открытого ключа '{user_id}' пропущена.")
                return False

            if self._conn is None:
                return False

            now = datetime.now(timezone.utc).isoformat()
            try:
                with self._conn:
                    existing = self._conn.execute(
                        "SELECT user_id, registered_at, status FROM users WHERE user_id = ?",
                        (user_id,),
                    ).fetchone()

                    if existing is None:
                        self._conn.execute(
                            """
                            INSERT INTO users (
                                user_id, public_key, registered_at, last_seen_at, status, client_version, ip_address
                            ) VALUES (?, ?, ?, ?, 'active', ?, ?)
                            """,
                            (user_id, public_key, now, now, client_version, ip_address),
                        )
                        event_type = "USER_REGISTER"
                        details = f"Зарегистрирован новый абонент c IP {ip_address}, версия {client_version}"
                    else:
                        self._conn.execute(
                            """
                            UPDATE users
                            SET public_key = ?, last_seen_at = ?, client_version = ?, ip_address = ?
                            WHERE user_id = ?
                            """,
                            (public_key, now, client_version, ip_address, user_id),
                        )
                        event_type = "USER_KEY_UPDATE"
                        details = f"Обновлен открытый ключ с IP {ip_address}, версия {client_version}"

                    self._conn.execute(
                        """
                        INSERT INTO audit_log (timestamp, event_type, user_id, details)
                        VALUES (?, ?, ?, ?)
                        """,
                        (now, event_type, user_id, details),
                    )
                return True
            except Exception as e:
                logger.error(f"Ошибка сохранения пользователя '{user_id}' в SQLite: {e}", exc_info=True)
                return False

    def get_user(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Возвращает профиль пользователя по его идентификатору или None."""
        with self._lock:
            if self._conn is None:
                return None
            try:
                row = self._conn.execute(
                    """
                    SELECT user_id, public_key, registered_at, last_seen_at, status, client_version, ip_address, device_id
                    FROM users
                    WHERE user_id = ?
                    """,
                    (user_id,),
                ).fetchone()
                return dict(row) if row else None
            except sqlite3.Error as e:
                logger.error(f"Ошибка чтения профиля пользователя '{user_id}': {e}")
                return None

    def get_all_users(self) -> List[Dict[str, Any]]:
        """Возвращает список всех зарегистрированных пользователей."""
        with self._lock:
            if self._conn is None:
                return []
            try:
                rows = self._conn.execute(
                    """
                    SELECT user_id, public_key, registered_at, last_seen_at, status, client_version, ip_address, device_id
                    FROM users
                    ORDER BY registered_at ASC
                    """
                ).fetchall()
                return [dict(row) for row in rows]
            except sqlite3.Error as e:
                logger.error(f"Ошибка чтения списка пользователей: {e}")
                return []

    def update_last_seen(self, user_id: str, ip_address: Optional[str] = None) -> bool:
        """Обновляет временную метку последней активности пользователя."""
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            if self._conn is None:
                return False
            try:
                with self._conn:
                    if ip_address is not None:
                        cursor = self._conn.execute(
                            "UPDATE users SET last_seen_at = ?, ip_address = ? WHERE user_id = ?",
                            (now, ip_address, user_id),
                        )
                    else:
                        cursor = self._conn.execute(
                            "UPDATE users SET last_seen_at = ? WHERE user_id = ?",
                            (now, user_id),
                        )
                    return cursor.rowcount > 0
            except Exception as e:
                logger.error(f"Ошибка обновления last_seen для '{user_id}': {e}")
                return False

    def update_user_status(self, user_id: str, status: str) -> bool:
        """Обновляет статус учетной записи ('active', 'suspended', 'blocked')."""
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            if self._conn is None:
                return False
            try:
                with self._conn:
                    cursor = self._conn.execute(
                        "UPDATE users SET status = ? WHERE user_id = ?",
                        (status, user_id),
                    )
                    if cursor.rowcount > 0:
                        self._conn.execute(
                            """
                            INSERT INTO audit_log (timestamp, event_type, user_id, details)
                            VALUES (?, 'STATUS_CHANGE', ?, ?)
                            """,
                            (now, user_id, f"Статус учетной записи изменен на '{status}'"),
                        )
                        return True
                    return False
            except Exception as e:
                logger.error(f"Ошибка изменения статуса для '{user_id}': {e}")
                return False

    def delete_user(self, user_id: str) -> bool:
        """Удаляет профиль пользователя и фиксирует операцию в журнале аудита."""
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            if self._conn is None:
                return False
            try:
                with self._conn:
                    cursor = self._conn.execute(
                        "DELETE FROM users WHERE user_id = ?",
                        (user_id,),
                    )
                    if cursor.rowcount > 0:
                        self._conn.execute(
                            """
                            INSERT INTO audit_log (timestamp, event_type, user_id, details)
                            VALUES (?, 'USER_DELETE', ?, 'Профиль пользователя удален')
                            """,
                            (now, user_id),
                        )
                        return True
                    return False
            except Exception as e:
                logger.error(f"Ошибка удаления пользователя '{user_id}': {e}")
                return False

    def log_event(
        self,
        event_type: str,
        user_id: Optional[str] = None,
        details: Optional[str] = None,
    ) -> None:
        """Записывает произвольное событие в системный журнал аудита."""
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            if self._conn is None:
                return
            try:
                with self._conn:
                    self._conn.execute(
                        """
                        INSERT INTO audit_log (timestamp, event_type, user_id, details)
                        VALUES (?, ?, ?, ?)
                        """,
                        (now, event_type, user_id, details),
                    )
            except Exception as e:
                logger.error(f"Ошибка записи в журнал аудита: {e}")

    def get_audit_logs(
        self,
        limit: int = 100,
        user_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Возвращает последние записи журнала аудита с возможностью фильтрации по user_id."""
        with self._lock:
            if self._conn is None:
                return []
            if user_id:
                rows = self._conn.execute(
                    """
                    SELECT id, timestamp, event_type, user_id, details
                    FROM audit_log
                    WHERE user_id = ?
                    ORDER BY id DESC
                    LIMIT ?
                    """,
                    (user_id, limit),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    """
                    SELECT id, timestamp, event_type, user_id, details
                    FROM audit_log
                    ORDER BY id DESC
                    LIMIT ?
                    """,
                    (limit,),
                ).fetchall()
            return [dict(row) for row in rows]

    def get_stats(self) -> Dict[str, Any]:
        """Возвращает агрегированные метрики состояния базы данных."""
        with self._lock:
            if self._conn is None:
                return {
                    "enabled": self._enabled,
                    "db_path": self.db_path,
                    "user_count": 0,
                    "active_count": 0,
                    "log_count": 0,
                    "db_size_bytes": 0,
                }

            try:
                user_count = self._conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
                active_count = self._conn.execute(
                    "SELECT COUNT(*) FROM users WHERE status = 'active'"
                ).fetchone()[0]
                log_count = self._conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
            except sqlite3.Error as e:
                logger.error(f"Ошибка получения счетчиков статистики: {e}")
                user_count, active_count, log_count = 0, 0, 0

            if self.db_path != ":memory:" and os.path.exists(self.db_path):
                db_size_bytes = 0
                for path_candidate in [self.db_path, f"{self.db_path}-wal", f"{self.db_path}-shm"]:
                    if os.path.exists(path_candidate):
                        try:
                            db_size_bytes += os.path.getsize(path_candidate)
                        except OSError:
                            pass
            else:
                try:
                    page_count = self._conn.execute("PRAGMA page_count").fetchone()[0]
                    page_size = self._conn.execute("PRAGMA page_size").fetchone()[0]
                    db_size_bytes = page_count * page_size
                except sqlite3.Error:
                    db_size_bytes = 0

            return {
                "enabled": self._enabled,
                "db_path": self.db_path,
                "user_count": user_count,
                "active_count": active_count,
                "log_count": log_count,
                "db_size_bytes": db_size_bytes,
            }

    def export_users_json(self) -> str:
        """Экспортирует профили всех абонентов в формат JSON."""
        users = self.get_all_users()
        return json.dumps(users, indent=2, ensure_ascii=False)

    def export_users_csv(self) -> str:
        """Экспортирует профили всех абонентов в формат CSV."""
        users = self.get_all_users()
        output = io.StringIO()
        fieldnames = [
            "user_id",
            "public_key",
            "registered_at",
            "last_seen_at",
            "status",
            "client_version",
            "ip_address",
            "device_id",
        ]
        writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore", lineterminator="\n")
        writer.writeheader()
        for u in users:
            writer.writerow(u)
        return output.getvalue()

    # --- Методы безопасного обновления ПО (ПЗ-4) ---

    def add_release(
        self,
        version: str,
        os_name: str,
        arch: str,
        package_path: str,
        package_sha256: str,
        manifest_path: str,
        signature: str,
        min_supported: str = "1.0.0",
        sbom_path: Optional[str] = None,
        created_at: Optional[str] = None,
    ) -> bool:
        """Регистрирует новый выпуск ПО (релиз) в таблице releases."""
        with self._lock:
            if self._conn is None:
                return False
            if created_at is None:
                created_at = datetime.now(timezone.utc).isoformat()
            try:
                with self._conn:
                    self._conn.execute(
                        """
                        INSERT OR REPLACE INTO releases (
                            version, os, arch, min_supported, package_path,
                            package_sha256, manifest_path, sbom_path, signature, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            version,
                            os_name,
                            arch,
                            min_supported,
                            package_path,
                            package_sha256,
                            manifest_path,
                            sbom_path,
                            signature,
                            created_at,
                        ),
                    )
                logger.info(f"Релиз {version} ({os_name}-{arch}) успешно сохранен в базе данных.")
                return True
            except sqlite3.Error as e:
                logger.error(f"Ошибка сохранения релиза {version}: {e}")
                return False

    def get_release(
        self,
        version: str,
        os_name: Optional[str] = None,
        arch: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Возвращает информацию о конкретном релизе по версии и платформе."""
        with self._lock:
            if self._conn is None:
                return None
            query = "SELECT * FROM releases WHERE version = ?"
            params: list[Any] = [version]
            if os_name:
                query += " AND os = ?"
                params.append(os_name)
            if arch:
                query += " AND arch = ?"
                params.append(arch)
            row = self._conn.execute(query, params).fetchone()
            return dict(row) if row else None

    def get_latest_release(
        self,
        os_name: Optional[str] = None,
        arch: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Возвращает наиболее актуальный релиз ПО для указанной платформы."""
        with self._lock:
            if self._conn is None:
                return None
            query = "SELECT * FROM releases"
            params: list[Any] = []
            clauses = []
            if os_name:
                clauses.append("os = ?")
                params.append(os_name)
            if arch:
                clauses.append("arch = ?")
                params.append(arch)
            if clauses:
                query += " WHERE " + " AND ".join(clauses)

            rows = self._conn.execute(query, params).fetchall()
            if not rows:
                return None

            try:
                from packaging.version import parse as parse_ver
                sorted_rows = sorted(
                    rows,
                    key=lambda r: parse_ver(r["version"].split("-")[0] if "-" in r["version"] else r["version"]),
                    reverse=True,
                )
                return dict(sorted_rows[0])
            except Exception:
                # Резервная сортировка по id / строке
                sorted_rows = sorted(rows, key=lambda r: r["id"], reverse=True)
                return dict(sorted_rows[0])

    def delete_release(self, version: str) -> bool:
        """Удаляет релиз по номеру версии."""
        with self._lock:
            if self._conn is None:
                return False
            with self._conn:
                cur = self._conn.execute("DELETE FROM releases WHERE version = ?", (version,))
                return cur.rowcount > 0

    def record_update_audit(
        self,
        user_id: Optional[str],
        device_id: Optional[str],
        from_version: Optional[str],
        to_version: Optional[str],
        status: str,
        ip: Optional[str] = None,
        ts: Optional[str] = None,
    ) -> bool:
        """Записывает событие обновления ПО в журнал update_audit."""
        with self._lock:
            if self._conn is None:
                return False
            if ts is None:
                ts = datetime.now(timezone.utc).isoformat()
            try:
                with self._conn:
                    self._conn.execute(
                        """
                        INSERT INTO update_audit (
                            user_id, device_id, from_version, to_version, status, ip, ts
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (user_id, device_id, from_version, to_version, status, ip, ts),
                    )
                logger.info(
                    f"Аудит обновления: user={user_id}, device={device_id}, "
                    f"{from_version} -> {to_version}, статус={status}"
                )
                return True
            except sqlite3.Error as e:
                logger.error(f"Ошибка записи аудита обновления: {e}")
                return False

    def get_update_audit_logs(
        self,
        limit: int = 100,
        user_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Возвращает журнал аудита обновлений ПО."""
        with self._lock:
            if self._conn is None:
                return []
            if user_id:
                rows = self._conn.execute(
                    """
                    SELECT id, user_id, device_id, from_version, to_version, status, ip, ts
                    FROM update_audit
                    WHERE user_id = ?
                    ORDER BY id DESC
                    LIMIT ?
                    """,
                    (user_id, limit),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    """
                    SELECT id, user_id, device_id, from_version, to_version, status, ip, ts
                    FROM update_audit
                    ORDER BY id DESC
                    LIMIT ?
                    """,
                    (limit,),
                ).fetchall()
            return [dict(row) for row in rows]

    def clear_all(self) -> None:
        """Очищает содержимое всех таблиц (для изоляции тестовых прогонов)."""
        with self._lock:
            if self._conn is not None:
                with self._conn:
                    self._conn.execute("DELETE FROM sessions")
                    self._conn.execute("DELETE FROM update_audit")
                    self._conn.execute("DELETE FROM releases")
                    self._conn.execute("DELETE FROM audit_log")
                    self._conn.execute("DELETE FROM users")

    def close(self) -> None:
        """Закрывает подключение к SQLite."""
        with self._lock:
            if self._conn is not None:
                try:
                    self._conn.close()
                except Exception:
                    pass
                self._conn = None


# Глобальный экземпляр менеджера базы данных для сервера
db_manager = DatabaseManager()
