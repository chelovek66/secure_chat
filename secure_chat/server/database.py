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
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from .config import settings

logger = logging.getLogger("secure_chat.database")


def hash_user_password(password: str, salt: Optional[str] = None) -> tuple[str, str]:
    """Хэширует пароль алгоритмом bash256 (СТБ 34.101.47-2017) с криптографической солью."""
    from client.crypto.bee2_wrapper import engine
    if salt is None:
        salt = secrets.token_hex(16)
    digest = engine.bash256(f"STB_PWD_SALT:{salt}:{password}".encode("utf-8")).hex()
    return digest, salt


def verify_user_password(password: str, salt: str, expected_hash: str) -> bool:
    """Проверяет пароль пользователя по хэшу bash256."""
    from client.crypto.bee2_wrapper import engine
    computed = engine.bash256(f"STB_PWD_SALT:{salt}:{password}".encode("utf-8")).hex()
    return hmac.compare_digest(computed, expected_hash)


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
                        password_salt TEXT
                    );
                """)

                # Миграция: добавляем колонки password_hash и password_salt если они отсутствуют
                try:
                    cols = [c[1] for c in self._conn.execute("PRAGMA table_info(users)").fetchall()]
                    if "password_hash" not in cols:
                        self._conn.execute("ALTER TABLE users ADD COLUMN password_hash TEXT;")
                    if "password_salt" not in cols:
                        self._conn.execute("ALTER TABLE users ADD COLUMN password_salt TEXT;")
                except Exception as m_err:
                    logger.debug(f"Миграция колонок users: {m_err}")

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

        logger.info(f"База данных SQLite успешно инициализирована: {self.db_path}")

    def register_user_with_password(
        self,
        user_id: str,
        public_key: str,
        password: str,
        ip_address: str = "127.0.0.1",
        client_version: str = "2.1.0",
    ) -> bool:
        """Регистрирует нового пользователя с хэшированием пароля по СТБ 34.101.47-2017 (bash256)."""
        with self._lock:
            pwd_hash, pwd_salt = hash_user_password(password)
            now = datetime.now(timezone.utc).isoformat()
            if self._conn is None:
                return False

            with self._conn:
                existing = self._conn.execute(
                    "SELECT user_id FROM users WHERE user_id = ?",
                    (user_id,),
                ).fetchone()

                if existing is None:
                    self._conn.execute(
                        """
                        INSERT INTO users (
                            user_id, public_key, registered_at, last_seen_at, status, client_version, ip_address, password_hash, password_salt
                        ) VALUES (?, ?, ?, ?, 'active', ?, ?, ?, ?)
                        """,
                        (user_id, public_key, now, now, client_version, ip_address, pwd_hash, pwd_salt),
                    )
                    self._conn.execute(
                        "INSERT INTO audit_log (timestamp, event_type, user_id, details) VALUES (?, ?, ?, ?)",
                        (now, "USER_REGISTER", user_id, "Регистрация учетной записи абонента"),
                    )
                else:
                    self._conn.execute(
                        """
                        UPDATE users
                        SET public_key = ?, last_seen_at = ?, client_version = ?, ip_address = ?, password_hash = ?, password_salt = ?
                        WHERE user_id = ?
                        """,
                        (public_key, now, client_version, ip_address, pwd_hash, pwd_salt, user_id),
                    )
            return True

    def verify_user_credentials(self, user_id: str, password: str) -> tuple[bool, Optional[str], str]:
        """
        Проверяет подлинность пароля пользователя по хэшу bash256.
        Возвращает (успех: bool, открытый_ключ: Optional[str], сообщение: str).
        """
        with self._lock:
            if self._conn is None:
                return False, None, "База данных сервера недоступна"

            row = self._conn.execute(
                "SELECT user_id, public_key, status, password_hash, password_salt FROM users WHERE user_id = ?",
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
                new_hash, new_salt = hash_user_password(password)
                with self._conn:
                    self._conn.execute(
                        "UPDATE users SET password_hash = ?, password_salt = ?, last_seen_at = ? WHERE user_id = ?",
                        (new_hash, new_salt, now, user_id),
                    )
                return True, row["public_key"], "Вход выполнен успешно"

            if verify_user_password(password, pwd_salt, pwd_hash):
                now = datetime.now(timezone.utc).isoformat()
                with self._conn:
                    self._conn.execute("UPDATE users SET last_seen_at = ? WHERE user_id = ?", (now, user_id))
                    self._conn.execute(
                        "INSERT INTO audit_log (timestamp, event_type, user_id, details) VALUES (?, ?, ?, ?)",
                        (now, "USER_LOGIN_SUCCESS", user_id, "Успешная проверка учетных данных"),
                    )
                return True, row["public_key"], "Вход выполнен успешно"
            else:
                now = datetime.now(timezone.utc).isoformat()
                with self._conn:
                    self._conn.execute(
                        "INSERT INTO audit_log (timestamp, event_type, user_id, details) VALUES (?, ?, ?, ?)",
                        (now, "USER_LOGIN_FAILED", user_id, "Ошибка аутентификации: неверный пароль"),
                    )
                return False, None, "Неверный пароль! Проверьте правильность ввода."

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
                    SELECT user_id, public_key, registered_at, last_seen_at, status, client_version, ip_address
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
                    SELECT user_id, public_key, registered_at, last_seen_at, status, client_version, ip_address
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
        ]
        writer = csv.DictWriter(output, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        for u in users:
            writer.writerow(u)
        return output.getvalue()

    def clear_all(self) -> None:
        """Очищает содержимое всех таблиц (для изоляции тестовых прогонов)."""
        with self._lock:
            if self._conn is not None:
                with self._conn:
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
