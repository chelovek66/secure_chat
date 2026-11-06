"""
Потокобезопасное хранилище сообщений и пользователей «Secure Chat».
Реализует концепцию «Слепого ретранслятора» (Blind Relay):
  * Сервер не хранит приватных ключей и не имеет доступа к открытому тексту;
  * Сообщения хранятся во временных очередях ОЗУ с принудительной деструктивной выборкой (POP);
  * Доступ синхронизирован мьютексом для исключения состояний гонки (Race Conditions);
  * Данные пользователей и открытые ключи синхронизируются с базой данных SQLite
    для персистентности между перезапусками сервера.
"""

import time
import threading
import logging
from typing import Dict, List, Optional
from .models import MessageItem, UserResponse
from .database import db_manager, DatabaseManager

logger = logging.getLogger("secure_chat.storage")


class Storage:
    """
    Потокобезопасный репозиторий данных оперативной памяти,
    синхронизируемый с персистентной базой данных SQLite.
    """

    def __init__(self, max_queue_size: int = 1000, db: Optional[DatabaseManager] = None):
        self._lock = threading.Lock()
        self._users: Dict[str, str] = {}  # user_id -> public_key
        self._inbox: Dict[str, List[MessageItem]] = {}  # user_id -> messages list
        self.max_queue_size = max_queue_size
        self.db = db if db is not None else db_manager
        self._load_from_db()

    def _load_from_db(self) -> None:
        """Загружает сохраненных пользователей из SQLite в оперативную память (если БД включена)."""
        if self.db is None or not self.db.is_enabled():
            logger.info("База данных выключена: хранение открытых ключей пользователей активно только в ОЗУ.")
            return
        try:
            users = self.db.get_all_users()
            with self._lock:
                for u in users:
                    uid = u["user_id"]
                    self._users[uid] = u["public_key"]
                    if uid not in self._inbox:
                        self._inbox[uid] = []
            logger.info(f"Загружено {len(users)} пользователей и открытых ключей из SQLite в ОЗУ.")
        except Exception as e:
            logger.warning(f"Не удалось загрузить пользователей из БД: {e}")

    def register_user(
        self,
        user_id: str,
        public_key: str,
        ip_address: str = "127.0.0.1",
        client_version: str = "2.1.0",
    ) -> bool:
        """Регистрирует или обновляет открытый ключ пользователя в ОЗУ и БД (при её включении)."""
        with self._lock:
            self._users[user_id] = public_key
            if user_id not in self._inbox:
                self._inbox[user_id] = []

        if self.db is not None and self.db.is_enabled():
            self.db.register_user(
                user_id=user_id,
                public_key=public_key,
                ip_address=ip_address,
                client_version=client_version,
            )
        return True

    def delete_user(self, user_id: str) -> bool:
        """Удаляет пользователя из ОЗУ и базы данных SQLite."""
        with self._lock:
            self._users.pop(user_id, None)
            self._inbox.pop(user_id, None)

        if self.db is not None and self.db.is_enabled():
            return self.db.delete_user(user_id)
        return True

    def update_last_seen(self, user_id: str, ip_address: Optional[str] = None) -> bool:
        """Обновляет отметку времени последней активности в БД."""
        if self.db is not None and self.db.is_enabled():
            return self.db.update_last_seen(user_id, ip_address)
        return False

    def update_user_status(self, user_id: str, status: str) -> bool:
        """Обновляет статус пользователя в БД."""
        if self.db is not None and self.db.is_enabled():
            return self.db.update_user_status(user_id, status)
        return False

    def get_users(self) -> List[UserResponse]:
        """Возвращает список всех зарегистрированных абонентов."""
        with self._lock:
            return [
                UserResponse(user_id=uid, public_key=pk)
                for uid, pk in self._users.items()
            ]

    def get_user(self, user_id: str) -> Optional[UserResponse]:
        """Возвращает информацию о конкретном пользователе."""
        with self._lock:
            pk = self._users.get(user_id)
            if pk is None and self.db is not None and self.db.is_enabled():
                db_user = self.db.get_user(user_id)
                if db_user is not None:
                    pk = db_user["public_key"]
                    self._users[user_id] = pk
                    if user_id not in self._inbox:
                        self._inbox[user_id] = []
            if pk is None:
                return None
            return UserResponse(user_id=user_id, public_key=pk)

    def user_exists(self, user_id: str) -> bool:
        """Проверяет факт регистрации пользователя."""
        with self._lock:
            if user_id in self._users:
                return True
            if self.db is not None and self.db.is_enabled():
                db_user = self.db.get_user(user_id)
                if db_user is not None:
                    self._users[user_id] = db_user["public_key"]
                    if user_id not in self._inbox:
                        self._inbox[user_id] = []
                    return True
            return False

    def add_message(self, to_id: str, message: MessageItem) -> bool:
        """Помещает зашифрованный пакет во входящую очередь адресата."""
        with self._lock:
            if to_id not in self._users:
                # Проверим, вдруг абонент есть в БД, но еще не кеширован
                if self.db is not None and self.db.is_enabled() and self.db.get_user(to_id) is not None:
                    db_u = self.db.get_user(to_id)
                    self._users[to_id] = db_u["public_key"]
                    self._inbox.setdefault(to_id, [])
                else:
                    return False

            queue = self._inbox.setdefault(to_id, [])
            if len(queue) >= self.max_queue_size:
                # Вытеснение самого старого сообщения при переполнении очереди
                queue.pop(0)

            queue.append(message)
            return True

    def pop_messages(self, user_id: str) -> List[MessageItem]:
        """
        Деструктивная выборка: извлекает все входящие сообщения для пользователя
        и немедленно удаляет их из оперативной памяти сервера.
        """
        with self._lock:
            if user_id not in self._inbox:
                return []
            messages = self._inbox[user_id]
            self._inbox[user_id] = []
            return messages

    def count_stats(self) -> tuple[int, int]:
        """Возвращает кортеж (число пользователей, суммарное число сообщений в очередях)."""
        with self._lock:
            total_msgs = sum(len(q) for q in self._inbox.values())
            return len(self._users), total_msgs

    def cleanup_expired(self, ttl_seconds: int) -> int:
        """Очищает сообщения, находящиеся в очередях дольше заданного TTL."""
        now = time.time()
        removed_count = 0
        with self._lock:
            for uid, q in self._inbox.items():
                fresh = [m for m in q if (now - m.timestamp) < ttl_seconds]
                removed_count += len(q) - len(fresh)
                self._inbox[uid] = fresh
        return removed_count

    def is_db_enabled(self) -> bool:
        """Проверяет, включено ли персистентное сохранение открытых ключей в БД."""
        return bool(self.db and self.db.is_enabled())

    def set_db_enabled(self, enabled: bool, sync_memory: bool = True) -> bool:
        """Переключает режим активности персистентной базы данных."""
        if self.db is None:
            return False
        res = self.db.set_enabled(enabled)
        if res and sync_memory and enabled:
            self.sync_from_db()
            self.sync_to_db()
        return res

    def sync_to_db(self) -> int:
        """Синхронизирует всех пользователей и открытые ключи из ОЗУ в базу данных."""
        if self.db is None or not self.db.is_enabled():
            return 0
        with self._lock:
            users_snapshot = list(self._users.items())
        count = 0
        for uid, pk in users_snapshot:
            if self.db.register_user(user_id=uid, public_key=pk):
                count += 1
        logger.info(f"Синхронизировано {count} открытых ключей из ОЗУ в базу данных SQLite.")
        return count

    def sync_from_db(self) -> int:
        """Загружает открытые ключи из базы данных в ОЗУ."""
        if self.db is None or not self.db.is_enabled():
            return 0
        users = self.db.get_all_users()
        with self._lock:
            for u in users:
                uid = u["user_id"]
                self._users[uid] = u["public_key"]
                self._inbox.setdefault(uid, [])
        logger.info(f"Загружено {len(users)} открытых ключей из базы данных SQLite в ОЗУ.")
        return len(users)

    def reset(self) -> None:
        """Полный сброс хранилища ОЗУ и базы данных SQLite (для тестов)."""
        with self._lock:
            self._users.clear()
            self._inbox.clear()
        if self.db is not None:
            self.db.clear_all()


storage = Storage()
