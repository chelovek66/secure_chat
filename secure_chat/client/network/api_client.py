"""
Отказоустойчивый сетевой HTTP-клиент для взаимодействия с REST API сервера «Secure Chat».
Реализует:
  * Пул соединений и автоматическое переиспользование сессий;
  * Настройку таймаутов на сетевой ввод-вывод;
  * Строгую типизацию запросов и ответов;
  * Обработку сетевых исключений без падения приложения.
"""

import logging
from typing import Any, List, Optional
import requests

logger = logging.getLogger("secure_chat.network.api")


class ApiClientError(Exception):
    """Базовое исключение сетевого клиента."""
    pass


class ApiConnectionError(ApiClientError):
    """Ошибка подключения (сервер недоступен, таймаут, сбой сети)."""
    pass


class ApiNotFoundError(ApiClientError):
    """Запрашиваемый ресурс или пользователь не найден (HTTP 404)."""
    pass


class ApiClient:
    """
    HTTP-шлюз клиентского приложения для взаимодействия с сервером.
    """

    DEFAULT_TIMEOUT_SEC = 5.0

    def __init__(self, base_url: str = "http://127.0.0.1:8000"):
        self.base_url = base_url.rstrip("/")
        self.user_id: Optional[str] = None
        # Хранение сессионного токена только в оперативной памяти (без записи на диск/лог)
        self._token: Optional[str] = None
        try:
            from common.fingerprint import get_device_fingerprint
            self.device_id: Optional[str] = get_device_fingerprint()
        except Exception:
            self.device_id = None

        self._session = requests.Session()
        self._session.headers.update({
            "User-Agent": "SecureChat-Client/2.0 (Belarusian-STB; Bee2-Engine)",
            "Accept": "application/json",
        })

    @property
    def token(self) -> Optional[str]:
        return self._token

    @token.setter
    def token(self, value: Optional[str]) -> None:
        self._token = value

    def set_base_url(self, url: str) -> None:
        """Обновляет базовый URL сервера."""
        self.base_url = url.rstrip("/")

    def _request(self, method: str, endpoint: str, **kwargs: Any) -> Any:
        silent = kwargs.pop("silent", False)
        url = f"{self.base_url}{endpoint}"
        kwargs.setdefault("timeout", self.DEFAULT_TIMEOUT_SEC)

        # Автоматическая отправка заголовка Authorization: Bearer <token>
        if self._token:
            req_headers = kwargs.get("headers", {})
            if "Authorization" not in req_headers:
                req_headers["Authorization"] = f"Bearer {self._token}"
                kwargs["headers"] = req_headers

        try:
            logger.debug(f"→ {method} {endpoint}")
            resp = self._session.request(method, url, **kwargs)
            if resp.status_code == 404:
                raise ApiNotFoundError(f"Ресурс не найден: {url}")
            resp.raise_for_status()
            logger.debug(f"← {resp.status_code} OK ({endpoint})")
            return resp.json()
        except requests.exceptions.ConnectionError as exc:
            if not silent:
                logger.warning(
                    f"Сервер {self.base_url} недоступен ({endpoint}): соединение отклонено (сервер не запущен)."
                )
            raise ApiConnectionError(f"Сервер {self.base_url} недоступен. Убедитесь, что сервер запущен.") from exc
        except requests.exceptions.Timeout as exc:
            if not silent:
                logger.warning(f"Таймаут соединения с сервером {self.base_url} ({endpoint}).")
            raise ApiConnectionError(f"Таймаут соединения с {self.base_url}") from exc
        except requests.exceptions.HTTPError as exc:
            if not silent:
                logger.error(f"HTTP ошибка от сервера {url} (код {resp.status_code}): {resp.text}")
            raise ApiClientError(f"Ошибка сервера (HTTP {resp.status_code}): {resp.text}") from exc
        except Exception as exc:
            if not silent:
                logger.error(f"Непредвиденная сетевая ошибка: {exc}")
            raise ApiClientError(f"Сетевой сбой: {exc}") from exc

    def check_health(self, timeout: float = 0.8) -> bool:
        """Проверяет доступность сервера через эндпоинт /health (тихий режим)."""
        try:
            data = self._request("GET", "/health", timeout=timeout, silent=True)
            return data.get("status") == "healthy"
        except Exception:
            return False

    def register(
        self,
        user_id: str,
        public_key_hex: str,
        password: Optional[str] = None,
        device_id: Optional[str] = None,
        silent: bool = False,
    ) -> Any:
        dev_id = device_id if device_id is not None else self.device_id
        payload = {
            "user_id": user_id,
            "login": user_id,
            "public_key": public_key_hex,
        }
        if password:
            payload["password"] = password
        if dev_id:
            payload["device_id"] = dev_id

        res = self._request("POST", "/register", json=payload, silent=silent)
        self.user_id = user_id
        if isinstance(res, dict):
            token = res.get("token") or res.get("access_token")
            if token:
                self._token = token
            if password:
                return res
        return res.get("status") == "ok"

    def login(
        self,
        login: str,
        password: str,
        device_id: Optional[str] = None,
        silent: bool = False,
    ) -> dict:
        dev_id = device_id if device_id is not None else self.device_id
        payload = {
            "login": login,
            "user_id": login,
            "password": password,
        }
        if dev_id:
            payload["device_id"] = dev_id

        res = self._request("POST", "/login", json=payload, silent=silent)
        self.user_id = login
        if isinstance(res, dict):
            token = res.get("token") or res.get("access_token")
            if token:
                self._token = token
        return res

    def logout(self, silent: bool = False) -> bool:
        try:
            res = self._request("POST", "/logout", silent=silent)
            return res.get("status") == "ok"
        finally:
            self._token = None

    def get_me(self, silent: bool = False) -> dict:
        return self._request("GET", "/me", silent=silent)

    def auth_register(
        self,
        user_id: str,
        password: str,
        public_key_hex: str,
        device_id: Optional[str] = None,
        silent: bool = False,
    ) -> dict:
        dev_id = device_id if device_id is not None else self.device_id
        payload = {
            "user_id": user_id,
            "login": user_id,
            "password": password,
            "public_key": public_key_hex,
        }
        if dev_id:
            payload["device_id"] = dev_id
        res = self._request("POST", "/auth/register", json=payload, silent=silent)
        self.user_id = user_id
        if isinstance(res, dict):
            token = res.get("token") or res.get("access_token")
            if token:
                self._token = token
        return res

    def auth_login(
        self,
        user_id: str,
        password: str,
        device_id: Optional[str] = None,
        silent: bool = False,
    ) -> dict:
        dev_id = device_id if device_id is not None else self.device_id
        payload = {
            "user_id": user_id,
            "login": user_id,
            "password": password,
        }
        if dev_id:
            payload["device_id"] = dev_id
        res = self._request("POST", "/auth/login", json=payload, silent=silent)
        self.user_id = user_id
        if isinstance(res, dict):
            token = res.get("token") or res.get("access_token")
            if token:
                self._token = token
        return res

    def get_users(self, silent: bool = False) -> List[dict]:
        """
        Запрашивает список зарегистрированных пользователей (GET /users).
        Возвращает: [{"user_id": str, "public_key": str}, ...]
        """
        return self._request("GET", "/users", silent=silent)

    def close(self) -> None:
        """Освобождает ресурсы сетевой сессии requests."""
        if hasattr(self, "_session") and self._session:
            try:
                self._session.close()
            except Exception:
                pass

    def get_user(self, user_id: str, silent: bool = False) -> Optional[dict]:
        """
        Запрашивает открытый ключ конкретного пользователя (GET /users/{user_id}).
        """
        try:
            return self._request("GET", f"/users/{user_id}", silent=silent)
        except ApiNotFoundError:
            return None

    def send_message(
        self,
        from_id: str,
        to_id: str,
        ciphertext: str,
        nonce: str,
        mac: str,
        encrypted_key: str,
        signature: str,
        silent: bool = False,
    ) -> bool:
        """
        Отправляет защищенный криптографический пакет адресату (POST /send).
        """
        payload = {
            "from_id": from_id,
            "to_id": to_id,
            "ciphertext": ciphertext,
            "nonce": nonce,
            "mac": mac,
            "encrypted_key": encrypted_key,
            "signature": signature,
        }
        logger.info(f"Сетевой вызов: передача зашифрованного пакета для '{to_id}' (POST /send)")
        res = self._request("POST", "/send", json=payload, silent=silent)
        return res.get("status") == "delivered"

    def get_inbox(self, user_id: str, silent: bool = True) -> List[dict]:
        """
        Извлекает и деструктивно очищает входящую очередь сообщений (GET /inbox/{user_id}).
        По умолчанию выполняется в тихом режиме для фонового опроса.
        """
        return self._request("GET", f"/inbox/{user_id}", silent=silent)

    def get_version(self, silent: bool = False) -> dict:
        """Запрашивает метаданные сборки и версии сервера (GET /version)."""
        return self._request("GET", "/version", silent=silent)

    def get_db_stats(self, silent: bool = False) -> dict:
        """Запрашивает статистику базы данных сервера (GET /admin/db/stats)."""
        return self._request("GET", "/admin/db/stats", silent=silent)

    def get_db_status(self, silent: bool = False) -> dict:
        """Запрашивает статус активности базы данных (GET /admin/db/status)."""
        return self._request("GET", "/admin/db/status", silent=silent)

    def toggle_db(self) -> dict:
        """Переключает режим активности базы данных (POST /admin/db/toggle)."""
        return self._request("POST", "/admin/db/toggle")

    def set_db_enabled(self, enabled: bool, sync_memory_to_db: bool = True) -> dict:
        """Включает или выключает персистентную базу данных (POST /admin/db/status)."""
        payload = {"enabled": enabled, "sync_memory_to_db": sync_memory_to_db}
        return self._request("POST", "/admin/db/status", json=payload)

    def get_db_users(self, silent: bool = False) -> List[dict]:
        """Запрашивает расширенный список пользователей из БД (GET /admin/db/users)."""
        return self._request("GET", "/admin/db/users", silent=silent)

    def get_db_audit_logs(self, limit: int = 100, user_id: Optional[str] = None, silent: bool = False) -> List[dict]:
        """Запрашивает журнал аудита безопасности сервера (GET /admin/db/audit)."""
        params = {"limit": limit}
        if user_id:
            params["user_id"] = user_id
        return self._request("GET", "/admin/db/audit", params=params, silent=silent)

    def update_user_status(self, user_id: str, status: str) -> bool:
        """Обновляет статус абонента (POST /admin/db/users/{user_id}/status)."""
        res = self._request("POST", f"/admin/db/users/{user_id}/status", json={"status": status})
        return res.get("status") == "ok"

    def delete_db_user(self, user_id: str) -> bool:
        """Удаляет абонента из базы данных (DELETE /admin/db/users/{user_id})."""
        res = self._request("DELETE", f"/admin/db/users/{user_id}")
        return res.get("status") == "ok"

