"""
Конфигурация серверного узла «Secure Chat».
Реализует безопасное чтение параметров из переменных окружения и .env файлов.
"""

import os
from pathlib import Path
from pydantic import BaseModel


class ServerConfig(BaseModel):
    """Настройки серверного приложения."""
    host: str = os.getenv("SECURE_CHAT_HOST", "0.0.0.0")
    port: int = int(os.getenv("SECURE_CHAT_PORT", "8000"))
    message_ttl_seconds: int = int(os.getenv("MESSAGE_TTL_SECONDS", "86400"))  # 24 часа
    max_queue_per_user: int = int(os.getenv("MAX_QUEUE_PER_USER", "1000"))
    log_level: str = os.getenv("LOG_LEVEL", "INFO")
    database_path: str = os.getenv("SECURE_CHAT_DB_PATH", str(Path(__file__).parent / "secure_chat.db"))
    database_enabled: bool = os.getenv("SECURE_CHAT_DB_ENABLED", "true").lower() in ("true", "1", "yes")


settings = ServerConfig()
