"""
Pydantic-модели валидации структур данных серверного REST API «Secure Chat».
"""

from typing import List, Optional
from pydantic import BaseModel, Field, field_validator


class RegisterRequest(BaseModel):
    """Модель регистрации открытого ключа пользователя."""
    user_id: str = Field(..., min_length=1, max_length=64, description="Уникальный идентификатор (псевдоним) пользователя")
    public_key: str = Field(..., min_length=32, description="Открытый ключ bign (шестнадцатеричная или Base64 строка)")

    @field_validator("user_id")
    @classmethod
    def validate_user_id(cls, v: str) -> str:
        v_clean = v.strip()
        if not v_clean:
            raise ValueError("Идентификатор пользователя не может состоять только из пробелов")
        return v_clean

    @field_validator("public_key")
    @classmethod
    def validate_public_key(cls, v: str) -> str:
        clean = v.strip()
        if len(clean) < 32:
            raise ValueError("Открытый ключ bign слишком короткий (минимум 32 символа)")
        return clean


class UserResponse(BaseModel):
    """Модель профиля зарегистрированного пользователя."""
    user_id: str
    public_key: str


class SendMessageRequest(BaseModel):
    """Модель пересылки зашифрованного пакета адресату."""
    from_id: str = Field(..., min_length=1, max_length=64)
    to_id: str = Field(..., min_length=1, max_length=64)
    ciphertext: str = Field(..., min_length=1, description="Шифротекст belt-che (Base64)")
    nonce: str = Field(..., min_length=1, description="Синхропосылка IV (Base64)")
    mac: str = Field(..., min_length=1, description="Имитовставка MAC (Base64)")
    encrypted_key: str = Field(..., min_length=1, description="Зашифрованный сессионный ключ bign-keytrans (Base64)")
    signature: str = Field(..., min_length=1, description="Цифровая подпись bign-sign (Base64)")


class MessageItem(BaseModel):
    """Модель входящего сообщения для получателя."""
    from_id: str
    ciphertext: str
    nonce: str
    mac: str
    encrypted_key: str
    signature: str
    timestamp: float


class StatusResponse(BaseModel):
    """Унифицированный ответ со статусом операции."""
    status: str
    detail: Optional[str] = None


class HealthResponse(BaseModel):
    """Ответ проверки работоспособности узла."""
    status: str
    registered_users: int
    pending_messages: int


class UpdateUserStatusRequest(BaseModel):
    """Модель запроса на изменение административного статуса пользователя."""
    status: str = Field(..., min_length=1, max_length=32, description="Новый статус ('active', 'suspended', 'blocked')")

    @field_validator("status")
    @classmethod
    def validate_status(cls, v: str) -> str:
        clean = v.strip().lower()
        if clean not in ("active", "suspended", "blocked"):
            raise ValueError("Недопустимый статус. Разрешены: 'active', 'suspended', 'blocked'")
        return clean


class DbStatsResponse(BaseModel):
    """Модель агрегированной статистики базы данных."""
    enabled: bool = True
    user_count: int
    active_count: int
    log_count: int
    db_size_bytes: int


class DbStatusResponse(BaseModel):
    """Модель детального статуса и режима работы базы данных сервера."""
    enabled: bool
    db_path: str
    user_count_in_db: int
    user_count_in_memory: int
    log_count: int
    db_size_bytes: int


class SetDbStatusRequest(BaseModel):
    """Модель запроса на включение/выключение персистентной базы данных."""
    enabled: bool
    sync_memory_to_db: bool = True


class DbUserResponse(BaseModel):
    """Модель расширенного профиля пользователя из БД."""
    user_id: str
    public_key: str
    registered_at: str
    last_seen_at: str
    status: str
    client_version: Optional[str] = None
    ip_address: Optional[str] = None


class AuditLogResponse(BaseModel):
    """Модель записи системного журнала аудита безопасности."""
    id: int
    timestamp: str
    event_type: str
    user_id: Optional[str] = None
    details: Optional[str] = None


class UserRegisterRequest(BaseModel):
    """Модель регистрации нового пользователя с паролем и открытым ключом bign."""
    user_id: str = Field(..., min_length=2, max_length=64, description="Логин пользователя")
    password: str = Field(..., min_length=3, max_length=128, description="Пароль пользователя")
    public_key: str = Field(..., min_length=32, description="Открытый ключ bign")

    @field_validator("user_id")
    @classmethod
    def validate_user_id(cls, v: str) -> str:
        v_clean = v.strip()
        if not v_clean:
            raise ValueError("Идентификатор пользователя не может состоять только из пробелов")
        return v_clean

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        if not v or len(v.strip()) < 3:
            raise ValueError("Пароль должен содержать минимум 3 символа")
        return v


class UserLoginRequest(BaseModel):
    """Модель аутентификации пользователя по логину и паролю."""
    user_id: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=1, max_length=128)


class AuthResponse(BaseModel):
    """Модель ответа на запрос аутентификации или регистрации."""
    success: bool
    message: str
    user_id: str
    public_key: Optional[str] = None
