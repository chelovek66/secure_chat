"""
Маршрутизатор аутентификации, авторизации и управления сессиями (ПЗ-3).
Реализует:
  * Регистрацию и аутентификацию по PBKDF2-HMAC-SHA256 (не менее 200 000 итераций);
  * Привязку пользователей к отпечатку устройства (Device Fingerprint);
  * Сессионные токены (30 мин) с деавторизацией (/logout) и проверкой профиля (/me);
  * Полную совместимость с эндпоинтами /auth/register, /auth/login и базовым /register.
"""

import logging
from typing import Optional
from fastapi import APIRouter, HTTPException, Request, Header, status

from .models import (
    RegisterRequest,
    UserRegisterRequest,
    UserLoginRequest,
    AuthResponse,
    LoginResponse,
    MeResponse,
    StatusResponse,
)
from .storage import storage
from .database import db_manager

try:
    from .update_router import create_update_jwt
except Exception:
    create_update_jwt = None

logger = logging.getLogger("secure_chat.server.auth")

auth_router = APIRouter(tags=["Аутентификация"])


def get_active_db():
    """Возвращает активный экземпляр менеджера БД с учетом изоляции тестов в storage.db."""
    if storage.db is not None and storage.db.is_enabled():
        return storage.db
    return db_manager


def extract_bearer_token(authorization: Optional[str]) -> Optional[str]:
    """Извлекает Bearer токен из заголовка Authorization."""
    if not authorization:
        return None
    parts = authorization.strip().split()
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1].strip()
    if len(parts) == 1:
        return parts[0].strip()
    return None


@auth_router.post("/register", response_model=AuthResponse, status_code=status.HTTP_200_OK)
async def register(req: RegisterRequest, request: Request):
    """
    Регистрация пользователя.
    Поддерживает как регистрацию с паролем и Device Fingerprint (ПЗ-3),
    так и базовую регистрацию открытого ключа bign.
    """
    db = get_active_db()
    client_ip = request.client.host if request.client else "127.0.0.1"
    client_version = request.headers.get("X-Client-Version", "2.1.0")
    user_id = req.get_user_id()

    password = getattr(req, 'password', None)
    device_id = getattr(req, 'device_id', None)
    if password:
        # Регистрация с паролем по PBKDF2-HMAC-SHA256 (200 000 итераций) и отпечатком устройства
        if db is not None:
            db.register_user_with_password(
                user_id=user_id,
                public_key=req.public_key,
                password=password,
                device_id=device_id,
                ip_address=client_ip,
                client_version=client_version,
            )
        storage.register_user(
            user_id=user_id,
            public_key=req.public_key,
            ip_address=client_ip,
            client_version=client_version,
        )
        logger.info(f"Пользователь '{user_id}' зарегистрирован с паролем PBKDF2 и device_id='{req.device_id}'.")
        return AuthResponse(
            success=True,
            status="ok",
            message=f"Пользователь '{user_id}' успешно зарегистрирован",
            user_id=user_id,
            public_key=req.public_key,
            device_id=req.device_id,
        )
    else:
        # Регистрация только открытого ключа (совместимость со старыми клиентами)
        storage.register_user(
            user_id=user_id,
            public_key=req.public_key,
            ip_address=client_ip,
            client_version=client_version,
        )
        if db is not None:
            db.register_user(
                user_id=user_id,
                public_key=req.public_key,
                ip_address=client_ip,
                client_version=client_version,
            )
        logger.info(f"Зарегистрирован открытый ключ пользователя '{user_id}' (IP: {client_ip}).")
        return AuthResponse(
            success=True,
            status="ok",
            message=f"Открытый ключ пользователя '{user_id}' зарегистрирован",
            user_id=user_id,
            public_key=req.public_key,
        )


@auth_router.post("/auth/register", response_model=AuthResponse, status_code=status.HTTP_200_OK)
async def auth_register(req: UserRegisterRequest, request: Request):
    """
    Регистрация пользователя через эндпоинт /auth/register (обратная совместимость).
    """
    db = get_active_db()
    client_ip = request.client.host if request.client else "127.0.0.1"
    client_version = request.headers.get("X-Client-Version", "2.1.0")
    user_id = req.get_user_id()

    if db is not None:
        db.register_user_with_password(
            user_id=user_id,
            public_key=req.public_key,
            password=req.password,
            device_id=req.device_id,
            ip_address=client_ip,
            client_version=client_version,
        )

    storage.register_user(
        user_id=user_id,
        public_key=req.public_key,
        ip_address=client_ip,
        client_version=client_version,
    )

    logger.info(f"Аутентификация: пользователь '{user_id}' успешно зарегистрирован.")
    jwt_token = create_update_jwt(user_id=user_id) if create_update_jwt else None
    return AuthResponse(
        success=True,
        status="ok",
        message=f"Пользователь '{user_id}' успешно зарегистрирован",
        user_id=user_id,
        public_key=req.public_key,
        device_id=req.device_id,
        access_token=jwt_token,
    )


@auth_router.post("/login", response_model=LoginResponse, status_code=status.HTTP_200_OK)
async def login(req: UserLoginRequest, request: Request):
    """
    Аутентификация пользователя (ПЗ-3):
      * Проверка логина и пароля по PBKDF2-HMAC-SHA256 (200 000 итераций) или bash256;
      * Проверка совпадения Device Fingerprint (device_id);
      * При несовпадении device_id -> HTTP 403 Forbidden «Вход с незнакомого устройства»;
      * При неверном пароле / отсутствии пользователя -> HTTP 401 Unauthorized;
      * При успехе -> генерация токена сессии в таблице sessions и возврат профиля.
    """
    db = get_active_db()
    user_id = req.get_user_id()

    if db is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="База данных сервера недоступна",
        )

    success, pubkey, msg = db.verify_user_credentials(
        user_id=user_id,
        password=req.password,
        device_id=req.device_id,
    )

    if not success:
        if "Вход с незнакомого устройства" in msg:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Вход с незнакомого устройства",
            )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=msg or "Неверный логин или пароль",
        )

    # Генерация токена сессии
    token = db.create_session(
        user_id=user_id,
        device_id=req.device_id,
        expires_in_seconds=1800,
    )

    if pubkey:
        storage.register_user(user_id, pubkey)

    logger.info(f"Успешный вход пользователя '{user_id}' (device_id={req.device_id}). Выдан токен сессии.")

    return LoginResponse(
        token=token,
        access_token=token,
        token_type="bearer",
        user_id=user_id,
        public_key=pubkey,
        device_id=req.device_id,
        expires_in=1800,
    )


@auth_router.post("/auth/login", response_model=AuthResponse, status_code=status.HTTP_200_OK)
async def auth_login(req: UserLoginRequest, request: Request):
    """
    Совместимый эндпоинт аутентификации /auth/login.
    Возвращает 200 OK с полем success: bool (для старых клиентов и тестов).
    """
    db = get_active_db()
    user_id = req.get_user_id()

    if db is not None:
        success, pubkey, msg = db.verify_user_credentials(
            user_id=user_id,
            password=req.password,
            device_id=req.device_id,
        )
        if not success:
            return AuthResponse(
                success=False,
                message=msg,
                user_id=user_id,
                public_key=None,
            )

        token = db.create_session(user_id=user_id, device_id=req.device_id, expires_in_seconds=1800)
        if pubkey:
            storage.register_user(user_id, pubkey)

        jwt_token = create_update_jwt(user_id=user_id) if create_update_jwt else None
        return AuthResponse(
            success=True,
            message=msg,
            user_id=user_id,
            public_key=pubkey,
            token=token,
            access_token=jwt_token or token,
            device_id=req.device_id,
        )

    # Резервный режим памяти
    mem_user = storage.get_user(user_id)
    if mem_user:
        return AuthResponse(
            success=True,
            message="Вход выполнен (режим ОЗУ)",
            user_id=user_id,
            public_key=mem_user.public_key,
        )

    return AuthResponse(
        success=False,
        message=f"Пользователь '{user_id}' не найден",
        user_id=user_id,
        public_key=None,
    )


@auth_router.post("/logout", response_model=StatusResponse, status_code=status.HTTP_200_OK)
async def logout(
    request: Request,
    authorization: Optional[str] = Header(None),
):
    """
    Инвалидация текущей сессии/токена пользователя (/logout).
    Удаляет сессионную запись из таблицы sessions базы данных.
    """
    db = get_active_db()
    token = extract_bearer_token(authorization)

    # Также проверяем query/body если в заголовке нет
    if not token and request.query_params.get("token"):
        token = request.query_params.get("token")

    if token and db is not None:
        db.delete_session(token)
        logger.info("Сессия успешно отозвана (/logout).")

    return StatusResponse(
        status="ok",
        detail="Сессия успешно завершена",
    )


@auth_router.get("/me", response_model=MeResponse, status_code=status.HTTP_200_OK)
async def get_me(authorization: Optional[str] = Header(None)):
    """
    Проверка текущей сессии пользователя по заголовку Authorization: Bearer <token>.
    Возвращает актуальный профиль абонента и привязанный отпечаток устройства.
    """
    token = extract_bearer_token(authorization)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Отсутствует заголовок Authorization или токен Bearer",
        )

    db = get_active_db()
    if db is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="База данных сервера недоступна",
        )

    session = db.get_session(token)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Сессия недействительна или истек срок действия",
        )

    user_id = session["user_id"]
    user = db.get_user(user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Пользователь '{user_id}' не найден в базе данных",
        )

    return MeResponse(
        user_id=user["user_id"],
        login=user["user_id"],
        public_key=user["public_key"],
        device_id=session.get("device_id") or user.get("device_id"),
        status=user.get("status", "active"),
        registered_at=user.get("registered_at"),
        last_seen_at=user.get("last_seen_at"),
    )
