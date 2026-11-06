"""
Основное приложение REST API сервера «Secure Chat» (FastAPI / Uvicorn).
Реализует спецификацию ТЗ на маршрутизацию зашифрованных пакетов
и администрирование базы данных абонентов и аудита.
"""

import time
import sys
import logging
from pathlib import Path
from contextlib import asynccontextmanager
from typing import List, Optional

# Поддержка прямого запуска скрипта: py server/app.py
if __name__ == "__main__" and not __package__:
    ROOT_DIR = Path(__file__).resolve().parent.parent
    if str(ROOT_DIR) not in sys.path:
        sys.path.insert(0, str(ROOT_DIR))
    import server
    __package__ = "server"

from fastapi import FastAPI, HTTPException, Query, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware

from .config import settings
from .database import db_manager
from .models import (
    RegisterRequest,
    UserResponse,
    SendMessageRequest,
    MessageItem,
    StatusResponse,
    HealthResponse,
    UpdateUserStatusRequest,
    DbStatsResponse,
    DbUserResponse,
    AuditLogResponse,
    DbStatusResponse,
    SetDbStatusRequest,
    UserRegisterRequest,
    UserLoginRequest,
    AuthResponse,
)
from .storage import storage
from common.build_info import BuildInfo, get_build_info
from .update_router import update_router, create_update_jwt
from .auth_router import auth_router

logging.basicConfig(
    level=settings.log_level,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("secure_chat.server")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Жизненный цикл серверного приложения."""
    logger.info("Сервер «Secure Chat» (маршрутизатор E2EE и SQLite БД) запущен.")
    yield
    try:
        db_manager.close()
        logger.info("База данных SQLite закрыта, WAL-журнал сброшен.")
    except Exception as exc:
        logger.warning(f"Ошибка при закрытии базы данных: {exc}")
    logger.info("Сервер «Secure Chat» остановлен.")


app = FastAPI(
    title="Secure Chat Server (Belarusian-STB / Bee2)",
    description="Высокопроизводительный сервер-ретранслятор зашифрованных сообщений с поддержкой SQLite",
    version="2.1.0",
    lifespan=lifespan,
)

# Разрешение CORS для веб-клиентов и кросс-доменных вызовов
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router)
app.include_router(update_router)


@app.get("/health", response_model=HealthResponse, tags=["Системные"])
async def health_check():
    """Проверка доступности и текущего состояния сервиса."""
    users_cnt, msgs_cnt = storage.count_stats()
    return HealthResponse(
        status="healthy",
        registered_users=users_cnt,
        pending_messages=msgs_cnt,
    )


@app.get("/version", response_model=BuildInfo, tags=["Системные"])
async def get_version():
    """
    Получение метаданных сборки, версии и поддерживаемых криптографических стандартов СТБ.
    """
    return get_build_info()


# Маршруты /register, /login, /logout, /me вынесены в auth_router (ПЗ-3)


@app.get("/users", response_model=List[UserResponse], tags=["Пользователи"])
async def list_users():
    """
    Получение списка всех зарегистрированных участников системы с их открытыми ключами.
    """
    return storage.get_users()


@app.get("/users/{user_id}", response_model=UserResponse, tags=["Пользователи"])
async def get_user_public_key(user_id: str):
    """
    Получение открытого ключа конкретного абонента для инициализации защищенного сеанса связи.
    """
    user = storage.get_user(user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Пользователь '{user_id}' не найден на сервере",
        )
    return user


@app.post("/send", response_model=StatusResponse, status_code=status.HTTP_200_OK, tags=["Сообщения"])
async def send_message(req: SendMessageRequest, request: Request):
    """
    Маршрутизация зашифрованного пакета во входящую очередь адресата.
    Сервер не выполняет расшифрование и не имеет доступа к открытому тексту.
    """
    if not storage.user_exists(req.to_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Адресат '{req.to_id}' не зарегистрирован в системе",
        )

    msg = MessageItem(
        from_id=req.from_id,
        ciphertext=req.ciphertext,
        nonce=req.nonce,
        mac=req.mac,
        encrypted_key=req.encrypted_key,
        signature=req.signature,
        timestamp=time.time(),
    )

    success = storage.add_message(req.to_id, msg)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Не удалось поместить сообщение в очередь доставки",
        )

    client_ip = request.client.host if request.client else "127.0.0.1"
    storage.update_last_seen(req.from_id, ip_address=client_ip)

    logger.debug(f"Пакет от '{req.from_id}' для '{req.to_id}' принят в очередь.")
    return StatusResponse(status="delivered")


@app.get("/inbox/{user_id}", response_model=List[MessageItem], tags=["Сообщения"])
async def get_inbox(user_id: str, request: Request):
    """
    Деструктивная выгрузка очереди входящих сообщений (POP).
    Все извлеченные сообщения немедленно удаляются из оперативной памяти сервера.
    """
    messages = storage.pop_messages(user_id)
    client_ip = request.client.host if request.client else "127.0.0.1"
    storage.update_last_seen(user_id, ip_address=client_ip)
    return messages


# --- Административные конечные точки управления БД ---


@app.get("/admin/db/status", response_model=DbStatusResponse, tags=["Администрирование"])
async def get_admin_db_status():
    """
    Возвращает статус активности базы данных:
    Включена ли персистентность открытых ключей и статистика ОЗУ/диска.
    """
    stats = db_manager.get_stats()
    mem_users_cnt, _ = storage.count_stats()
    return DbStatusResponse(
        enabled=stats.get("enabled", True),
        db_path=stats.get("db_path", settings.database_path),
        user_count_in_db=stats.get("user_count", 0),
        user_count_in_memory=mem_users_cnt,
        log_count=stats.get("log_count", 0),
        db_size_bytes=stats.get("db_size_bytes", 0),
    )


@app.post("/admin/db/toggle", response_model=DbStatusResponse, tags=["Администрирование"])
async def toggle_admin_db_state():
    """
    Переключает режим активности базы данных:
    Включена -> Сохраняет открытые ключи абонентов на диске.
    Выключена -> Открытые ключи хранятся исключительно в оперативной памяти (ОЗУ).
    """
    current_enabled = db_manager.is_enabled()
    new_enabled = not current_enabled
    storage.set_db_enabled(new_enabled, sync_memory=True)
    return await get_admin_db_status()


@app.post("/admin/db/status", response_model=DbStatusResponse, tags=["Администрирование"])
async def set_admin_db_status(req: SetDbStatusRequest):
    """Явно включает или выключает персистентную базу данных сервера."""
    storage.set_db_enabled(req.enabled, sync_memory=req.sync_memory_to_db)
    return await get_admin_db_status()


@app.get("/admin/db/stats", response_model=DbStatsResponse, tags=["Администрирование"])
async def get_admin_db_stats():
    """Возвращает агрегированные метрики состояния базы данных SQLite."""
    stats = db_manager.get_stats()
    return DbStatsResponse(**stats)


@app.get(
    "/admin/db/users",
    response_model=List[DbUserResponse],
    responses={200: {"content": {"text/csv": {}}}},
    tags=["Администрирование"],
)
async def get_admin_db_users(
    format: Optional[str] = Query(None, description="Формат вывода ('csv' или 'json')"),
    export: Optional[str] = Query(None, description="Псевдоним формата ('csv' или 'json')"),
):
    """
    Возвращает реестр пользователей из базы данных.
    При format='csv' или export='csv' возвращает документ CSV.
    """
    fmt = (format or export or "").lower()
    if fmt == "csv":
        csv_data = db_manager.export_users_csv()
        return Response(content=csv_data, media_type="text/csv")
    return db_manager.get_all_users()


@app.get("/admin/db/audit", response_model=List[AuditLogResponse], tags=["Администрирование"])
async def get_admin_db_audit(
    limit: int = Query(100, ge=1, le=1000, description="Максимальное число возвращаемых записей"),
    user_id: Optional[str] = Query(None, description="Фильтрация по идентификатору пользователя"),
):
    """Возвращает записи журнала аудита безопасности."""
    return db_manager.get_audit_logs(limit=limit, user_id=user_id)


@app.post("/admin/db/users/{user_id}/status", response_model=StatusResponse, tags=["Администрирование"])
async def update_admin_user_status(user_id: str, req: UpdateUserStatusRequest):
    """Изменяет статус учетной записи пользователя в базе данных."""
    user = db_manager.get_user(user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Пользователь '{user_id}' не найден в базе данных",
        )
    success = db_manager.update_user_status(user_id, req.status)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Не удалось обновить статус пользователя",
        )
    return StatusResponse(
        status="ok",
        detail=f"Статус пользователя '{user_id}' успешно изменен на '{req.status}'",
    )


@app.delete("/admin/db/users/{user_id}", response_model=StatusResponse, tags=["Администрирование"])
async def delete_admin_user(user_id: str):
    """Удаляет профиль пользователя из базы данных и ОЗУ сервера."""
    user = db_manager.get_user(user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Пользователь '{user_id}' не найден в базе данных",
        )
    storage.delete_user(user_id)
    return StatusResponse(
        status="ok",
        detail=f"Пользователь '{user_id}' успешно удален",
    )


if __name__ == "__main__":
    import uvicorn
    # Прямой запуск веб-сервера FastAPI
    print(f"[*] Запуск сервера «Secure Chat» на http://{settings.host}:{settings.port}")
    uvicorn.run(app, host=settings.host, port=settings.port)
