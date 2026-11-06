"""
Маршрутизатор API безопасного обновления ПО (ПЗ-4).
Реализует REST-эндпоинты:
  * GET  /updates/check?os=...&arch=...&version=...  (проверка наличия новой версии)
  * GET  /updates/manifest/{version}                (получение подписанного манифеста)
  * POST /updates/request_token                     (запрос одноразового download_token)
  * GET  /updates/download/{version}                (скачивание ZIP-пакета обновления)
  * GET  /updates/sbom/{version}.json               (получение SBOM CycloneDX 1.5)
  * POST /updates/report                            (фиксация статуса обновления)
  * POST /updates/publish                           (публикация нового релиза)
"""

import json
import logging
import os
import secrets
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

import jwt
from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel, Field

from common.update_crypto import (
    calculate_sha256,
    canonicalize_manifest,
    load_private_key,
    load_public_key,
    sign_manifest,
    verify_manifest,
)
from server.database import db_manager

logger = logging.getLogger("secure_chat.update_router")

# Секретный ключ для подписи и верификации JWT-токенов доступа
JWT_SECRET_KEY = os.getenv("UPDATE_JWT_SECRET", "SECURE_CHAT_UPDATE_JWT_SECRET_2026_RB")
JWT_ALGORITHM = "HS256"

# Хранилище одноразовых токенов скачивания: token -> {user_id, device_id, version, expires_at}
_active_download_tokens: Dict[str, Dict[str, Any]] = {}

update_router = APIRouter(prefix="/updates", tags=["Безопасное обновление ПО"])


def create_update_jwt(user_id: str, device_id: Optional[str] = None, expires_sec: int = 3600) -> str:
    """Генерирует JWT-токен авторизации для клиента обновлений."""
    now = int(time.time())
    payload = {
        "sub": user_id,
        "device_id": device_id or "default_device",
        "iat": now,
        "exp": now + expires_sec,
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def decode_update_jwt(token: str) -> Dict[str, Any]:
    """Декодирует и верифицирует JWT-токен."""
    try:
        return jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Срок действия токена авторизации (JWT) истек",
        )
    except jwt.InvalidTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Недействительный токен авторизации (JWT): {exc}",
        )


async def get_current_user(
    request: Request,
    authorization: Optional[str] = Header(None),
    token_param: Optional[str] = Query(None, alias="token"),
) -> Dict[str, Any]:
    """Извлекает и проверяет JWT-токен из заголовка Authorization или query-параметра token."""
    raw_token = None
    if authorization:
        parts = authorization.split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            raw_token = parts[1]
        elif len(parts) == 1:
            raw_token = parts[0]
    elif token_param:
        raw_token = token_param

    if not raw_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Отсутствует токен авторизации (Authorization: Bearer <token> или ?token=...)",
        )

    return decode_update_jwt(raw_token)


def create_download_token(user_id: str, device_id: str, version: str, ttl_sec: int = 300) -> str:
    """Генерирует одноразовый токен для скачивания пакета обновления."""
    clean_expired_download_tokens()
    tok = secrets.token_urlsafe(32)
    _active_download_tokens[tok] = {
        "user_id": user_id,
        "device_id": device_id,
        "version": version,
        "expires_at": time.time() + ttl_sec,
    }
    return tok


def verify_and_consume_download_token(token: str, version: str) -> bool:
    """Проверяет и уничтожает одноразовый download_token."""
    clean_expired_download_tokens()
    entry = _active_download_tokens.pop(token, None)
    if not entry:
        return False
    if entry["expires_at"] < time.time():
        return False
    if entry["version"] != version:
        return False
    return True


def clean_expired_download_tokens() -> None:
    """Очищает устаревшие токены скачивания."""
    now = time.time()
    expired = [k for k, v in _active_download_tokens.items() if v["expires_at"] < now]
    for k in expired:
        _active_download_tokens.pop(k, None)


# --- Модели запросов и ответов ---


class UpdateCheckResponse(BaseModel):
    update_available: bool
    version: Optional[str] = None
    min_supported: Optional[str] = None
    manifest_url: Optional[str] = None


class RequestDownloadTokenRequest(BaseModel):
    version: str
    device_id: str


class DownloadTokenResponse(BaseModel):
    download_token: str
    expires_in: int


class UpdateReportRequest(BaseModel):
    device_id: Optional[str] = "unknown"
    from_version: Optional[str] = None
    to_version: Optional[str] = None
    status: str = Field(..., description="downloaded | verified | installed | failed | rolled_back | sbom_mismatch")


class PublishReleaseRequest(BaseModel):
    version: str
    os: str = "windows"
    arch: str = "x64"
    min_supported: str = "1.0.0"
    package_path: str
    manifest_path: str
    sbom_path: Optional[str] = None
    package_sha256: Optional[str] = None
    signature: Optional[str] = None


class AuthTokenRequest(BaseModel):
    user_id: str = "client_user"
    device_id: Optional[str] = "client_device"


# --- Конечные точки (Endpoints) ---


@update_router.post("/auth/token", tags=["Безопасное обновление ПО"])
async def issue_auth_token(req: AuthTokenRequest):
    """Выпуск JWT-токена для клиента обновлений (для авторизованных запросов к /updates/*)."""
    token = create_update_jwt(user_id=req.user_id, device_id=req.device_id)
    return {"access_token": token, "token_type": "bearer", "expires_in": 3600}


@update_router.get("/check", response_model=UpdateCheckResponse)
async def check_for_updates(
    os: str = Query("windows", description="Операционная система клиента"),
    arch: str = Query("x64", description="Архитектура процессора"),
    version: str = Query("1.0.0", description="Текущая версия установленного клиента"),
    user_data: Dict[str, Any] = Depends(get_current_user),
):
    """
    Проверяет наличие новой версии ПО для указанной платформы.
    Требует JWT-авторизацию.
    """
    latest = db_manager.get_latest_release(os_name=os, arch=arch)
    if not latest:
        return UpdateCheckResponse(
            update_available=False,
            version=None,
            min_supported=None,
            manifest_url=None,
        )

    from packaging.version import parse as parse_ver

    try:
        latest_clean = latest["version"].split("-")[0]
        current_clean = version.split("-")[0]
        has_new_version = parse_ver(latest_clean) > parse_ver(current_clean)
    except Exception:
        has_new_version = latest["version"] != version

    return UpdateCheckResponse(
        update_available=has_new_version,
        version=latest["version"],
        min_supported=latest.get("min_supported", "1.0.0"),
        manifest_url=f"/updates/manifest/{latest['version']}" if has_new_version else None,
    )


@update_router.get("/manifest/{version}")
async def get_manifest(
    version: str,
    user_data: Dict[str, Any] = Depends(get_current_user),
):
    """
    Возвращает подписанный манифест релиза с цифровой подписью Ed25519.
    Требует JWT-авторизацию.
    """
    release = db_manager.get_release(version)
    if not release:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Релиз версии '{version}' не зарегистрирован на сервере",
        )

    manifest_path = Path(release["manifest_path"])
    if not manifest_path.is_file():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Файл манифеста для релиза {version} не найден на диске",
        )

    content = manifest_path.read_text(encoding="utf-8")
    manifest_dict = json.loads(content)

    # Убеждаемся, что цифровая подпись присутствует
    if not manifest_dict.get("signature") and release.get("signature"):
        manifest_dict["signature"] = release["signature"]

    return manifest_dict


@update_router.post("/request_token", response_model=DownloadTokenResponse)
async def request_download_token(
    req: RequestDownloadTokenRequest,
    user_data: Dict[str, Any] = Depends(get_current_user),
):
    """
    Выдает одноразовый download_token для скачивания пакета релиза.
    Токен привязан к JWT (user_id), device_id и версии ПО.
    """
    release = db_manager.get_release(req.version)
    if not release:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Релиз версии '{req.version}' не найден",
        )

    user_id = user_data.get("sub", "unknown")
    tok = create_download_token(user_id=user_id, device_id=req.device_id, version=req.version, ttl_sec=300)
    return DownloadTokenResponse(download_token=tok, expires_in=300)


@update_router.get("/download/{version}")
async def download_package(
    version: str,
    token: Optional[str] = Query(None, description="Одноразовый download_token"),
    x_download_token: Optional[str] = Header(None, alias="X-Download-Token"),
    user_data: Dict[str, Any] = Depends(get_current_user),
):
    """
    Скачивание ZIP-пакета релиза.
    Требует JWT-авторизацию и валидный одноразовый download_token.
    """
    download_tok = x_download_token or token
    if not download_tok:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Отсутствует одноразовый токен скачивания (download_token)",
        )

    if not verify_and_consume_download_token(download_tok, version):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="download_token недействителен, просрочен или уже был использован",
        )

    release = db_manager.get_release(version)
    if not release:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Релиз версии '{version}' не найден",
        )

    pkg_path = Path(release["package_path"])
    if not pkg_path.is_file():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Пакет обновления {pkg_path.name} не найден на сервере",
        )

    return FileResponse(
        path=str(pkg_path),
        filename=pkg_path.name,
        media_type="application/zip",
    )


@update_router.get("/sbom/{version}.json")
async def get_sbom(
    version: str,
    user_data: Dict[str, Any] = Depends(get_current_user),
):
    """
    Возвращает спецификацию компонентов SBOM в формате CycloneDX 1.5 JSON.
    Требует JWT-авторизацию.
    """
    release = db_manager.get_release(version)
    if not release:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Релиз версии '{version}' не найден",
        )

    sbom_path = release.get("sbom_path")
    if not sbom_path or not Path(sbom_path).is_file():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Файл SBOM для релиза {version} не найден",
        )

    content = Path(sbom_path).read_text(encoding="utf-8")
    return json.loads(content)


@update_router.post("/report")
async def report_update_status(
    req: UpdateReportRequest,
    request: Request,
    user_data: Dict[str, Any] = Depends(get_current_user),
):
    """
    Фиксация статуса установки обновления клиентом в журнале update_audit.
    Требует JWT-авторизацию.
    """
    user_id = user_data.get("sub", "unknown")
    client_ip = request.client.host if request.client else "127.0.0.1"
    now_ts = datetime.now(timezone.utc).isoformat()

    success = db_manager.record_update_audit(
        user_id=user_id,
        device_id=req.device_id,
        from_version=req.from_version,
        to_version=req.to_version,
        status=req.status,
        ip=client_ip,
        ts=now_ts,
    )

    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Не удалось записать статус обновления в аудит",
        )

    return {
        "status": "ok",
        "recorded": True,
        "detail": f"Статус '{req.status}' успешно зафиксирован",
    }


@update_router.get("/audit", tags=["Безопасное обновление ПО"])
async def get_update_audit(
    limit: int = Query(100, ge=1, le=1000),
    user_id: Optional[str] = Query(None),
    user_data: Dict[str, Any] = Depends(get_current_user),
):
    """Возвращает журнал аудита обновлений ПО."""
    return db_manager.get_update_audit_logs(limit=limit, user_id=user_id)


@update_router.post("/publish", tags=["Безопасное обновление ПО"])
async def publish_release_endpoint(req: PublishReleaseRequest):
    """
    Регистрация нового релиза ПО на сервере.
    Если хэш и подпись не переданы, они вычисляются автоматически.
    """
    result = publish_release(
        version=req.version,
        os_name=req.os,
        arch=req.arch,
        min_supported=req.min_supported,
        package_path=req.package_path,
        manifest_path=req.manifest_path,
        sbom_path=req.sbom_path,
        package_sha256=req.package_sha256,
        signature=req.signature,
    )
    if not result:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Не удалось опубликовать релиз",
        )
    return {"status": "ok", "message": f"Релиз {req.version} успешно опубликован"}


def publish_release(
    version: str,
    os_name: str,
    arch: str,
    package_path: str,
    manifest_path: str,
    min_supported: str = "1.0.0",
    sbom_path: Optional[str] = None,
    package_sha256: Optional[str] = None,
    signature: Optional[str] = None,
) -> bool:
    """
    Вспомогательная функция для публикации релиза в базу данных.
    Автоматически вычисляет SHA-256 пакета и подписывает манифест ключом Ed25519 при необходимости.
    """
    pkg_p = Path(package_path)
    if not pkg_p.is_file():
        logger.error(f"Файл пакета не существует: {package_path}")
        return False

    if not package_sha256:
        package_sha256 = calculate_sha256(pkg_p)

    man_p = Path(manifest_path)
    if not man_p.is_file():
        logger.error(f"Файл манифеста не существует: {manifest_path}")
        return False

    manifest_data = json.loads(man_p.read_text(encoding="utf-8"))

    if not signature:
        if "signature" in manifest_data and manifest_data["signature"]:
            signature = manifest_data["signature"]
        else:
            signed_manifest = sign_manifest(manifest_data)
            signature = signed_manifest["signature"]
            man_p.write_text(json.dumps(signed_manifest, indent=2, ensure_ascii=False), encoding="utf-8")

    return db_manager.add_release(
        version=version,
        os_name=os_name,
        arch=arch,
        package_path=str(pkg_p.resolve()),
        package_sha256=package_sha256,
        manifest_path=str(man_p.resolve()),
        sbom_path=str(Path(sbom_path).resolve()) if sbom_path else None,
        signature=signature,
        min_supported=min_supported,
    )
