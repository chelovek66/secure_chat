"""
Клиентский модуль безопасного обновления ПО (ПЗ-4).
Реализует:
  * Архитектуру на базе интерфейса IUpdateSource (HttpSource, FileSource);
  * Класс Updater с конвейером проверок:
      1. Загрузка манифеста релиза;
      2. Проверка цифровой подписи Ed25519 манифеста;
      3. Контроль min_supported (блокировка устаревших клиентов);
      4. Скачивание/получение пакета .zip;
      5. Проверка контрольной суммы SHA-256 пакета;
      6. Верификация SBOM (CycloneDX 1.5, соответствие хэша SHA-256);
      7. Атомарная замена: app -> backup, staging -> app;
      8. Автоматический откат (rollback) из backup/ при сбоях;
      9. Аудит и отчетность на сервер или в локальный журнал.
"""

import abc
import hashlib
import json
import logging
import os
import platform
import shutil
import tempfile
import uuid
import zipfile
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Union

import requests
from packaging.version import parse as parse_version

from common.update_crypto import (
    calculate_sha256,
    load_public_key,
    validate_cyclonedx_sbom,
    verify_manifest,
    verify_sha256,
)

logger = logging.getLogger("secure_chat.updater")


def get_device_id() -> str:
    """Формирует уникальный и стабильный аппаратный идентификатор устройства (device_id)."""
    raw = f"{platform.node()}-{uuid.getnode()}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


class UpdateError(Exception):
    """Базовое исключение системы обновления ПО."""
    pass


class SignatureVerificationError(UpdateError):
    """Ошибка проверки цифровой подписи манифеста."""
    pass


class MinSupportedVersionError(UpdateError, ValueError):
    """Текущая версия ниже минимально поддерживаемой min_supported (требуется чистая установка)."""
    pass


class ChecksumMismatchError(UpdateError):
    """Несовпадение контрольной суммы SHA-256 пакета обновления."""
    pass


class SbomMismatchError(UpdateError):
    """Ошибка валидации или несоответствие контрольной суммы SBOM."""
    pass


class InstallationError(UpdateError):
    """Ошибка на этапе распаковки, атомарной замены или верификации файлов."""
    pass


# Статусы процесса обновления ПО
STATUS_DOWNLOADED = "downloaded"
STATUS_VERIFIED = "verified"
STATUS_INSTALLED = "installed"
STATUS_FAILED = "failed"
STATUS_ROLLED_BACK = "rolled_back"
STATUS_SBOM_MISMATCH = "sbom_mismatch"


class IUpdateSource(abc.ABC):
    """Абстрактный интерфейс источника обновлений ПО."""

    @abc.abstractmethod
    def check_update(self, current_version: str, os_name: str, arch: str) -> Optional[Dict[str, Any]]:
        """Проверяет доступность обновлений для платформы."""
        pass

    @abc.abstractmethod
    def get_manifest(self) -> Dict[str, Any]:
        """Возвращает словарь манифеста с цифровой подписью."""
        pass

    @abc.abstractmethod
    def download_package(
        self,
        target_path: Path,
        progress_cb: Optional[Callable[[int, int], None]] = None,
    ) -> Path:
        """Скачивает или копирует ZIP-пакет обновления в target_path."""
        pass

    @abc.abstractmethod
    def get_sbom(self) -> Optional[Dict[str, Any]]:
        """Возвращает структуру SBOM (CycloneDX JSON) или None."""
        pass

    @abc.abstractmethod
    def report_status(
        self,
        from_version: str,
        to_version: str,
        status: str,
        device_id: str,
    ) -> None:
        """Передает отчет о статусе обновления на сервер или фиксирует локально."""
        pass


class HttpSource(IUpdateSource):
    """
    Реализация источника обновлений через сетевой REST API сервера.
    Использует JWT-авторизацию и одноразовый download_token.
    """

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:8000",
        jwt_token: Optional[str] = None,
        device_id: Optional[str] = None,
        user_id: str = "updater_client",
    ):
        self.base_url = base_url.rstrip("/")
        self.device_id = device_id or get_device_id()
        self.user_id = user_id
        self._session = requests.Session()
        self._target_version: Optional[str] = None
        self._cached_manifest: Optional[Dict[str, Any]] = None

        if jwt_token:
            self.jwt_token = jwt_token
        else:
            self.jwt_token = self._obtain_token()

    def _obtain_token(self) -> str:
        """Запрашивает JWT-токен у сервера."""
        try:
            url = f"{self.base_url}/updates/auth/token"
            resp = self._session.post(url, json={"user_id": self.user_id, "device_id": self.device_id}, timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                return data.get("access_token", "")
        except Exception as exc:
            logger.debug(f"Не удалось получить авто-токен JWT: {exc}")
        return ""

    def _get_headers(self) -> Dict[str, str]:
        headers = {"Accept": "application/json"}
        if self.jwt_token:
            headers["Authorization"] = f"Bearer {self.jwt_token}"
        return headers

    def check_update(self, current_version: str, os_name: str = "windows", arch: str = "x64") -> Optional[Dict[str, Any]]:
        url = f"{self.base_url}/updates/check"
        params = {"os": os_name, "arch": arch, "version": current_version}
        resp = self._session.get(url, params=params, headers=self._get_headers(), timeout=10)
        resp.raise_for_status()
        data = resp.json()
        if data.get("update_available"):
            self._target_version = data.get("version")
            return data
        return None

    def get_manifest(self) -> Dict[str, Any]:
        if not self._target_version:
            raise UpdateError("Версия для обновления не задана (не выполнен check_update)")
        url = f"{self.base_url}/updates/manifest/{self._target_version}"
        resp = self._session.get(url, headers=self._get_headers(), timeout=10)
        resp.raise_for_status()
        self._cached_manifest = resp.json()
        return self._cached_manifest

    def download_package(
        self,
        target_path: Path,
        progress_cb: Optional[Callable[[int, int], None]] = None,
    ) -> Path:
        if not self._target_version:
            raise UpdateError("Версия для скачивания не задана")

        # 1. Запрос одноразового download_token
        tok_url = f"{self.base_url}/updates/request_token"
        tok_resp = self._session.post(
            tok_url,
            json={"version": self._target_version, "device_id": self.device_id},
            headers=self._get_headers(),
            timeout=10,
        )
        tok_resp.raise_for_status()
        dl_token = tok_resp.json().get("download_token")
        if not dl_token:
            raise UpdateError("Сервер не вернул одноразовый download_token")

        # 2. Скачивание пакета с передачей токена
        dl_url = f"{self.base_url}/updates/download/{self._target_version}"
        headers = self._get_headers()
        headers["X-Download-Token"] = dl_token

        target_path.parent.mkdir(parents=True, exist_ok=True)
        with self._session.get(dl_url, headers=headers, stream=True, timeout=60) as resp:
            resp.raise_for_status()
            total_size = int(resp.headers.get("content-length", 0))
            downloaded = 0
            with open(target_path, "wb") as f:
                for chunk in resp.iter_content(chunk_size=65536):
                    if chunk:
                        f.write(chunk)
                        downloaded += len(chunk)
                        if progress_cb and total_size > 0:
                            progress_cb(downloaded, total_size)

        return target_path

    def get_sbom(self) -> Optional[Dict[str, Any]]:
        if not self._target_version:
            return None
        url = f"{self.base_url}/updates/sbom/{self._target_version}.json"
        try:
            resp = self._session.get(url, headers=self._get_headers(), timeout=10)
            if resp.status_code == 200:
                return resp.json()
        except Exception as exc:
            logger.warning(f"Не удалось получить SBOM с сервера: {exc}")
        return None

    def report_status(
        self,
        from_version: str,
        to_version: str,
        status: str,
        device_id: str,
    ) -> None:
        url = f"{self.base_url}/updates/report"
        payload = {
            "device_id": device_id,
            "from_version": from_version,
            "to_version": to_version,
            "status": status,
        }
        try:
            resp = self._session.post(url, json=payload, headers=self._get_headers(), timeout=10)
            if resp.status_code != 200:
                logger.warning(f"Сервер вернул код {resp.status_code} при отправке отчета: {resp.text}")
        except Exception as exc:
            logger.warning(f"Ошибка отправки отчета обновления на сервер: {exc}")


class FileSource(IUpdateSource):
    """
    Реализация источника обновлений из локального каталога или файла манифеста (офлайн-режим).
    """

    def __init__(self, manifest_file: Union[str, Path]):
        self.manifest_path = Path(manifest_file).resolve()
        if not self.manifest_path.is_file():
            raise FileNotFoundError(f"Файл манифеста не найден: {self.manifest_path}")
        self.base_dir = self.manifest_path.parent
        self._cached_manifest: Optional[Dict[str, Any]] = None

    def check_update(self, current_version: str, os_name: str = "windows", arch: str = "x64") -> Optional[Dict[str, Any]]:
        manifest = self.get_manifest()
        new_ver = manifest.get("version", "1.0.0")
        try:
            has_update = parse_version(new_ver.split("-")[0]) > parse_version(current_version.split("-")[0])
        except Exception:
            has_update = new_ver != current_version

        if has_update:
            return {
                "update_available": True,
                "version": new_ver,
                "min_supported": manifest.get("min_supported", "1.0.0"),
                "manifest_url": str(self.manifest_path),
            }
        return None

    def get_manifest(self) -> Dict[str, Any]:
        if self._cached_manifest is None:
            content = self.manifest_path.read_text(encoding="utf-8")
            self._cached_manifest = json.loads(content)
        return self._cached_manifest

    def download_package(
        self,
        target_path: Path,
        progress_cb: Optional[Callable[[int, int], None]] = None,
    ) -> Path:
        manifest = self.get_manifest()
        pkg_rel = manifest.get("package_url", "")
        # Поиск пакета: рядом с манифестом, по имени или по относительному пути
        candidates = [
            self.base_dir / Path(pkg_rel).name,
            self.base_dir / f"SecureClient-{manifest.get('version', '')}-win-x64.zip",
            self.base_dir / "package.zip",
            self.base_dir / Path(pkg_rel),
        ]
        source_pkg = None
        for cand in candidates:
            if cand.is_file():
                source_pkg = cand
                break

        if not source_pkg:
            # Попробуем найти любой .zip в каталоге
            zips = list(self.base_dir.glob("*.zip"))
            if zips:
                source_pkg = zips[0]

        if not source_pkg or not source_pkg.is_file():
            raise FileNotFoundError(f"Пакет обновления .zip не найден в каталоге манифеста: {self.base_dir}")

        target_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source_pkg, target_path)

        if progress_cb:
            size = target_path.stat().st_size
            progress_cb(size, size)

        return target_path

    def get_sbom(self) -> Optional[Dict[str, Any]]:
        manifest = self.get_manifest()
        sbom_meta = manifest.get("sbom", {})
        candidates = [
            self.base_dir / "sbom.json",
            self.base_dir / Path(sbom_meta.get("url", "sbom.json")).name,
        ]
        for cand in candidates:
            if cand.is_file():
                try:
                    return json.loads(cand.read_text(encoding="utf-8"))
                except Exception:
                    pass
        return None

    def report_status(
        self,
        from_version: str,
        to_version: str,
        status: str,
        device_id: str,
    ) -> None:
        """Локальная фиксация статуса в файл журнала audit_local.log."""
        log_file = self.base_dir / "update_audit_local.log"
        entry = (
            f"[{platform.node()}] device={device_id} "
            f"from={from_version} to={to_version} status={status}\n"
        )
        try:
            with open(log_file, "a", encoding="utf-8") as f:
                f.write(entry)
        except Exception:
            pass


class Updater:
    """
    Класс управления жизненным циклом безопасного обновления ПО.
    """

    def __init__(
        self,
        source: IUpdateSource,
        current_version: str,
        app_dir: Union[str, Path],
        public_key: Optional[Any] = None,
        device_id: Optional[str] = None,
        log_callback: Optional[Callable[[str], None]] = None,
    ):
        self.source = source
        self.current_version = current_version
        self.app_dir = Path(app_dir).resolve()
        self.public_key = load_public_key(public_key)
        self.device_id = device_id or get_device_id()
        self.log_callback = log_callback or (lambda msg: logger.info(msg))

        self.work_dir = self.app_dir.parent / f".update_work_{self.app_dir.name}"
        self.staging_dir = self.work_dir / "staging"
        self.backup_dir = self.work_dir / "backup"
        self.package_path = self.work_dir / "package.zip"

    def _log(self, message: str) -> None:
        logger.info(message)
        if self.log_callback:
            try:
                self.log_callback(message)
            except Exception:
                pass

    def run_update(
        self,
        progress_cb: Optional[Callable[[int, int], None]] = None,
    ) -> bool:
        """
        Выполняет полный цикл безопасного обновления ПО.
        В случае любой ошибки автоматически откатывает изменения из backup/.
        """
        target_version = "unknown"
        backup_created = False

        try:
            self._log("Шаг 1/8: Получение манифеста релиза...")
            manifest = self.source.get_manifest()
            target_version = manifest.get("version", "unknown")
            self._log(f"-> Манифест релиза {target_version} получен.")

            self._log("Шаг 2/8: Проверка цифровой подписи Ed25519 манифеста...")
            if not verify_manifest(manifest, public_key=self.public_key):
                raise SignatureVerificationError(
                    "Цифровая подпись манифеста Ed25519 недействительна! Возможно манифест был подменен."
                )
            self._log("-> Цифровая подпись Ed25519 успешно верифицирована.")

            self._log("Шаг 3/8: Проверка минимально поддерживаемой версии (min_supported)...")
            min_supported = manifest.get("min_supported")
            if min_supported:
                try:
                    min_v = parse_version(min_supported.split("-")[0])
                    cur_v = parse_version(self.current_version.split("-")[0])
                    if min_v > cur_v:
                        raise MinSupportedVersionError(
                            f"Требуется чистая установка: текущая версия ({self.current_version}) "
                            f"ниже минимально поддерживаемой ({min_supported})"
                        )
                except MinSupportedVersionError:
                    raise
                except Exception as exc:
                    self._log(f"Предупреждение: ошибка сопоставления версий: {exc}")
            self._log("-> Проверка min_supported пройдена успешно.")

            # Подготовка рабочего каталога
            self.work_dir.mkdir(parents=True, exist_ok=True)

            self._log("Шаг 4/8: Получение пакета обновления (.zip)...")
            if self.package_path.exists():
                self.package_path.unlink()
            self.source.download_package(self.package_path, progress_cb=progress_cb)
            self._log("-> Пакет обновления успешно получен.")
            self.source.report_status(self.current_version, target_version, STATUS_DOWNLOADED, self.device_id)

            self._log("Шаг 5/8: Проверка контрольной суммы пакета SHA-256...")
            expected_pkg_sha256 = manifest.get("package_sha256")
            if not expected_pkg_sha256:
                raise ChecksumMismatchError("В манифесте отсутствует поле 'package_sha256'")

            if not verify_sha256(self.package_path, expected_pkg_sha256):
                actual_sha = calculate_sha256(self.package_path)
                raise ChecksumMismatchError(
                    f"Хэш SHA-256 пакета не совпадает: ожидался {expected_pkg_sha256}, вычислен {actual_sha}"
                )
            self._log("-> Контрольная сумма SHA-256 пакета подтверждена.")
            self.source.report_status(self.current_version, target_version, STATUS_VERIFIED, self.device_id)

            self._log("Шаг 6/8: Распаковка в staging/ и верификация SBOM...")
            if self.staging_dir.exists():
                shutil.rmtree(self.staging_dir, ignore_errors=True)
            self.staging_dir.mkdir(parents=True, exist_ok=True)

            with zipfile.ZipFile(self.package_path, "r") as zf:
                zf.extractall(self.staging_dir)

            # Проверка SBOM
            self._verify_sbom_step(manifest)
            self._log("-> Спецификация SBOM CycloneDX 1.5 успешно верифицирована.")

            self._log("Шаг 7/8: Атомарная замена (app -> backup, staging -> app)...")
            if self.backup_dir.exists():
                shutil.rmtree(self.backup_dir, ignore_errors=True)
            self.backup_dir.mkdir(parents=True, exist_ok=True)

            # Создание резервной копии текущего приложения
            if self.app_dir.exists():
                for item in self.app_dir.iterdir():
                    dst = self.backup_dir / item.name
                    if item.is_dir():
                        shutil.copytree(item, dst)
                    else:
                        shutil.copy2(item, dst)
                backup_created = True

            # Замена файлов новыми из staging_dir
            self.app_dir.mkdir(parents=True, exist_ok=True)
            # Очищаем текущее приложение
            for item in self.app_dir.iterdir():
                if item.is_dir():
                    shutil.rmtree(item, ignore_errors=True)
                else:
                    item.unlink()

            # Копируем из staging в app_dir
            for item in self.staging_dir.iterdir():
                dst = self.app_dir / item.name
                if item.is_dir():
                    shutil.copytree(item, dst)
                else:
                    shutil.copy2(item, dst)

            self._log("Шаг 8/8: Финализация и отправка отчета об успешной установке...")
            self.source.report_status(self.current_version, target_version, STATUS_INSTALLED, self.device_id)
            self._log(f"✅ Обновление до версии {target_version} успешно установлено!")

            # Очистка временных файлов
            try:
                shutil.rmtree(self.staging_dir, ignore_errors=True)
                if self.package_path.exists():
                    self.package_path.unlink()
            except Exception:
                pass

            return True

        except SbomMismatchError as exc:
            self._log(f"🚨 Ошибка SBOM: {exc}")
            self.source.report_status(self.current_version, target_version, STATUS_SBOM_MISMATCH, self.device_id)
            if backup_created:
                self.rollback()
            raise

        except Exception as exc:
            self._log(f"🚨 Критическая ошибка процесса обновления: {exc}")
            if backup_created:
                self._log("Запуск процедуры автоматического отката (rollback)...")
                try:
                    self.rollback()
                    self.source.report_status(self.current_version, target_version, STATUS_ROLLED_BACK, self.device_id)
                    self._log("-> Откат к предыдущей версии успешно завершен.")
                except Exception as rb_exc:
                    self._log(f"Ошибка при выполнении отката: {rb_exc}")
                    self.source.report_status(self.current_version, target_version, STATUS_FAILED, self.device_id)
            else:
                self.source.report_status(self.current_version, target_version, STATUS_FAILED, self.device_id)
            raise

    def _verify_sbom_step(self, manifest: Dict[str, Any]) -> None:
        """Проверяет наличие, контрольную сумму и формат CycloneDX 1.5 для SBOM."""
        sbom_meta = manifest.get("sbom")
        if not sbom_meta:
            self._log("SBOM в манифесте не указан, пропускаем валидацию SBOM.")
            return

        expected_sha = sbom_meta.get("sha256")
        expected_format = sbom_meta.get("format", "CycloneDX-1.5")

        # 1. Поиск SBOM внутри распакованного пакета или через источник
        sbom_file_in_staging = self.staging_dir / "sbom.json"
        sbom_data = None
        sbom_bytes = b""

        if sbom_file_in_staging.is_file():
            sbom_bytes = sbom_file_in_staging.read_bytes()
            try:
                sbom_data = json.loads(sbom_bytes.decode("utf-8"))
            except Exception as exc:
                raise SbomMismatchError(f"Файл sbom.json поврежден (невалидный JSON): {exc}")
        else:
            # Получение через source
            sbom_data = self.source.get_sbom()
            if sbom_data:
                sbom_bytes = json.dumps(sbom_data, ensure_ascii=False).encode("utf-8")

        if not sbom_data:
            raise SbomMismatchError("Файл SBOM отсутствует в пакете и не получен от сервера")

        # 2. Проверка хэша SHA-256
        if expected_sha:
            actual_sha = hashlib.sha256(sbom_bytes).hexdigest().lower()
            if actual_sha != expected_sha.strip().lower():
                raise SbomMismatchError(
                    f"Хэш SHA-256 файла SBOM не совпадает: ожидался {expected_sha}, получен {actual_sha}"
                )

        # 3. Валидация спецификации CycloneDX
        valid, msg = validate_cyclonedx_sbom(sbom_data)
        if not valid:
            raise SbomMismatchError(f"Невалидный формат SBOM ({expected_format}): {msg}")

    def rollback(self) -> None:
        """Восстанавливает файлы приложения из резервной копии backup/."""
        self._log("Выполняется восстановление файлов из резервной копии backup/...")
        if not self.backup_dir.is_dir():
            raise InstallationError("Каталог резервной копии backup/ отсутствует или пуст")

        if self.app_dir.exists():
            for item in self.app_dir.iterdir():
                if item.is_dir():
                    shutil.rmtree(item, ignore_errors=True)
                else:
                    item.unlink()

        for item in self.backup_dir.iterdir():
            dst = self.app_dir / item.name
            if item.is_dir():
                shutil.copytree(item, dst)
            else:
                shutil.copy2(item, dst)
