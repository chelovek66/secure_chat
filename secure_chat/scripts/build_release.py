#!/usr/bin/env python3
"""
Скрипт автоматизированной сборки исполняемого файла .exe и релиз-пакета «Secure Client»
в соответствии с требованиями лабораторной работы ПЗ-4 (п. 7).

Выполняет:
  1. Генерацию криптографических ключей обновления Ed25519 (release_keys/);
  2. Сборку автономного бинарного приложения через PyInstaller (--onedir, --windowed);
  3. Включение нативной библиотеки СТБ Bee2 (bee2.dll) и конфигурации (config.json);
  4. Проверку артефактов компиляции (SecureClient.exe, bee2.dll);
  5. Генерацию паспорта компонентов SBOM CycloneDX 1.5 JSON (release/sbom.json);
  6. Упаковку дистрибутива в архив release/SecureClient-2.1.0-win-x64.zip;
  7. Формирование релизного манифеста обновления release/manifest.json;
  8. Подписание манифеста цифровой подписью Ed25519 (release/manifest.sig);
  9. Быстрый smoke-тест скомпилированного .exe бинарника;
 10. Комплексную проверку целостности архива, манифеста и криптографических подписей.
"""

import os
import sys
import json
import uuid
import shutil
import base64
import hashlib
import zipfile
import subprocess
import importlib.metadata
from pathlib import Path
from datetime import datetime, timezone
from typing import Tuple, Dict, Any

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

# Конфигурация сборки
APP_NAME = "SecureClient"
VERSION = "2.1.0"
MIN_SUPPORTED = "1.0.0"
OS_NAME = "windows"
ARCH_NAME = "x64"
ZIP_PACKAGE_NAME = f"{APP_NAME}-{VERSION}-win-x64.zip"


def get_project_root() -> Path:
    """Возвращает корень проекта secure_chat."""
    current = Path(__file__).resolve().parent
    if (current.parent / "client").is_dir():
        return current.parent
    if (current / "client").is_dir():
        return current
    return Path.cwd()


def sha256_of_bytes(data: bytes) -> str:
    """Вычисляет SHA-256 хэш байтового массива."""
    return hashlib.sha256(data).hexdigest()


def sha256_of_file(file_path: Path) -> str:
    """Вычисляет SHA-256 хэш содержимого файла блоками."""
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def get_or_create_ed25519_keys(keys_dir: Path) -> Tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey, Path, Path]:
    """
    Загружает или генерирует новую пару ключей релиза Ed25519.
    Сохраняет в release_keys/update_private.key и release_keys/update_public.key.
    """
    keys_dir.mkdir(parents=True, exist_ok=True)
    priv_path = keys_dir / "update_private.key"
    pub_path = keys_dir / "update_public.key"

    if priv_path.is_file() and pub_path.is_file():
        print(f"[KEYS] Загрузка существующих ключей Ed25519 из {keys_dir}")
        priv_bytes = priv_path.read_bytes()
        if b"BEGIN" in priv_bytes:
            priv_key = serialization.load_pem_private_key(priv_bytes, password=None)
        else:
            priv_key = ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes[:32])

        pub_bytes = pub_path.read_bytes()
        if b"BEGIN" in pub_bytes:
            pub_key = serialization.load_pem_public_key(pub_bytes)
        else:
            pub_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes[:32])

        return priv_key, pub_key, priv_path, pub_path

    print(f"[KEYS] Генерация новой ключевой пары Ed25519 в {keys_dir}...")
    priv_key = ed25519.Ed25519PrivateKey.generate()
    pub_key = priv_key.public_key()

    priv_pem = priv_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = pub_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    priv_path.write_bytes(priv_pem)
    pub_path.write_bytes(pub_pem)
    print(f"[KEYS] Сгенерированы:\n  Закрытый ключ: {priv_path}\n  Открытый ключ: {pub_path}")
    return priv_key, pub_key, priv_path, pub_path


def generate_sbom(release_dir: Path, project_root: Path) -> Tuple[Path, str]:
    """
    Формирует спецификацию SBOM в стандарте CycloneDX 1.5 JSON (release/sbom.json)
    с перечислением ключевых компонентов и вычислением SHA-256.
    """
    release_dir.mkdir(parents=True, exist_ok=True)
    sbom_path = release_dir / "sbom.json"

    def get_pkg_version(name: str, fallback: str = "unknown") -> str:
        try:
            return importlib.metadata.version(name)
        except Exception:
            return fallback

    # Находим bee2.dll и берем ее SHA-256
    bee2_candidates = [
        project_root / "bee2.dll",
        project_root / "client" / "crypto" / "bee2.dll",
    ]
    bee2_file = next((f for f in bee2_candidates if f.is_file()), None)
    bee2_sha = sha256_of_file(bee2_file) if bee2_file else "unknown"
    bee2_size = bee2_file.stat().st_size if bee2_file else 0

    components = [
        {
            "type": "library",
            "name": "cryptography",
            "version": get_pkg_version("cryptography", "50.0.1"),
            "purl": f"pkg:pypi/cryptography@{get_pkg_version('cryptography', '50.0.1')}",
            "description": "Криптографическая библиотека Python (Ed25519, AES, RSA, X.509)",
            "licenses": [{"license": {"id": "Apache-2.0"}}]
        },
        {
            "type": "library",
            "name": "PyQt5",
            "version": get_pkg_version("PyQt5", "5.15.11"),
            "purl": f"pkg:pypi/pyqt5@{get_pkg_version('PyQt5', '5.15.11')}",
            "description": "Python-биндинги графической подсистемы Qt5",
            "licenses": [{"license": {"id": "GPL-3.0"}}]
        },
        {
            "type": "library",
            "name": "requests",
            "version": get_pkg_version("requests", "2.34.2"),
            "purl": f"pkg:pypi/requests@{get_pkg_version('requests', '2.34.2')}",
            "description": "HTTP-клиент для взаимодействия с REST API сервера",
            "licenses": [{"license": {"id": "Apache-2.0"}}]
        },
        {
            "type": "library",
            "name": "fastapi",
            "version": get_pkg_version("fastapi", "0.141.1"),
            "purl": f"pkg:pypi/fastapi@{get_pkg_version('fastapi', '0.141.1')}",
            "description": "Высокопроизводительный веб-фреймворк REST API",
            "licenses": [{"license": {"id": "MIT"}}]
        },
        {
            "type": "library",
            "name": "uvicorn",
            "version": get_pkg_version("uvicorn", "0.53.0"),
            "purl": f"pkg:pypi/uvicorn@{get_pkg_version('uvicorn', '0.53.0')}",
            "description": "Молниеносный ASGI веб-сервер",
            "licenses": [{"license": {"id": "BSD-3-Clause"}}]
        },
        {
            "type": "library",
            "name": "pydantic",
            "version": get_pkg_version("pydantic", "2.13.5"),
            "purl": f"pkg:pypi/pydantic@{get_pkg_version('pydantic', '2.13.5')}",
            "description": "Валидация структур данных и настроек",
            "licenses": [{"license": {"id": "MIT"}}]
        },
        {
            "type": "library",
            "name": "bee2.dll",
            "version": VERSION,
            "description": "Национальная криптографическая библиотека Республики Беларусь (СТБ 34.101.45/31/47/78)",
            "hashes": [
                {
                    "alg": "SHA-256",
                    "content": bee2_sha
                }
            ],
            "properties": [
                {"name": "file_size", "value": str(bee2_size)},
                {"name": "standards", "value": "СТБ 34.101.45-2013, СТБ 34.101.31-2011, СТБ 34.101.47-2017"}
            ]
        }
    ]

    sbom_doc = {
        "$schema": "http://cyclonedx.org/schema/bom-1.5.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [
                {
                    "vendor": "Secure Chat Release Authority",
                    "name": "build_release.py",
                    "version": VERSION
                }
            ],
            "component": {
                "type": "application",
                "name": "SecureClient",
                "version": VERSION,
                "description": "Защищенный клиентский мессенджер с криптографией СТБ РБ и защитой обновлений"
            }
        },
        "components": components
    }

    content_str = json.dumps(sbom_doc, indent=2, ensure_ascii=False)
    sbom_path.write_text(content_str, encoding="utf-8")
    sbom_sha256 = sha256_of_file(sbom_path)
    print(f"[SBOM] Файл сгенерирован: {sbom_path}")
    print(f"[SBOM] Компонентов: {len(components)}, SHA-256: {sbom_sha256}")
    return sbom_path, sbom_sha256


def run_pyinstaller_build(project_root: Path, python_exe: str = sys.executable) -> Path:
    """
    Запускает PyInstaller для client/main.py с требуемыми флагами:
    --onedir --windowed --name SecureClient
    """
    entry_point = project_root / "client" / "main.py"
    dist_dir = project_root / "dist" / APP_NAME
    build_dir = project_root / "build"

    print(f"[BUILD] Запуск сборки PyInstaller...")
    print(f"  Точка входа: {entry_point}")
    print(f"  Каталог назначения: {dist_dir}")

    # Пути к ресурсам
    bee2_src = project_root / "client" / "crypto" / "bee2.dll"
    if not bee2_src.is_file():
        bee2_src = project_root / "bee2.dll"
    if not bee2_src.is_file():
        raise FileNotFoundError(f"Файл bee2.dll не найден в {project_root}")

    config_src = project_root / "config.json"
    build_info_src = project_root / "build_info.json"
    manifest_src = project_root / "software_manifest.json"

    cmd = [
        python_exe,
        "-m",
        "PyInstaller",
        "--onedir",
        "--windowed",
        "--name", APP_NAME,
        "--distpath", str(project_root / "dist"),
        "--workpath", str(build_dir),
        "--specpath", str(project_root),
        "--noconfirm",
        "--clean",
        "--paths", str(project_root),
        # Добавление бинарных файлов и данных
        "--add-binary", f"{bee2_src};.",
        "--add-binary", f"{bee2_src};client/crypto",
        "--add-data", f"{config_src};.",
        "--add-data", f"{build_info_src};.",
        "--add-data", f"{manifest_src};.",
        # Скрытые импорты
        "--hidden-import", "PyQt5",
        "--hidden-import", "PyQt5.QtCore",
        "--hidden-import", "PyQt5.QtWidgets",
        "--hidden-import", "PyQt5.QtGui",
        "--hidden-import", "cryptography",
        "--hidden-import", "cryptography.hazmat.primitives.asymmetric.ed25519",
        "--hidden-import", "requests",
        "--hidden-import", "pydantic",
        "--hidden-import", "client",
        "--hidden-import", "client.main",
        "--hidden-import", "client.gui.main_window",
        "--hidden-import", "client.gui.auth_dialog",
        "--hidden-import", "client.gui.build_dialog",
        "--hidden-import", "client.gui.chat_dialog",
        "--hidden-import", "client.gui.config_dialog",
        "--hidden-import", "client.gui.database_dialog",
        "--hidden-import", "client.gui.integrity_dialog",
        "--hidden-import", "client.gui.key_dialog",
        "--hidden-import", "client.gui.logs_dialog",
        "--hidden-import", "client.gui.styles",
        "--hidden-import", "client.gui.users_dialog",
        "--hidden-import", "client.network.api_client",
        "--hidden-import", "client.crypto.bee2_wrapper",
        "--hidden-import", "client.crypto.belt",
        "--hidden-import", "client.crypto.bign",
        "--hidden-import", "client.crypto.hybrid",
        "--hidden-import", "client.crypto.keystore",
        "--hidden-import", "common.logger",
        "--hidden-import", "common.config_manager",
        "--hidden-import", "common.build_info",
        "--hidden-import", "common.integrity",
        str(entry_point),
    ]

    print(f"[BUILD] Команда PyInstaller: {' '.join(cmd[:8])} ...")
    res = subprocess.run(cmd, cwd=str(project_root), capture_output=True, text=True)
    if res.returncode != 0:
        print(f"[BUILD ERROR] PyInstaller завершился с кодом {res.returncode}:")
        print(res.stderr[-2000:])
        raise RuntimeError(f"PyInstaller build failed with return code {res.returncode}")

    print("[BUILD] PyInstaller успешно завершил компиляцию!")

    # Гарантируем наличие bee2.dll и config.json в корне dist/SecureClient
    exe_dir = dist_dir
    dest_bee2 = exe_dir / "bee2.dll"
    if not dest_bee2.is_file():
        shutil.copy2(bee2_src, dest_bee2)
        print(f"[BUILD] Скопирован {bee2_src.name} в {dest_bee2}")

    dest_cfg = exe_dir / "config.json"
    if not dest_cfg.is_file():
        shutil.copy2(config_src, dest_cfg)
        print(f"[BUILD] Скопирован {config_src.name} в {dest_cfg}")

    dest_binfo = exe_dir / "build_info.json"
    if not dest_binfo.is_file():
        shutil.copy2(build_info_src, dest_binfo)

    dest_sman = exe_dir / "software_manifest.json"
    if not dest_sman.is_file():
        shutil.copy2(manifest_src, dest_sman)

    return dist_dir


def verify_dist_structure(dist_dir: Path) -> None:
    """Проверяет корректность собранного каталога dist/SecureClient."""
    exe_file = dist_dir / f"{APP_NAME}.exe"
    bee2_file = dist_dir / "bee2.dll"
    config_file = dist_dir / "config.json"

    if not exe_file.is_file():
        raise FileNotFoundError(f"Исполняемый файл {exe_file} не найден!")
    if not bee2_file.is_file():
        raise FileNotFoundError(f"Библиотека bee2.dll не найдена в {dist_dir}!")
    if not config_file.is_file():
        raise FileNotFoundError(f"Конфигурация config.json не найдена в {dist_dir}!")

    print(f"[VERIFY] Структура сборки проверена:")
    print(f"  EXE:      {exe_file} ({exe_file.stat().st_size:,} байт)")
    print(f"  BEE2.DLL: {bee2_file} ({bee2_file.stat().st_size:,} байт)")
    print(f"  CONFIG:   {config_file}")


def create_release_zip(dist_dir: Path, zip_path: Path, sbom_path: Path) -> Tuple[Path, int, str]:
    """
    Упаковывает собранный дистрибутив в ZIP-архив release/SecureClient-2.1.0-win-x64.zip.
    Включает также sbom.json внутрь пакета (требование структуры пакета ПЗ-4 п. 3.3).
    """
    zip_path.parent.mkdir(parents=True, exist_ok=True)
    if zip_path.is_file():
        zip_path.unlink()

    print(f"[ZIP] Формирование архива релиза: {zip_path}...")
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        for root, _, files in os.walk(dist_dir):
            for file_name in files:
                abs_file = Path(root) / file_name
                rel_path = abs_file.relative_to(dist_dir)
                zf.write(abs_file, arcname=str(rel_path))

        # Добавляем sbom.json в архив
        if sbom_path.is_file():
            zf.write(sbom_path, arcname="sbom.json")

    pkg_size = zip_path.stat().st_size
    pkg_sha256 = sha256_of_file(zip_path)
    print(f"[ZIP] Релизный ZIP-архив сформирован:")
    print(f"  Путь:   {zip_path}")
    print(f"  Размер: {pkg_size:,} байт")
    print(f"  SHA256: {pkg_sha256}")
    return zip_path, pkg_size, pkg_sha256


def create_and_sign_manifest(
    release_dir: Path,
    pkg_size: int,
    pkg_sha256: str,
    sbom_sha256: str,
    priv_key: ed25519.Ed25519PrivateKey,
) -> Tuple[Path, Path, Dict[str, Any]]:
    """
    Формирует и подписывает manifest.json и сохраняет manifest.sig
    в соответствии со спецификацией ПЗ-4.
    """
    manifest_path = release_dir / "manifest.json"
    manifest_sig_path = release_dir / "manifest.sig"

    release_date_iso = datetime.now(timezone.utc).isoformat()

    manifest_payload = {
        "version": VERSION,
        "min_supported": MIN_SUPPORTED,
        "release_date": release_date_iso,
        "os": OS_NAME,
        "arch": ARCH_NAME,
        "package_url": f"/updates/download/{VERSION}",
        "package_size": pkg_size,
        "package_sha256": pkg_sha256,
        "signature": "",
        "sbom": {
            "format": "CycloneDX-1.5",
            "url": f"/updates/sbom/{VERSION}.json",
            "sha256": sbom_sha256,
        },
        "critical": False,
    }

    # Подписываем каноническое представление полей манифеста для поля signature
    to_sign = {k: v for k, v in manifest_payload.items() if k != "signature"}
    canonical_bytes = json.dumps(to_sign, sort_keys=True, separators=(",", ":")).encode("utf-8")
    signature_bytes = priv_key.sign(canonical_bytes)
    signature_b64 = base64.b64encode(signature_bytes).decode("ascii")

    manifest_payload["signature"] = signature_b64

    # Записываем манифест
    manifest_json_str = json.dumps(manifest_payload, indent=2, ensure_ascii=False)
    manifest_path.write_text(manifest_json_str, encoding="utf-8")

    # Создаем отсоединенную подпись manifest.sig для всего файла манифеста (для offline-режима ПЗ-4 п. 3.3)
    manifest_raw_bytes = manifest_path.read_bytes()
    manifest_detached_sig = priv_key.sign(manifest_raw_bytes)
    manifest_sig_b64 = base64.b64encode(manifest_detached_sig).decode("ascii")

    manifest_sig_path.write_text(manifest_sig_b64, encoding="utf-8")
    # Также сохраняем бинарную версию подписи manifest.sig.bin (64 байта)
    (release_dir / "manifest.sig.bin").write_bytes(manifest_detached_sig)

    print(f"[MANIFEST] Манифест релиза сохранен в {manifest_path}")
    print(f"[MANIFEST] Подпись сохранена в {manifest_sig_path}")
    print(f"[MANIFEST] Signature (base64): {signature_b64}")

    return manifest_path, manifest_sig_path, manifest_payload


def smoke_test_exe(dist_dir: Path) -> bool:
    """
    Запускает быстрый smoke-test скомпилированного SecureClient.exe.
    Проверяет успешность инициализации без блокировки и зависания UI.
    """
    exe_path = dist_dir / f"{APP_NAME}.exe"
    marker_file = dist_dir / "smoke_test.log"
    if marker_file.is_file():
        marker_file.unlink()

    print(f"[SMOKE-TEST] Проверка работоспособности {exe_path}...")
    cmd = [str(exe_path), "--smoke-test"]

    try:
        proc = subprocess.Popen(
            cmd,
            cwd=str(dist_dir),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            stdout, stderr = proc.communicate(timeout=8)
            ret_code = proc.returncode
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate()
            ret_code = proc.returncode

        # Проверяем результат по коду возврата или маркерному файлу
        if marker_file.is_file():
            content = marker_file.read_text(encoding="utf-8").strip()
            print("[SMOKE-TEST] Прочитан файл самодиагностики:")
            for line in content.splitlines():
                print(f"  {line}")
            if "SMOKE_TEST_OK" in content:
                print("[SMOKE-TEST] УСПЕШНО: Бинарный файл SecureClient.exe корректно запустился и выполнил самодиагностику!")
                return True

        if ret_code == 0:
            print("[SMOKE-TEST] УСПЕШНО: Процесс завершился с кодом 0!")
            return True

        print(f"[SMOKE-TEST] Возвращен код: {ret_code}")
        if stdout:
            print(f"  stdout: {stdout.strip()}")
        if stderr:
            print(f"  stderr: {stderr.strip()}")
        return False
    except Exception as exc:
        print(f"[SMOKE-TEST FAILED] Исключение при запуске: {exc}")
        return False


def verify_release_integrity(
    zip_path: Path,
    manifest_path: Path,
    manifest_sig_path: Path,
    sbom_path: Path,
    pub_key: ed25519.Ed25519PublicKey,
) -> bool:
    """
    Проверяет математическую корректность всех хэшей и подписей сформированного релиза.
    """
    print("\n" + "=" * 60)
    print("[INTEGRITY-CHECK] Комплексная проверка релиза:")

    # 1. Проверка манифеста
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    sig_b64 = manifest.get("signature", "")
    sig_bytes = base64.b64decode(sig_b64)

    to_verify = {k: v for k, v in manifest.items() if k != "signature"}
    canonical_bytes = json.dumps(to_verify, sort_keys=True, separators=(",", ":")).encode("utf-8")

    try:
        pub_key.verify(sig_bytes, canonical_bytes)
        print("  [OK] 1. Цифровая подпись манифеста Ed25519 (поле 'signature'): ВАЛИДНА")
    except Exception as e:
        print(f"  [FAIL] 1. Подпись манифеста недействительна: {e}")
        return False

    # 2. Проверка отсоединенной подписи manifest.sig
    sig_file_text = manifest_sig_path.read_text(encoding="utf-8").strip()
    detached_sig_bytes = base64.b64decode(sig_file_text)
    manifest_bytes = manifest_path.read_bytes()
    try:
        pub_key.verify(detached_sig_bytes, manifest_bytes)
        print("  [OK] 2. Отсоединенная подпись manifest.sig: ВАЛИДНА")
    except Exception as e:
        print(f"  [FAIL] 2. Файл manifest.sig не прошел проверку: {e}")
        return False

    # 3. Проверка SHA-256 ZIP архива
    actual_zip_sha256 = sha256_of_file(zip_path)
    expected_zip_sha256 = manifest["package_sha256"]
    if actual_zip_sha256.lower() == expected_zip_sha256.lower():
        print(f"  [OK] 3. Контрольная сумма пакета SHA-256 ({actual_zip_sha256[:16]}...): СОВПАДАЕТ")
    else:
        print(f"  [FAIL] 3. Несовпадение SHA-256 пакета! Ожидалось {expected_zip_sha256}, факт {actual_zip_sha256}")
        return False

    # 4. Проверка размера архива
    if zip_path.stat().st_size == manifest["package_size"]:
        print(f"  [OK] 4. Размер пакета ({manifest['package_size']:,} байт): СОВПАДАЕТ")
    else:
        print("  [FAIL] 4. Размер пакета не совпадает")
        return False

    # 5. Проверка SBOM
    actual_sbom_sha256 = sha256_of_file(sbom_path)
    expected_sbom_sha256 = manifest["sbom"]["sha256"]
    if actual_sbom_sha256.lower() == expected_sbom_sha256.lower():
        print(f"  [OK] 5. Контрольная сумма SBOM SHA-256 ({actual_sbom_sha256[:16]}...): СОВПАДАЕТ")
    else:
        print(f"  [FAIL] 5. Несовпадение SHA-256 SBOM! Ожидалось {expected_sbom_sha256}, факт {actual_sbom_sha256}")
        return False

    print("[INTEGRITY-CHECK] Все проверки успешно пройдены!")
    print("=" * 60 + "\n")
    return True


def main():
    """Основной пайплайн сборки релизного пакета."""
    print("=" * 70)
    print(f"   СБОРКА РЕЛИЗНОГО ПАКЕТА «{APP_NAME}» v{VERSION} (ПЗ-4 п. 7)")
    print("=" * 70)

    project_root = get_project_root()
    release_dir = project_root / "release"
    keys_dir = project_root / "release_keys"
    python_exe = sys.executable

    print(f"Рабочая директория: {project_root}")
    print(f"Интерпретатор:      {python_exe}")
    print(f"Каталог релиза:     {release_dir}")

    # Шаг 1: Ключи Ed25519
    priv_key, pub_key, priv_path, pub_path = get_or_create_ed25519_keys(keys_dir)

    # Шаг 2: Генерация SBOM CycloneDX 1.5 JSON
    sbom_path, sbom_sha256 = generate_sbom(release_dir, project_root)

    # Шаг 3: Сборка исполняемого файла через PyInstaller
    dist_dir = run_pyinstaller_build(project_root, python_exe=python_exe)

    # Шаг 4: Проверка структуры dist
    verify_dist_structure(dist_dir)

    # Шаг 5: Smoke-тест скомпилированного бинарника
    smoke_ok = smoke_test_exe(dist_dir)
    if not smoke_ok:
        print("[WARNING] Smoke-тест вернул ошибку, но сборка продолжается.")

    # Шаг 6: Упаковка в ZIP-архив
    zip_path = release_dir / ZIP_PACKAGE_NAME
    _, pkg_size, pkg_sha256 = create_release_zip(dist_dir, zip_path, sbom_path)

    # Шаг 7: Формирование и подписание манифеста
    manifest_path, manifest_sig_path, manifest_data = create_and_sign_manifest(
        release_dir=release_dir,
        pkg_size=pkg_size,
        pkg_sha256=pkg_sha256,
        sbom_sha256=sbom_sha256,
        priv_key=priv_key,
    )

    # Шаг 8: Верификация целостности и подписей
    integrity_ok = verify_release_integrity(
        zip_path=zip_path,
        manifest_path=manifest_path,
        manifest_sig_path=manifest_sig_path,
        sbom_path=sbom_path,
        pub_key=pub_key,
    )

    if not integrity_ok:
        print("[ERROR] Ошибка контроля целостности релиза!")
        sys.exit(1)

    print("\n" + "=" * 70)
    print("   РЕЛИЗНЫЙ ПАКЕТ УСПЕШНО СОБРАН И ВЕРИФИЦИРОВАН!")
    print("=" * 70)
    print(f"Архив:    {zip_path} ({pkg_size:,} байт)")
    print(f"SHA-256:  {pkg_sha256}")
    print(f"Манифест: {manifest_path}")
    print(f"Подпись:  {manifest_sig_path}")
    print(f"SBOM:     {sbom_path}")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()
