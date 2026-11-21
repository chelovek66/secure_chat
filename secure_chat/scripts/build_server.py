#!/usr/bin/env python3
"""
Скрипт автоматизированной сборки исполняемого файла сервера «SecureServer.exe».
Использует PyInstaller для создания автономного дистрибутива в dist/SecureServer.
"""

import sys
import subprocess
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DIST_DIR = PROJECT_ROOT / "dist"
BUILD_DIR = PROJECT_ROOT / "build" / "SecureServer"
SERVER_ENTRY = PROJECT_ROOT / "server_launcher.py"


def build_server():
    print("=" * 70)
    print("    СБОРКА ИСПОЛНЯЕМОГО ФАЙЛА СЕРВЕРА (SecureServer.exe)")
    print("=" * 70)
    print(f"[*] Точка входа: {SERVER_ENTRY}")
    print(f"[*] Выходной каталог: {DIST_DIR / 'SecureServer'}")

    # Файлы данных, необходимые серверу
    data_args = [
        f"--add-data={PROJECT_ROOT / 'software_manifest.json'};.",
        f"--add-data={PROJECT_ROOT / 'build_info.json'};.",
    ]
    if (PROJECT_ROOT / "bee2.dll").is_file():
        data_args.append(f"--add-binary={PROJECT_ROOT / 'bee2.dll'};.")
    if (PROJECT_ROOT / "client" / "crypto" / "bee2.dll").is_file():
        data_args.append(f"--add-binary={PROJECT_ROOT / 'client' / 'crypto' / 'bee2.dll'};client/crypto")

    hidden_imports = [
        "uvicorn",
        "uvicorn.logging",
        "uvicorn.loops",
        "uvicorn.loops.auto",
        "uvicorn.protocols",
        "uvicorn.protocols.http",
        "uvicorn.protocols.http.auto",
        "uvicorn.protocols.http.h11_impl",
        "uvicorn.protocols.http.httptools_impl",
        "uvicorn.protocols.websockets",
        "uvicorn.protocols.websockets.auto",
        "uvicorn.lifespans",
        "uvicorn.lifespans.on",
        "fastapi",
        "fastapi.routing",
        "fastapi.middleware.cors",
        "starlette",
        "starlette.responses",
        "starlette.routing",
        "pydantic",
        "pydantic_core",
        "sqlite3",
        "server",
        "server.app",
        "server.auth_router",
        "server.config",
        "server.database",
        "server.models",
        "server.storage",
        "server.update_router",
        "common",
        "common.build_info",
        "common.config_manager",
        "common.fingerprint",
        "common.integrity",
        "common.logger",
        "common.update_crypto",
        "client.crypto.bee2_wrapper",
    ]

    hidden_args = []
    for h in hidden_imports:
        hidden_args.extend(["--hidden-import", h])

    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--onedir",
        "--console",  # Консольное окно для сервера необходимо для вывода логов
        "--name", "SecureServer",
        "--distpath", str(DIST_DIR),
        "--workpath", str(BUILD_DIR),
        "--noconfirm",
        "--clean",
        "--paths", str(PROJECT_ROOT),
        *data_args,
        *hidden_args,
        str(SERVER_ENTRY),
    ]

    print("[*] Выполнение команды PyInstaller...")
    res = subprocess.run(cmd, cwd=str(PROJECT_ROOT))
    if res.returncode != 0:
        print(f"[ERROR] Сборка сервера завершилась с ошибкой: код {res.returncode}")
        return False

    exe_path = DIST_DIR / "SecureServer" / "SecureServer.exe"
    if not exe_path.is_file():
        print(f"[ERROR] Исполняемый файл не найден: {exe_path}")
        return False

    print("\n" + "=" * 70)
    print("✅ СБОРКА СЕРВЕРА УСПЕШНО ЗАВЕРШЕНА!")
    print(f"[*] Исполняемый файл: {exe_path}")
    print(f"[*] Размер: {exe_path.stat().st_size / 1024 / 1024:.2f} МБ")
    print("=" * 70)
    return True


if __name__ == "__main__":
    ok = build_server()
    sys.exit(0 if ok else 1)
