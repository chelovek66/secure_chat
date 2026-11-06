"""
Точка входа клиентского приложения «Secure Chat».
Запуск десктопного графического интерфейса PyQt5 с поддержкой High-DPI экранов.
"""

import os
import sys
import logging
from pathlib import Path

# Гарантируем, что корневая директория проекта находится в sys.path
root_dir = str(Path(__file__).resolve().parent.parent)
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

if __name__ == "__main__" and not __package__:
    import client
    __package__ = "client"

from PyQt5.QtWidgets import QApplication
from PyQt5.QtCore import Qt

from common.logger import log_service
try:
    from .gui.main_window import MainWindow
    from .gui.styles import APP_STYLESHEET
except (ImportError, ValueError):
    from client.gui.main_window import MainWindow
    from client.gui.styles import APP_STYLESHEET

# Инициализация консольного и внутрисистемного логирования
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log_service.setup_logging(root_level="INFO", attach_root=True)


def run_client():
    # Быстрый smoke-test для проверки собранного бинарного файла .exe
    if "--smoke-test" in sys.argv:
        # Проверяем инициализацию Qt подсистемы
        if hasattr(Qt, "AA_EnableHighDpiScaling"):
            QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
        app = QApplication(sys.argv)
        app.setApplicationName("SecureChat-Client")

        from common.config_manager import ConfigManager
        from common.build_info import get_build_info
        from client.crypto.bee2_wrapper import _find_bee2_library, engine

        cfg = ConfigManager().config
        info = get_build_info()
        bee2_path = _find_bee2_library()

        # Записываем маркер успешного прохождения теста в файл (для надежного считывания в Windows)
        marker = Path("smoke_test.log")
        marker.write_text(
            f"SMOKE_TEST_OK\nApp: {info.app_name}\nVersion: {info.version}\n"
            f"Engine: {info.crypto_engine}\nBee2: {bee2_path}\nServer: {cfg.server_url}\n",
            encoding="utf-8"
        )
        print("[SMOKE-TEST-OK] SecureClient binary initialized successfully.")
        print(f"App: {info.app_name}")
        print(f"Version: {info.version}")
        print(f"Crypto Engine: {info.crypto_engine}")
        print(f"Bee2 Library: {bee2_path}")
        print(f"Server URL: {cfg.server_url}")
        os._exit(0)

    # Настройка масштабирования интерфейса для мониторов высокого разрешения (4K / Retina)
    if hasattr(Qt, "AA_EnableHighDpiScaling"):
        QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    if hasattr(Qt, "AA_UseHighDpiPixmaps"):
        QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)

    app = QApplication(sys.argv)
    app.setApplicationName("SecureChat-Client")
    app.setApplicationDisplayName("Secure Chat (СТБ РБ / Bee2)")
    app.setStyleSheet(APP_STYLESHEET)

    # Аутентификация и регистрация пользователей при запуске (СТБ 34.101.47 bash256)
    from common.config_manager import ConfigManager
    try:
        from .network.api_client import ApiClient
        from .gui.auth_dialog import AuthDialog
    except (ImportError, ValueError):
        from client.network.api_client import ApiClient
        from client.gui.auth_dialog import AuthDialog

    cfg = ConfigManager().config
    api = ApiClient(base_url=cfg.server_url)

    auth_dlg = AuthDialog(api_client=api, keys_dir=cfg.keys_dir)
    if auth_dlg.exec_() != AuthDialog.Accepted or not auth_dlg.authenticated_user_id:
        sys.exit(0)

    window = MainWindow(
        authenticated_user=auth_dlg.authenticated_user_id,
        authenticated_keypair=auth_dlg.authenticated_keypair,
    )
    window.show()

    sys.exit(app.exec_())


if __name__ == "__main__":
    run_client()
