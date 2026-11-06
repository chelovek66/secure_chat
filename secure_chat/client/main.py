"""
Точка входа клиентского приложения «Secure Chat».
Запуск десктопного графического интерфейса PyQt5 с поддержкой High-DPI экранов.
"""

import sys
import logging
from pathlib import Path

if __name__ == "__main__" and not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    import client
    __package__ = "client"

from PyQt5.QtWidgets import QApplication
from PyQt5.QtCore import Qt

from common.logger import log_service
from .gui.main_window import MainWindow
from .gui.styles import APP_STYLESHEET

# Инициализация консольного и внутрисистемного логирования
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log_service.setup_logging(root_level="INFO", attach_root=True)


def run_client():
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
    from .network.api_client import ApiClient
    from .gui.auth_dialog import AuthDialog

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
