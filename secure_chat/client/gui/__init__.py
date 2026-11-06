"""
Графический интерфейс пользователя (GUI) «Secure Chat» на базе PyQt5.
"""

from .main_window import MainWindow
from .chat_dialog import ChatDialog
from .key_dialog import KeyDialog
from .users_dialog import UsersDialog
from .config_dialog import ConfigDialog
from .database_dialog import DatabaseDialog
from .build_dialog import BuildDialog
from .integrity_dialog import IntegrityDialog
from .logs_dialog import LogsDialog

__all__ = [
    "MainWindow",
    "ChatDialog",
    "KeyDialog",
    "UsersDialog",
    "ConfigDialog",
    "DatabaseDialog",
    "BuildDialog",
    "IntegrityDialog",
    "LogsDialog",
]

