"""
Главное окно клиентского приложения «Secure Chat» (MainWindow).
Координирует жизненный цикл сессии, загрузку криптографических ключей,
подключение к серверу и открытие диалоговых окон.
"""

import sys
import logging
from pathlib import Path
from typing import Optional

from PyQt5.QtWidgets import (
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QMessageBox,
    QInputDialog,
    QStatusBar,
)
from PyQt5.QtCore import Qt, QTimer

from ..crypto.bign import BignKeyPair
from ..crypto.keystore import KeyStore, KeyStoreError
from ..network.api_client import ApiClient, ApiClientError, ApiConnectionError
from common.config_manager import ConfigManager, ClientConfig
from common.build_info import get_build_info
from common.integrity import SoftwareIntegrityManager
from .key_dialog import KeyDialog
from .users_dialog import UsersDialog
from .chat_dialog import ChatDialog
from .config_dialog import ConfigDialog
from .database_dialog import DatabaseDialog
from .build_dialog import BuildDialog
from .integrity_dialog import IntegrityDialog
from .logs_dialog import LogsDialog

logger = logging.getLogger("secure_chat.gui.main")


class MainWindow(QMainWindow):
    """
    Главная форма координации работы клиентского приложения.
    """

    def __init__(
        self,
        authenticated_user: Optional[str] = None,
        authenticated_keypair: Optional[BignKeyPair] = None,
    ):
        super().__init__()
        self.setWindowTitle("Secure Chat — Сквозное шифрование")
        self.resize(880, 480)
        self.setMinimumSize(800, 440)

        self.config_manager = ConfigManager()
        self.config = self.config_manager.config
        self.api = ApiClient(base_url=self.config.server_url)
        self.keypair: Optional[BignKeyPair] = authenticated_keypair
        self.active_chat_dialog: Optional[ChatDialog] = None
        self.logs_dialog: Optional[LogsDialog] = None
        self._server_proc = None
        self.keys_dir: str = str(Path(self.config.keys_dir).resolve())

        # Регистрация слушателя изменения настроек
        self.config_manager.add_change_listener(self._on_config_changed)

        self.init_ui()
        self._check_startup_integrity()

        # Применение параметров аутентифицированного пользователя
        if authenticated_user:
            self.user_id_input.setText(authenticated_user)
            self.user_id_input.setEnabled(False)
            self.api.user_id = authenticated_user
            if self.keypair:
                self.users_btn.setEnabled(True)
                self.chat_btn.setEnabled(True)
                self.connect_btn.setEnabled(False)
                self.status_bar.showMessage(f"Аутентифицирован: {authenticated_user} @ {self.config.server_url}")

        # Фоновый опрос доступности сервера для динамического статуса
        self.health_timer = QTimer(self)
        self.health_timer.setInterval(3000)
        self.health_timer.timeout.connect(self.update_server_status_indicator)
        self.health_timer.start()
        self.update_server_status_indicator()

        logger.info("Главное окно «Secure Chat» инициализировано.")

    def _on_config_changed(self, new_cfg: ClientConfig):
        """Реакция на динамическое изменение конфигурации."""
        self.config = new_cfg
        self.api.set_base_url(new_cfg.server_url)
        self.server_url_input.setText(new_cfg.server_url)
        self.keys_dir = str(Path(new_cfg.keys_dir).resolve())
        self.status_bar.showMessage(f"Конфигурация обновлена: {new_cfg.server_url}")

    def init_ui(self):
        central_widget = QWidget(self)
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        layout.setSpacing(12)
        layout.setContentsMargins(24, 20, 24, 20)

        # Заголовок
        header_layout = QHBoxLayout()
        v_title = QVBoxLayout()
        title = QLabel("Программный комплекс «Secure Chat»")
        title.setObjectName("titleLabel")
        v_title.addWidget(title)

        subtitle = QLabel("Защищенная система обмена сообщениями")
        subtitle.setObjectName("subtitleLabel")
        v_title.addWidget(subtitle)
        header_layout.addLayout(v_title)

        header_layout.addStretch()

        # Панель системных инструментов
        self.sys_config_btn = QPushButton("⚙️ Настройки", self)
        self.sys_config_btn.setObjectName("secondaryButton")
        self.sys_config_btn.clicked.connect(self.open_config_dialog)
        header_layout.addWidget(self.sys_config_btn)

        self.sys_logs_btn = QPushButton("📋 Журнал", self)
        self.sys_logs_btn.setObjectName("secondaryButton")
        self.sys_logs_btn.clicked.connect(self.open_logs_dialog)
        header_layout.addWidget(self.sys_logs_btn)

        self.sys_integrity_btn = QPushButton("🛡️ Контроль целостности", self)
        self.sys_integrity_btn.setObjectName("secondaryButton")
        self.sys_integrity_btn.clicked.connect(self.open_integrity_dialog)
        header_layout.addWidget(self.sys_integrity_btn)

        self.sys_about_btn = QPushButton("ℹ️ Сборка", self)
        self.sys_about_btn.setObjectName("secondaryButton")
        self.sys_about_btn.clicked.connect(self.open_build_dialog)
        header_layout.addWidget(self.sys_about_btn)

        layout.addLayout(header_layout)

        # 1. Настройки подключения и статус сервера
        server_header_h = QHBoxLayout()
        server_header_h.addWidget(QLabel("Адрес сервера (REST API):"))
        server_header_h.addStretch()

        self.server_status_badge = QLabel("⚪ Проверка связи...", self)
        self.server_status_badge.setStyleSheet("font-size: 11px; font-weight: bold; color: #94A3B8;")
        server_header_h.addWidget(self.server_status_badge)

        self.start_server_btn = QPushButton("🚀 Запустить сервер", self)
        self.start_server_btn.setObjectName("secondaryButton")
        self.start_server_btn.setStyleSheet("font-size: 11px; padding: 3px 10px;")
        self.start_server_btn.clicked.connect(self.start_local_server)
        server_header_h.addWidget(self.start_server_btn)

        layout.addLayout(server_header_h)
        self.server_url_input = QLineEdit(self.config.server_url, self)
        layout.addWidget(self.server_url_input)

        # 2. Идентификатор пользователя
        lbl_user = QLabel("Ваш идентификатор (Логин / ID):")
        layout.addWidget(lbl_user)
        self.user_id_input = QLineEdit(self)
        self.user_id_input.setPlaceholderText("Например: alice или user_01")
        layout.addWidget(self.user_id_input)

        # 3. Кнопки управления ключами и входом
        btn_grid_1 = QHBoxLayout()
        self.key_manager_btn = QPushButton("Мастер ключей...", self)
        self.key_manager_btn.setObjectName("secondaryButton")
        self.key_manager_btn.clicked.connect(self.open_key_dialog)
        btn_grid_1.addWidget(self.key_manager_btn)

        self.connect_btn = QPushButton("Подключиться к серверу", self)
        self.connect_btn.setObjectName("successButton")
        self.connect_btn.clicked.connect(self.connect_and_register)
        btn_grid_1.addWidget(self.connect_btn)
        layout.addLayout(btn_grid_1)

        # 4. Панель взаимодействия (активна после подключения)
        layout.addSpacing(6)
        btn_grid_2 = QHBoxLayout()
        self.users_btn = QPushButton("Пользователи в сети", self)
        self.users_btn.setEnabled(False)
        self.users_btn.clicked.connect(self.open_users_dialog)
        btn_grid_2.addWidget(self.users_btn)

        self.chat_btn = QPushButton("Открыть диалог...", self)
        self.chat_btn.setEnabled(False)
        self.chat_btn.clicked.connect(self.open_chat_dialog)
        btn_grid_2.addWidget(self.chat_btn)
        layout.addLayout(btn_grid_2)

        layout.addStretch()

        # Строка состояния
        self.status_bar = QStatusBar(self)
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Готов к работе. Требуется авторизация.")

    def _check_startup_integrity(self):
        """Фоновый неблокирующий контроль целостности ПО при запуске."""
        if not self.config.verify_integrity_on_startup:
            return

        try:
            im = SoftwareIntegrityManager()
            if im.manifest_path.is_file():
                report = im.verify_integrity()
                if report.is_valid:
                    self.status_bar.showMessage("🛡️ Контроль целостности ПО пройден (файлы не изменены)")
                else:
                    self.status_bar.showMessage(f"🚨 ВНИМАНИЕ: {report.status}! Нарушена целостность ПО")
            else:
                self.status_bar.showMessage("ℹ️ Эталонные контрольные суммы не сформированы")
        except Exception:
            pass

    def open_config_dialog(self):
        """Открывает окно управления конфигурацией."""
        dlg = ConfigDialog(self, config_manager=self.config_manager)
        if dlg.exec_() == ConfigDialog.Accepted:
            self._on_config_changed(dlg.config)

    def open_database_dialog(self):
        """Открывает окно администрирования базы данных."""
        dlg = DatabaseDialog(self.api, self)
        dlg.exec_()

    def open_logs_dialog(self):
        """Открывает окно системного журнала событий и аудита безопасности."""
        if self.logs_dialog is None:
            self.logs_dialog = LogsDialog(api_client=self.api, parent=self)
        self.logs_dialog.show()
        self.logs_dialog.raise_()
        self.logs_dialog.activateWindow()

    def open_integrity_dialog(self):
        """Открывает окно контроля целостности и ЭЦП ПО."""
        dlg = IntegrityDialog(self)
        dlg.exec_()

    def open_build_dialog(self):
        """Открывает окно сведений о сборке и версии ПО."""
        server_info = {}
        try:
            if self.api.check_health(timeout=0.4):
                server_info = self.api.get_version(silent=True)
        except Exception:
            pass
        dlg = BuildDialog(self, server_build_info=server_info)
        dlg.exec_()

    def update_server_status_indicator(self):
        """Периодически проверяет доступность сервера без блокировки интерфейса."""
        is_alive = self.api.check_health(timeout=0.4)
        if is_alive:
            self.server_status_badge.setText("🟢 Сервер онлайн")
            self.server_status_badge.setStyleSheet("color: #34D399; font-weight: bold; font-size: 11px;")
            self.start_server_btn.setVisible(False)
        else:
            self.server_status_badge.setText("🔴 Сервер офлайн")
            self.server_status_badge.setStyleSheet("color: #F87171; font-weight: bold; font-size: 11px;")
            self.start_server_btn.setVisible(True)

    def start_local_server(self):
        """Запускает локальный веб-сервер FastAPI в фоновом процессе."""
        if self.api.check_health(timeout=0.4):
            self.update_server_status_indicator()
            QMessageBox.information(self, "Сервер", "Сервер уже запущен и готов к работе!")
            return

        import subprocess
        server_script = Path(__file__).resolve().parent.parent.parent / "server" / "app.py"
        try:
            self._server_proc = subprocess.Popen(
                [sys.executable, str(server_script)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            logger.info("Запущен локальный сервер FastAPI в фоновом процессе.")
            self.status_bar.showMessage("Сервер запускается, ожидание ответа...")
            QTimer.singleShot(1200, self._check_server_after_launch)
        except Exception as exc:
            QMessageBox.critical(self, "Ошибка запуска", f"Не удалось запустить сервер: {exc}")

    def _check_server_after_launch(self):
        """Неблокирующая проверка доступности запущенного сервера."""
        self.update_server_status_indicator()
        if self.api.check_health(timeout=1.0):
            QMessageBox.information(
                self,
                "Сервер запущен",
                f"Сервер «Secure Chat» успешно запущен и отвечает по адресу:\n{self.api.base_url}",
            )
            self.status_bar.showMessage("Сервер готов к работе.")
        else:
            self.status_bar.showMessage("Сервер инициализируется...")

    def closeEvent(self, event):
        """Останавливает таймеры, закрывает сетевые сессии и локальный сервер при выходе."""
        if hasattr(self, "health_timer") and self.health_timer.isActive():
            self.health_timer.stop()

        if hasattr(self, "active_chat_dialog") and self.active_chat_dialog:
            try:
                self.active_chat_dialog.close()
            except Exception:
                pass

        if hasattr(self, "logs_dialog") and self.logs_dialog:
            try:
                self.logs_dialog.close()
            except Exception:
                pass

        if hasattr(self, "api") and self.api:
            self.api.close()

        if hasattr(self, "_server_proc") and self._server_proc:
            try:
                self._server_proc.terminate()
            except Exception:
                pass
        event.accept()

    def open_key_dialog(self):
        curr_user = self.user_id_input.text().strip() or getattr(self.api, "user_id", None)
        dlg = KeyDialog(self, initial_dir=self.keys_dir, username=curr_user)
        if dlg.exec_() == KeyDialog.Accepted:
            self.keys_dir = dlg.target_dir
            self.status_bar.showMessage(f"Ключевые файлы сохранены в: {self.keys_dir}")

    def connect_and_register(self):
        user_id = self.user_id_input.text().strip()
        server_url = self.server_url_input.text().strip()

        if not user_id:
            QMessageBox.warning(self, "Ошибка ввода", "Введите идентификатор пользователя!")
            return
        if not server_url:
            QMessageBox.warning(self, "Ошибка ввода", "Введите URL сервера!")
            return

        self.api.set_base_url(server_url)

        # Быстрая проверка связи перед попыткой регистрации
        if not self.api.check_health(timeout=1.0):
            QMessageBox.warning(
                self,
                "Сервер недоступен",
                f"Не удалось связаться с сервером по адресу {server_url}.\n\n"
                f"Убедитесь, что сервер запущен:\n"
                f"• Нажмите кнопку «🚀 Запустить сервер» вверху\n"
                f"• Или запустите в консоли: py .\\server\\app.py",
            )
            return

        # Загрузка локальных ключей пользователя
        try:
            # Проверяем, существует ли закрытый ключ пользователя
            _, priv_path = KeyStore.find_user_keys(self.keys_dir, user_id)
            if not priv_path.is_file():
                reply = QMessageBox.question(
                    self,
                    "Ключи не найдены",
                    f"Персональные ключи для пользователя '{user_id}' в папке {self.keys_dir} не найдены. Сгенерировать новую пару?",
                    QMessageBox.Yes | QMessageBox.No,
                )
                if reply == QMessageBox.Yes:
                    self.open_key_dialog()
                    return
                else:
                    return

            # Попытка чтения ключей (с запросом пароля при необходимости)
            password = None
            try:
                self.keypair = KeyStore.load_keys(self.keys_dir, password=None, expected_username=user_id)
            except KeyStoreError as k_err:
                if "требуется пароль" in str(k_err).lower():
                    pwd, ok = QInputDialog.getText(
                        self,
                        "Пароль закрытого ключа",
                        "Файл личного ключа защищен паролем. Введите пароль:",
                        QLineEdit.Password,
                    )
                    if not ok:
                        return
                    password = pwd
                    self.keypair = KeyStore.load_keys(self.keys_dir, password=password, expected_username=user_id)
                else:
                    raise

            # Регистрация открытого ключа на сервере
            logger.info(f"Регистрация пользователя '{user_id}' на сервере {server_url}...")
            self.api.register(user_id, self.keypair.public_hex)
            logger.info(f"Пользователь '{user_id}' успешно зарегистрирован. Открытый ключ опубликован.")

            self.status_bar.showMessage(f"Подключен: {user_id} @ {server_url}")
            self.users_btn.setEnabled(True)
            self.chat_btn.setEnabled(True)
            self.connect_btn.setEnabled(False)
            self.user_id_input.setEnabled(False)
            self.server_url_input.setEnabled(False)

            QMessageBox.information(
                self,
                "Успешное подключение",
                f"Пользователь '{user_id}' успешно зарегистрирован на сервере.\n"
                f"Открытый ключ опубликован в реестре абонентов.",
            )

        except ApiConnectionError as exc:
            QMessageBox.critical(self, "Сбой связи", f"Не удалось связаться с сервером: {exc}")
        except KeyStoreError as exc:
            QMessageBox.critical(self, "Ошибка ключей", f"Не удалось загрузить ключевую пару: {exc}")
        except Exception as exc:
            QMessageBox.critical(self, "Критическая ошибка", f"Ошибка авторизации: {exc}")

    def open_users_dialog(self):
        dlg = UsersDialog(self.api, self)
        if dlg.exec_() == UsersDialog.Accepted and dlg.selected_user:
            self._start_chat_with_user(dlg.selected_user)

    def open_chat_dialog(self):
        target_id, ok = QInputDialog.getText(
            self,
            "Выбор собеседника",
            "Введите идентификатор пользователя для начала диалога:",
        )
        if ok and target_id.strip():
            self._start_chat_with_user(target_id.strip())

    def _start_chat_with_user(self, partner_id: str):
        if partner_id == self.api.user_id:
            QMessageBox.warning(self, "Предупреждение", "Нельзя начать чат с самим собой!")
            return

        try:
            user_info = self.api.get_user(partner_id)
            if not user_info:
                QMessageBox.warning(self, "Ошибка", f"Пользователь '{partner_id}' не найден на сервере!")
                return

            pub_hex = user_info.get("public_key", "").strip()
            if not pub_hex:
                QMessageBox.warning(self, "Ошибка ключа", f"У пользователя '{partner_id}' отсутствует открытый ключ!")
                return

            partner_pubkey_bytes = bytes.fromhex(pub_hex)
            if len(partner_pubkey_bytes) != 64:
                QMessageBox.warning(
                    self,
                    "Некорректный ключ абонента",
                    f"Открытый ключ пользователя '{partner_id}' имеет некорректный размер ({len(partner_pubkey_bytes)} байт вместо 64 байт).\n"
                    f"Пользователю '{partner_id}' необходимо пересоздать ключевую пару.",
                )
                return

            logger.info(f"Получен открытый ключ абонента '{partner_id}'. Инициализация диалога E2EE...")

            # Открытие окна чата
            self.active_chat_dialog = ChatDialog(
                api_client=self.api,
                keypair=self.keypair,
                partner_id=partner_id,
                partner_pubkey=partner_pubkey_bytes,
                parent=self,
            )
            self.active_chat_dialog.show()
            logger.info(f"Окно защищенного чата с '{partner_id}' открыто.")

        except ApiClientError as exc:
            QMessageBox.critical(self, "Ошибка сети", f"Не удалось запросить ключ абонента: {exc}")
        except Exception as exc:
            QMessageBox.critical(self, "Ошибка инициализации", f"Не удалось открыть диалог: {exc}")
