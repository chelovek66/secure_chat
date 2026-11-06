"""
Диалоговое окно аутентификации и регистрации пользователей «Secure Chat».
Обеспечивает защищенную регистрацию с криптографическим хэшированием паролей
(СТБ 34.101.47-2017 bash256) и персональной привязкой ключевых пар bign.
"""

from pathlib import Path
from typing import Optional
from PyQt5.QtWidgets import (
    QDialog,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QTabWidget,
    QWidget,
    QMessageBox,
    QFrame,
)
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtWidgets import QProgressBar

from ..network.api_client import ApiClient, ApiClientError, ApiConnectionError
from ..crypto.bign import BignCrypto, BignKeyPair
from ..crypto.keystore import KeyStore, KeyStoreError
from common.fingerprint import get_device_fingerprint, get_device_details


class AuthDialog(QDialog):
    """
    Диалоговое окно первичной аутентификации и регистрации абонента.
    """

    def __init__(self, api_client: ApiClient, keys_dir: str = "keys", parent=None):
        super().__init__(parent)
        self.api = api_client
        self.keys_dir = Path(keys_dir).resolve()
        self.keys_dir.mkdir(parents=True, exist_ok=True)

        self.authenticated_user_id: Optional[str] = None
        self.authenticated_keypair: Optional[BignKeyPair] = None

        # Получение цифрового отпечатка устройства (Device Fingerprint)
        try:
            self.device_id = getattr(self.api, "device_id", None) or get_device_fingerprint()
            self.device_details = get_device_details()
        except Exception:
            self.device_id = "unknown_device_id"
            self.device_details = {}

        self.setWindowTitle("Аутентификация — Secure Chat")
        self.resize(620, 640)
        self.setMinimumSize(560, 600)

        self.init_ui()

        # Таймер проверки сервера
        self.health_timer = QTimer(self)
        self.health_timer.setInterval(2500)
        self.health_timer.timeout.connect(self.check_server_status)
        self.health_timer.start()
        self.check_server_status()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.setContentsMargins(24, 20, 24, 20)

        # Заголовок
        title = QLabel("Вход в систему «Secure Chat»")
        title.setObjectName("titleLabel")
        layout.addWidget(title)

        subtitle = QLabel("Защищенная аутентификация пользователей")
        subtitle.setObjectName("subtitleLabel")
        layout.addWidget(subtitle)

        # Индикатор сервера
        server_box = QHBoxLayout()
        self.server_status_lbl = QLabel("⚪ Проверка связи с сервером...")
        self.server_status_lbl.setStyleSheet("font-size: 11px; font-weight: bold; color: #94A3B8;")
        server_box.addWidget(self.server_status_lbl)
        server_box.addStretch()

        self.start_srv_btn = QPushButton("🚀 Запустить сервер", self)
        self.start_srv_btn.setObjectName("secondaryButton")
        self.start_srv_btn.setStyleSheet("font-size: 11px; padding: 4px 10px;")
        self.start_srv_btn.clicked.connect(self.start_local_server)
        server_box.addWidget(self.start_srv_btn)
        layout.addLayout(server_box)

        # Отображение Device Fingerprint
        dev_frame = QFrame(self)
        dev_frame.setStyleSheet("background-color: #1E293B; border-radius: 6px; padding: 6px 10px; margin: 2px 0;")
        dev_layout = QHBoxLayout(dev_frame)
        dev_layout.setContentsMargins(8, 4, 8, 4)
        dev_icon = QLabel("💻 Отпечаток устройства (Device ID):")
        dev_icon.setStyleSheet("font-size: 11px; color: #94A3B8; font-weight: bold;")
        dev_layout.addWidget(dev_icon)

        short_dev = f"{self.device_id[:16]}...{self.device_id[-8:]}" if len(self.device_id) > 24 else self.device_id
        self.dev_label = QLabel(short_dev)
        self.dev_label.setStyleSheet("font-family: monospace; font-size: 11px; color: #38BDF8; font-weight: bold;")
        tooltip_txt = (
            f"Полный Device Fingerprint (SHA-256):\n{self.device_id}\n\n"
            f"Узел: {self.device_details.get('hostname', 'N/A')}\n"
            f"ОС: {self.device_details.get('platform', 'N/A')}\n"
            f"MAC: {self.device_details.get('mac', 'N/A')}"
        )
        self.dev_label.setToolTip(tooltip_txt)
        dev_layout.addWidget(self.dev_label)
        dev_layout.addStretch()
        layout.addWidget(dev_frame)

        # Вкладки: 1) Вход; 2) Регистрация
        self.tabs = QTabWidget(self)

        # --- Вкладка Вход ---
        tab_login = QWidget()
        v_login = QVBoxLayout(tab_login)
        v_login.setSpacing(10)
        v_login.setContentsMargins(16, 16, 16, 16)

        v_login.addWidget(QLabel("Логин / Идентификатор:"))
        self.login_user_input = QLineEdit(self)
        self.login_user_input.setMinimumHeight(38)
        self.login_user_input.setPlaceholderText("Например: alice или user_01")
        v_login.addWidget(self.login_user_input)

        v_login.addWidget(QLabel("Пароль:"))
        self.login_pass_input = QLineEdit(self)
        self.login_pass_input.setMinimumHeight(38)
        self.login_pass_input.setEchoMode(QLineEdit.Password)
        self.login_pass_input.setPlaceholderText("Введите ваш пароль")
        self.login_pass_input.returnPressed.connect(self.handle_login)
        v_login.addWidget(self.login_pass_input)

        v_login.addStretch()

        self.login_btn = QPushButton("Войти в Secure Chat", self)
        self.login_btn.setMinimumHeight(42)
        self.login_btn.setObjectName("successButton")
        self.login_btn.clicked.connect(self.handle_login)
        v_login.addWidget(self.login_btn)

        self.tabs.addTab(tab_login, "🔑 Вход в систему")

        # --- Вкладка Регистрация ---
        tab_reg = QWidget()
        v_reg = QVBoxLayout(tab_reg)
        v_reg.setSpacing(8)
        v_reg.setContentsMargins(16, 16, 16, 16)

        v_reg.addWidget(QLabel("Придумайте логин:"))
        self.reg_user_input = QLineEdit(self)
        self.reg_user_input.setMinimumHeight(38)
        self.reg_user_input.setPlaceholderText("Логин (только буквы, цифры, дефис, подчеркивание)")
        v_reg.addWidget(self.reg_user_input)

        v_reg.addWidget(QLabel("Пароль:"))
        self.reg_pass_input = QLineEdit(self)
        self.reg_pass_input.setMinimumHeight(38)
        self.reg_pass_input.setEchoMode(QLineEdit.Password)
        self.reg_pass_input.setPlaceholderText("Надежный пароль (минимум 8 символов, цифры, регистр)")
        self.reg_pass_input.textChanged.connect(self._on_password_changed)
        v_reg.addWidget(self.reg_pass_input)

        # Индикатор сложности пароля (Password Strength Meter)
        self.strength_lbl = QLabel("Сложность пароля: —")
        self.strength_lbl.setStyleSheet("font-size: 11px; font-weight: bold; color: #94A3B8;")
        v_reg.addWidget(self.strength_lbl)

        self.strength_bar = QProgressBar(self)
        self.strength_bar.setRange(0, 100)
        self.strength_bar.setValue(0)
        self.strength_bar.setFixedHeight(8)
        self.strength_bar.setTextVisible(False)
        self.strength_bar.setStyleSheet("QProgressBar { background-color: #334155; border-radius: 4px; }")
        v_reg.addWidget(self.strength_bar)

        self.strength_hint = QLabel("")
        self.strength_hint.setStyleSheet("font-size: 10px; color: #94A3B8;")
        self.strength_hint.setWordWrap(True)
        v_reg.addWidget(self.strength_hint)

        v_reg.addWidget(QLabel("Подтверждение пароля:"))
        self.reg_pass2_input = QLineEdit(self)
        self.reg_pass2_input.setMinimumHeight(38)
        self.reg_pass2_input.setEchoMode(QLineEdit.Password)
        self.reg_pass2_input.setPlaceholderText("Повторите пароль")
        self.reg_pass2_input.returnPressed.connect(self.handle_register)
        v_reg.addWidget(self.reg_pass2_input)

        reg_hint = QLabel("💡 Пароль хэшируется с солью и защищен от кражи.\nПри регистрации будет автоматически сформирован ваш личный ключ.")
        reg_hint.setStyleSheet("font-size: 11px; color: #94A3B8; padding: 4px 0;")
        reg_hint.setWordWrap(True)
        v_reg.addWidget(reg_hint)

        v_reg.addStretch()

        self.reg_btn = QPushButton("Зарегистрироваться", self)
        self.reg_btn.setMinimumHeight(42)
        self.reg_btn.setObjectName("successButton")
        self.reg_btn.clicked.connect(self.handle_register)
        v_reg.addWidget(self.reg_btn)

        self.tabs.addTab(tab_reg, "📝 Регистрация")

        layout.addWidget(self.tabs)

        # Кнопка отмены / выхода
        btn_box = QHBoxLayout()
        btn_box.addStretch()
        self.exit_btn = QPushButton("Выход", self)
        self.exit_btn.setMinimumHeight(36)
        self.exit_btn.setObjectName("secondaryButton")
        self.exit_btn.clicked.connect(self.reject)
        btn_box.addWidget(self.exit_btn)
        layout.addLayout(btn_box)

    def check_server_status(self):
        is_online = self.api.check_health(timeout=0.6)
        if is_online:
            self.server_status_lbl.setText("🟢 Сервер REST API доступен (онлайн)")
            self.server_status_lbl.setStyleSheet("font-size: 11px; font-weight: bold; color: #34D399;")
            self.start_srv_btn.setVisible(False)
        else:
            self.server_status_lbl.setText("🔴 Сервер оффлайн — запустите сервер для входа")
            self.server_status_lbl.setStyleSheet("font-size: 11px; font-weight: bold; color: #F87171;")
            self.start_srv_btn.setVisible(True)

    def start_local_server(self):
        import subprocess, sys
        srv_script = Path(__file__).resolve().parent.parent.parent / "server" / "app.py"
        try:
            subprocess.Popen([sys.executable, str(srv_script)], cwd=str(srv_script.parent.parent))
            QMessageBox.information(self, "Запуск сервера", "Сервер запускается в фоновом режиме. Пожалуйста, подождите 2-3 секунды.")
            QTimer.singleShot(2500, self.check_server_status)
        except Exception as exc:
            QMessageBox.critical(self, "Ошибка запуска", f"Не удалось запустить сервер: {exc}")

    def _evaluate_password_strength(self, pwd: str) -> tuple[int, str, str, str]:
        """
        Оценивает сложность пароля.
        Возвращает (процент, статус, цвет_hex, подсказка).
        """
        if not pwd:
            return 0, "—", "#94A3B8", ""

        length = len(pwd)
        has_upper = any(c.isupper() for c in pwd)
        has_lower = any(c.islower() for c in pwd)
        has_digit = any(c.isdigit() for c in pwd)
        has_special = any(not c.isalnum() for c in pwd)

        score = 0
        if length >= 8:
            score += 1
        if length >= 12:
            score += 1
        if has_upper and has_lower:
            score += 1
        if has_digit:
            score += 1
        if has_special:
            score += 1

        if length < 6 or score <= 2:
            return 30, "Слабый", "#EF4444", "Требуется не менее 8 символов, разные регистры и цифры"
        elif score in (3, 4):
            return 70, "Средний", "#F59E0B", "Хороший пароль. Добавьте спецсимволы (!@#$) для надежности"
        else:
            return 100, "Надежный", "#10B981", "Отличный криптостойкий пароль!"

    def _on_password_changed(self, text: str):
        pct, status_text, color, hint = self._evaluate_password_strength(text)
        self.strength_lbl.setText(f"Сложность пароля: {status_text}")
        self.strength_lbl.setStyleSheet(f"font-size: 11px; font-weight: bold; color: {color};")
        self.strength_bar.setValue(pct)
        self.strength_bar.setStyleSheet(f"QProgressBar {{ background-color: #334155; border-radius: 4px; }} QProgressBar::chunk {{ background-color: {color}; border-radius: 4px; }}")
        self.strength_hint.setText(hint)

    def handle_login(self):
        username = self.login_user_input.text().strip()
        password = self.login_pass_input.text()

        if not username:
            QMessageBox.warning(self, "Предупреждение", "Введите ваш логин!")
            self.login_user_input.setFocus()
            return
        if not password:
            QMessageBox.warning(self, "Предупреждение", "Введите пароль!")
            self.login_pass_input.setFocus()
            return

        if not self.api.check_health(timeout=0.8):
            QMessageBox.critical(self, "Сбой связи", "Сервер недоступен! Нажмите кнопку «🚀 Запустить сервер».")
            return

        try:
            res = self.api.login(username, password, device_id=self.device_id)
            if not res or ("token" not in res and not res.get("success")):
                msg = res.get("message") or res.get("detail", "Неверный логин или пароль!")
                QMessageBox.critical(self, "Ошибка входа", msg)
                return

            # Проверяем или загружаем ключи пользователя
            keypair = self._load_or_ensure_user_keys(username)
            if not keypair:
                return

            self.authenticated_user_id = username
            self.authenticated_keypair = keypair
            self.accept()

        except ApiClientError as exc:
            QMessageBox.critical(self, "Ошибка аутентификации", f"Сбой проверки учетных данных: {exc}")

    def handle_register(self):
        username = self.reg_user_input.text().strip()
        password = self.reg_pass_input.text()
        password_confirm = self.reg_pass2_input.text()

        if not username:
            QMessageBox.warning(self, "Предупреждение", "Введите желаемый логин!")
            self.reg_user_input.setFocus()
            return
        if len(username) < 2:
            QMessageBox.warning(self, "Предупреждение", "Логин должен содержать не менее 2 символов!")
            return
        if not password:
            QMessageBox.warning(self, "Предупреждение", "Введите пароль!")
            self.reg_pass_input.setFocus()
            return
        if password != password_confirm:
            QMessageBox.warning(self, "Ошибка пароля", "Введенные пароли не совпадают!")
            self.reg_pass2_input.setFocus()
            return

        if not self.api.check_health(timeout=0.8):
            QMessageBox.critical(self, "Сбой связи", "Сервер недоступен! Нажмите кнопку «🚀 Запустить сервер».")
            return

        try:
            # 1. Генерируем новую персональную ключевую пару bign с именем пользователя
            keypair = BignCrypto.generate_keypair()
            pub_file, priv_file = KeyStore.save_keys(self.keys_dir, keypair, username=username)

            # 2. Регистрируем пользователя на сервере с хэшированием пароля и привязкой устройства
            res = self.api.register(
                user_id=username,
                password=password,
                public_key_hex=keypair.public_hex,
                device_id=self.device_id,
            )

            is_ok = (isinstance(res, dict) and (res.get("success") or res.get("status") == "ok")) or res is True
            if not is_ok:
                err_msg = res.get("message") if isinstance(res, dict) else "Сбой регистрации пользователя!"
                QMessageBox.critical(self, "Ошибка регистрации", err_msg)
                return

            QMessageBox.information(
                self,
                "Регистрация завершена",
                f"Пользователь '{username}' успешно зарегистрирован!\n\n"
                f"Сформированы персональные ключи безопасности:\n"
                f"• {pub_file.name}\n"
                f"• {priv_file.name}\n\n"
                f"Пароль надежно сохранен в защищенном виде.",
            )

            self.authenticated_user_id = username
            self.authenticated_keypair = keypair
            self.accept()

        except ApiClientError as exc:
            QMessageBox.critical(self, "Ошибка регистрации", f"Сервер отклонил регистрацию: {exc}")
        except Exception as exc:
            QMessageBox.critical(self, "Ошибка", f"Не удалось выполнить регистрацию: {exc}")

    def _load_or_ensure_user_keys(self, username: str) -> Optional[BignKeyPair]:
        """
        Ищет и загружает персональные ключи пользователя {username}_public.bkey / {username}_private.bkey.
        """
        user_priv = self.keys_dir / f"{username}_private.bkey"
        user_pub = self.keys_dir / f"{username}_public.bkey"

        # Если персональные файлы найдены
        if user_priv.is_file() and user_pub.is_file():
            try:
                priv_bytes = KeyStore.load_private_key(user_priv, expected_username=username)
                pub_bytes = KeyStore.load_public_key(user_pub, expected_username=username)
                return BignKeyPair(private_key=priv_bytes, public_key=pub_bytes)
            except KeyStoreError as exc:
                QMessageBox.critical(self, "Ошибка ключей", f"Не удалось загрузить личный ключ: {exc}")
                return None

        # Проверяем fallback (public.bkey / private.bkey)
        fb_priv = self.keys_dir / KeyStore.PRIVATE_KEY_FILENAME
        fb_pub = self.keys_dir / KeyStore.PUBLIC_KEY_FILENAME
        if fb_priv.is_file() and fb_pub.is_file():
            try:
                priv_bytes = KeyStore.load_private_key(fb_priv)
                pub_bytes = KeyStore.load_public_key(fb_pub)
                # Пересохраняем с персонализацией имени
                kp = BignKeyPair(private_key=priv_bytes, public_key=pub_bytes)
                KeyStore.save_keys(self.keys_dir, kp, username=username)
                return kp
            except Exception:
                pass

        # Если ключей еще нет — генерируем автоматически под пользователя
        try:
            kp = BignCrypto.generate_keypair()
            KeyStore.save_keys(self.keys_dir, kp, username=username)
            return kp
        except Exception as exc:
            QMessageBox.critical(self, "Ошибка генерации ключей", f"Не удалось создать ключи: {exc}")
            return None
