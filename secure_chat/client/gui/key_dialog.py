"""
Диалоговое окно мастера генерации ключевых контейнеров Bign (СТБ 34.101.45-2013).
Поддерживает персонализацию имен ключей ({username}_public.bkey, {username}_private.bkey)
и строгую защиту от импорта чужих ключей.
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
    QFileDialog,
    QMessageBox,
)
from PyQt5.QtCore import Qt

from ..crypto.bign import BignCrypto
from ..crypto.keystore import KeyStore, KeyStoreError


class KeyDialog(QDialog):
    """
    Мастер генерации и импорта ключевых пар bign (контейнеры bkey).
    """

    def __init__(self, parent=None, initial_dir: str = "", username: Optional[str] = None):
        super().__init__(parent)
        self.username = username.strip() if username and username.strip() else None
        self.setWindowTitle("Мастер ключей")
        self.resize(760, 300)
        self.setMinimumSize(700, 270)
        self.target_dir = initial_dir or str(Path.cwd() / "keys")
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(12)

        title = QLabel("Генерация / Импорт ключевой пары")
        title.setObjectName("titleLabel")
        layout.addWidget(title)

        desc = QLabel("Формирование и управление персональными ключами безопасности.")
        desc.setObjectName("subtitleLabel")
        layout.addWidget(desc)

        if self.username:
            user_lbl = QLabel(
                f"Текущий пользователь: <b>{self.username}</b> "
                f"(ключи: <code>{self.username}_{KeyStore.PUBLIC_KEY_FILENAME}</code>, "
                f"<code>{self.username}_{KeyStore.PRIVATE_KEY_FILENAME}</code>)"
            )
            user_lbl.setStyleSheet("color: #38BDF8; font-size: 12px; margin: 2px 0;")
            layout.addWidget(user_lbl)

        # Выбор каталога назначения
        dir_layout = QHBoxLayout()
        self.dir_input = QLineEdit(self.target_dir)
        self.dir_input.setMinimumHeight(34)
        self.dir_btn = QPushButton("Обзор...", self)
        self.dir_btn.setObjectName("secondaryButton")
        self.dir_btn.setMinimumHeight(34)
        self.dir_btn.clicked.connect(self.browse_directory)
        dir_layout.addWidget(self.dir_input)
        dir_layout.addWidget(self.dir_btn)
        layout.addLayout(dir_layout)

        # Кнопки действий
        btn_layout = QHBoxLayout()

        self.import_btn = QPushButton("Импортировать ключи...", self)
        self.import_btn.setObjectName("secondaryButton")
        self.import_btn.setMinimumHeight(38)
        self.import_btn.clicked.connect(self.import_keys)

        self.use_existing_btn = QPushButton("Использовать ключи из папки", self)
        self.use_existing_btn.setObjectName("secondaryButton")
        self.use_existing_btn.setMinimumHeight(38)
        self.use_existing_btn.clicked.connect(self.use_current_keys)

        self.generate_btn = QPushButton("Сгенерировать новые", self)
        self.generate_btn.setMinimumHeight(38)
        self.generate_btn.clicked.connect(self.generate_keys)

        self.cancel_btn = QPushButton("Отмена", self)
        self.cancel_btn.setObjectName("secondaryButton")
        self.cancel_btn.setMinimumHeight(38)
        self.cancel_btn.clicked.connect(self.reject)

        btn_layout.addWidget(self.use_existing_btn)
        btn_layout.addWidget(self.import_btn)
        btn_layout.addStretch()
        btn_layout.addWidget(self.cancel_btn)
        btn_layout.addWidget(self.generate_btn)
        layout.addLayout(btn_layout)

    def _validate_key_ownership(self, file_path: Path | str) -> bool:
        """
        Проверяет, принадлежит ли файл ключа текущему пользователю.
        Если имя файла не содержит username или в метаданных чужой логин — выводит предупреждение и блокирует действие.
        """
        if not self.username:
            return True

        p = Path(file_path)
        # 1. Проверка имени файла
        if self.username.lower() not in p.name.lower():
            QMessageBox.warning(
                self,
                "Ошибка импорта ключа",
                f"Ошибка импорта ключа: данный ключ не принадлежит пользователю '{self.username}'! Импорт чужих ключей запрещен.",
            )
            return False

        # 2. Проверка метаданных файла при наличии
        if p.is_file():
            try:
                data = p.read_bytes()
                meta_user, _ = KeyStore.extract_metadata(data)
                if meta_user and meta_user.lower() != self.username.lower():
                    QMessageBox.warning(
                        self,
                        "Ошибка импорта ключа",
                        f"Ошибка импорта ключа: данный ключ не принадлежит пользователю '{self.username}'! Импорт чужих ключей запрещен.",
                    )
                    return False
            except Exception:
                pass

        return True

    def use_current_keys(self):
        """Активирует существующую ключевую пару из текущей выбранной папки."""
        target_path = self.dir_input.text().strip()
        if not target_path:
            QMessageBox.warning(self, "Предупреждение", "Укажите папку с ключами!")
            return
        p = Path(target_path).resolve()

        pub, priv = KeyStore.find_user_keys(p, self.username)

        if not pub.is_file() or not priv.is_file():
            if self.username:
                expected_files = (
                    f"• {self.username}_{KeyStore.PUBLIC_KEY_FILENAME}\n"
                    f"• {self.username}_{KeyStore.PRIVATE_KEY_FILENAME}\n\n"
                    f"(или стандартные {KeyStore.PUBLIC_KEY_FILENAME} / {KeyStore.PRIVATE_KEY_FILENAME})"
                )
            else:
                expected_files = (
                    f"• {KeyStore.PUBLIC_KEY_FILENAME}\n"
                    f"• {KeyStore.PRIVATE_KEY_FILENAME}"
                )
            QMessageBox.warning(
                self,
                "Ключи не найдены",
                f"В папке '{target_path}' не найдены файлы:\n{expected_files}\n\n"
                "Нажмите «Сгенерировать новые» или выберите другую папку через «Обзор...».",
            )
            return

        try:
            # Если файл содержит username в имени, проверяем с expected_username
            # Если использован fallback на public.bkey, проверяем метаданные на отсутствие чужого пользователя
            if self.username and self.username.lower() in pub.name.lower():
                KeyStore.load_public_key(pub, expected_username=self.username)
            else:
                # Fallback на public.bkey: проверяем, что в контейнере нет чужих метаданных
                data = pub.read_bytes()
                meta_user, _ = KeyStore.extract_metadata(data)
                if meta_user and self.username and meta_user.lower() != self.username.lower():
                    raise KeyStoreError(
                        f"Ключ принадлежит другому пользователю или не соответствует логину '{self.username}'"
                    )
                KeyStore.load_public_key(pub)

            self.target_dir = str(p)
            QMessageBox.information(
                self,
                "Ключи подключены",
                f"Ключевая пара ({pub.name}, {priv.name}) успешно выбрана и готова к работе:\n{p}",
            )
            self.accept()
        except KeyStoreError as exc:
            QMessageBox.critical(self, "Ошибка ключей", f"Ключ не прошел валидацию: {exc}")

    def browse_directory(self):
        chosen = QFileDialog.getExistingDirectory(
            self, "Выберите папку для сохранения ключей", self.dir_input.text()
        )
        if chosen:
            self.dir_input.setText(chosen)

    def generate_keys(self):
        target_path = self.dir_input.text().strip()
        if not target_path:
            QMessageBox.warning(self, "Предупреждение", "Укажите целевую директорию для сохранения ключей!")
            return

        password = None

        try:
            # 1. Генерация пары
            keypair = BignCrypto.generate_keypair()
            # 2. Сохранение контейнеров с учетом username
            pub_f, priv_f = KeyStore.save_keys(target_path, keypair, password, username=self.username)

            QMessageBox.information(
                self,
                "Успех",
                f"Ключевая пара успешно сформирована и сохранена!\n\n"
                f"Открытый ключ: {pub_f.name}\n"
                f"Личный ключ: {priv_f.name}\n"
                f"Папка: {target_path}",
            )
            self.target_dir = target_path
            self.accept()
        except KeyStoreError as exc:
            QMessageBox.critical(self, "Ошибка сохранения", f"Не удалось сохранить ключи: {exc}")
        except Exception as exc:
            QMessageBox.critical(self, "Критическая ошибка", f"Ошибка генерации: {exc}")

    def import_keys(self):
        """
        Импорт существующей ключевой пары bign из выбранной папки.
        Защищен от импорта чужих ключей и ошибки WinError 32.
        """
        source_dir = QFileDialog.getExistingDirectory(
            self, "Выберите папку с ключами для импорта", self.dir_input.text()
        )
        if not source_dir:
            return

        target_path = self.dir_input.text().strip()
        if not target_path:
            target_path = source_dir
            self.dir_input.setText(target_path)

        src = Path(source_dir).resolve()
        dst = Path(target_path).resolve()

        if self.username:
            user_pub_src = src / f"{self.username}_{KeyStore.PUBLIC_KEY_FILENAME}"
            user_priv_src = src / f"{self.username}_{KeyStore.PRIVATE_KEY_FILENAME}"

            if user_pub_src.is_file() and user_priv_src.is_file():
                pub_src = user_pub_src
                priv_src = user_priv_src
            else:
                # Проверяем наличие любых ключей в исходной директории
                bkey_files = list(src.glob("*.bkey"))
                if bkey_files:
                    matching = [f for f in bkey_files if self.username.lower() in f.name.lower()]
                    if not matching:
                        QMessageBox.warning(
                            self,
                            "Ошибка импорта ключа",
                            f"Ошибка импорта ключа: данный ключ не принадлежит пользователю '{self.username}'! Импорт чужих ключей запрещен.",
                        )
                        return

                reply = QMessageBox.question(
                    self,
                    "Файлы не найдены",
                    f"В выбранной папке отсутствуют ключевые файлы для '{self.username}':\n"
                    f"• {self.username}_{KeyStore.PUBLIC_KEY_FILENAME}\n"
                    f"• {self.username}_{KeyStore.PRIVATE_KEY_FILENAME}\n\n"
                    "Выбрать файлы открытого и закрытого ключей вручную?",
                    QMessageBox.Yes | QMessageBox.No,
                )
                if reply == QMessageBox.Yes:
                    self._import_individual_files(dst)
                return
        else:
            pub_src = src / KeyStore.PUBLIC_KEY_FILENAME
            priv_src = src / KeyStore.PRIVATE_KEY_FILENAME

            # Если стандартные файлы не найдены в папке
            if not pub_src.is_file() or not priv_src.is_file():
                reply = QMessageBox.question(
                    self,
                    "Файлы не найдены",
                    f"В выбранной папке отсутствуют стандартные файлы:\n"
                    f"• {KeyStore.PUBLIC_KEY_FILENAME}\n"
                    f"• {KeyStore.PRIVATE_KEY_FILENAME}\n\n"
                    "Выбрать файлы открытого и закрытого ключей вручную?",
                    QMessageBox.Yes | QMessageBox.No,
                )
                if reply == QMessageBox.Yes:
                    self._import_individual_files(dst)
                return

        # Проверка принадлежности ключей текущему пользователю
        if not self._validate_key_ownership(pub_src) or not self._validate_key_ownership(priv_src):
            return

        pub_dst_name = pub_src.name
        priv_dst_name = priv_src.name

        # 1. Если папка источника совпадает с целевой — просто активируем без копирования!
        if src == dst:
            try:
                KeyStore.load_public_key(pub_src, expected_username=self.username)
                QMessageBox.information(
                    self,
                    "Ключи подключены",
                    f"Ключевая пара уже находится в целевой папке и готова к работе:\n{src}",
                )
                self.target_dir = str(src)
                self.accept()
                return
            except KeyStoreError as exc:
                QMessageBox.critical(self, "Ошибка ключей", f"Ключи повреждены или не принадлежат пользователю: {exc}")
                return

        # 2. Если папки разные — подтверждение перезаписи
        dst.mkdir(parents=True, exist_ok=True)
        pub_dst = dst / pub_dst_name
        priv_dst = dst / priv_dst_name

        if priv_dst.is_file():
            reply = QMessageBox.question(
                self,
                "Подтверждение перезаписи",
                f"В папке назначения '{dst}' уже есть ключевой файл '{priv_dst.name}'.\n"
                "Заменить его импортируемым ключом?",
                QMessageBox.Yes | QMessageBox.No,
            )
            if reply != QMessageBox.Yes:
                return

        try:
            pub_data = pub_src.read_bytes()
            priv_data = priv_src.read_bytes()

            pub_dst.write_bytes(pub_data)
            priv_dst.write_bytes(priv_data)

            KeyStore.load_public_key(pub_dst, expected_username=self.username)

            QMessageBox.information(
                self,
                "Импорт завершён",
                f"Ключевые файлы успешно импортированы!\n\n"
                f"Файлы: {pub_dst.name}, {priv_dst.name}\n"
                f"Источник: {src}\n"
                f"Назначение: {dst}",
            )
            self.target_dir = str(dst)
            self.dir_input.setText(str(dst))
            self.accept()
        except PermissionError as p_err:
            QMessageBox.critical(
                self,
                "Ошибка доступа Windows (WinError 32)",
                f"Файл заблокирован операционной системой: {p_err}",
            )
        except KeyStoreError as exc:
            QMessageBox.critical(self, "Ошибка импорта", f"Ключи не прошли валидацию: {exc}")
        except Exception as exc:
            QMessageBox.critical(self, "Критическая ошибка", f"Не удалось импортировать ключи: {exc}")

    def _import_individual_files(self, dst: Path):
        """Ручной выбор отдельных файлов public.bkey и private.bkey с проверкой владельца."""
        prompt_pub = (
            f"Выберите файл открытого ключа ({self.username}_{KeyStore.PUBLIC_KEY_FILENAME})"
            if self.username
            else f"Выберите файл открытого ключа ({KeyStore.PUBLIC_KEY_FILENAME})"
        )
        pub_file, _ = QFileDialog.getOpenFileName(
            self,
            prompt_pub,
            str(dst),
            "Ключи bkey (*.bkey);;Все файлы (*.*)",
        )
        if not pub_file:
            return

        if not self._validate_key_ownership(pub_file):
            return

        prompt_priv = (
            f"Выберите файл закрытого (личного) ключа ({self.username}_{KeyStore.PRIVATE_KEY_FILENAME})"
            if self.username
            else f"Выберите файл закрытого (личного) ключа ({KeyStore.PRIVATE_KEY_FILENAME})"
        )
        priv_file, _ = QFileDialog.getOpenFileName(
            self,
            prompt_priv,
            str(Path(pub_file).parent),
            "Ключи bkey (*.bkey);;Все файлы (*.*)",
        )
        if not priv_file:
            return

        if not self._validate_key_ownership(priv_file):
            return

        try:
            pub_p = Path(pub_file).resolve()
            priv_p = Path(priv_file).resolve()

            dst.mkdir(parents=True, exist_ok=True)
            pub_dst_name = f"{self.username}_{KeyStore.PUBLIC_KEY_FILENAME}" if self.username else KeyStore.PUBLIC_KEY_FILENAME
            priv_dst_name = f"{self.username}_{KeyStore.PRIVATE_KEY_FILENAME}" if self.username else KeyStore.PRIVATE_KEY_FILENAME

            pub_dst = (dst / pub_dst_name).resolve()
            priv_dst = (dst / priv_dst_name).resolve()

            if pub_p != pub_dst:
                pub_dst.write_bytes(pub_p.read_bytes())
            if priv_p != priv_dst:
                priv_dst.write_bytes(priv_p.read_bytes())

            KeyStore.load_public_key(pub_dst, expected_username=self.username)

            QMessageBox.information(
                self,
                "Импорт завершён",
                f"Ключевые файлы успешно подключены в папку:\n{dst}",
            )
            self.target_dir = str(dst)
            self.dir_input.setText(str(dst))
            self.accept()
        except KeyStoreError as exc:
            QMessageBox.critical(self, "Ошибка импорта", f"Ключи не прошли валидацию: {exc}")
        except Exception as exc:
            QMessageBox.critical(self, "Ошибка импорта файлов", f"Не удалось импортировать: {exc}")
