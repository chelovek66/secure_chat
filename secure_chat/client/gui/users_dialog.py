"""
Диалоговое окно списка зарегистрированных участников сети «Secure Chat».
"""

from typing import Optional
from PyQt5.QtWidgets import (
    QDialog,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QPushButton,
    QMessageBox,
)
from PyQt5.QtCore import Qt

from ..network.api_client import ApiClient, ApiClientError


class UsersDialog(QDialog):
    """
    Диалог просмотра и выбора доступных участников для защищенной переписки.
    """

    def __init__(self, api_client: ApiClient, parent=None):
        super().__init__(parent)
        self.api = api_client
        self.selected_user: Optional[str] = None
        self.setWindowTitle("Пользователи в сети")
        self.resize(500, 420)
        self.setMinimumSize(440, 340)
        self.init_ui()
        self.refresh_users()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(10)

        title = QLabel("Список участников сети")
        title.setObjectName("titleLabel")
        layout.addWidget(title)

        desc = QLabel("Выберите пользователя для начала зашифрованного диалога (E2EE):")
        desc.setObjectName("subtitleLabel")
        layout.addWidget(desc)

        self.users_list = QListWidget(self)
        self.users_list.itemDoubleClicked.connect(self.select_user)
        layout.addWidget(self.users_list)

        btn_layout = QHBoxLayout()
        self.refresh_btn = QPushButton("Обновить", self)
        self.refresh_btn.setObjectName("secondaryButton")
        self.refresh_btn.clicked.connect(self.refresh_users)

        self.select_btn = QPushButton("Начать чат", self)
        self.select_btn.clicked.connect(self.select_user)

        btn_layout.addWidget(self.refresh_btn)
        btn_layout.addStretch()
        btn_layout.addWidget(self.select_btn)
        layout.addLayout(btn_layout)

    def refresh_users(self):
        self.users_list.clear()
        if not self.api.check_health(timeout=0.3):
            self.users_list.addItem("🔴 Сервер офлайн (127.0.0.1:8000)")
            self.users_list.item(0).setFlags(self.users_list.item(0).flags() & ~Qt.ItemIsEnabled)
            self.select_btn.setEnabled(False)
            return

        self.select_btn.setEnabled(True)
        try:
            users = self.api.get_users(silent=True)
            for u in users:
                uid = u["user_id"]
                # Исключаем текущего пользователя
                if uid != self.api.user_id:
                    self.users_list.addItem(uid)
            if self.users_list.count() == 0:
                self.users_list.addItem("(Других пользователей пока нет в сети)")
                self.users_list.item(0).setFlags(self.users_list.item(0).flags() & ~Qt.ItemIsEnabled)
        except ApiClientError as exc:
            self.users_list.addItem("(Не удалось получить список пользователей)")
            if self.users_list.count() > 0:
                self.users_list.item(0).setFlags(self.users_list.item(0).flags() & ~Qt.ItemIsEnabled)

    def select_user(self):
        current_item = self.users_list.currentItem()
        if not current_item or not (current_item.flags() & Qt.ItemIsEnabled):
            QMessageBox.information(self, "Выбор пользователя", "Пожалуйста, выберите доступного собеседника из списка.")
            return

        self.selected_user = current_item.text().strip()
        self.accept()
