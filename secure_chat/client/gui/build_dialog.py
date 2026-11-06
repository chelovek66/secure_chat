"""
Диалоговое окно сведений о версии и метаданных сборки ПО «Secure Chat».
Отображает системные параметры, версию релиза, состояние криптоядра Bee2 и государственные стандарты СТБ.
"""

from PyQt5.QtWidgets import (
    QDialog,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QMessageBox,
    QApplication,
)
from PyQt5.QtCore import Qt

from common.build_info import get_build_info, format_build_summary, format_display_date, BuildInfo


class BuildDialog(QDialog):
    """
    Информационное окно метаданных сборки и спецификаций криптографической защиты.
    """

    def __init__(self, parent=None, server_build_info: dict = None):
        super().__init__(parent)
        self.setWindowTitle("О программе — Метаданные сборки")
        self.resize(740, 520)
        self.setMinimumSize(680, 460)
        self.local_info: BuildInfo = get_build_info()
        self.server_info: dict = server_build_info or {}
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(12)

        title = QLabel("Программный комплекс «Secure Chat»")
        title.setObjectName("titleLabel")
        layout.addWidget(title)

        subtitle = QLabel(f"Релизная версия: 2.1.0 (Build #{self.local_info.build_number})")
        subtitle.setObjectName("subtitleLabel")
        layout.addWidget(subtitle)

        # Таблица параметров сборки
        self.table = QTableWidget(self)
        self.table.setColumnCount(2)
        self.table.setHorizontalHeaderLabels(["Параметр сборки", "Значение"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.table.verticalHeader().setVisible(False)
        self.table.setAlternatingRowColors(True)
        layout.addWidget(self.table)

        # Заполнение таблицы
        items = [
            ("Наименование ПО", self.local_info.app_name),
            ("Версия ПО", self.local_info.version),
            ("Номер сборки", str(self.local_info.build_number)),
            ("Дата официального релиза", format_display_date(self.local_info.build_date)),
            ("Криптографическое ядро", self.local_info.crypto_engine),
        ]

        if self.server_info:
            srv_ver = self.server_info.get("version", "-")
            srv_build = self.server_info.get("build_number", "-")
            srv_engine = self.server_info.get("crypto_engine", "-")
            srv_date = self.server_info.get("build_date")
            items.append(("Версия сервера REST API", f"{srv_ver} (build #{srv_build})"))
            if srv_date:
                items.append(("Дата релиза сервера", format_display_date(srv_date)))
            items.append(("Криптоядро сервера", str(srv_engine)))

        self.table.setRowCount(len(items))
        for row, (k, v) in enumerate(items):
            item_k = QTableWidgetItem(k)
            item_k.setFlags(item_k.flags() & ~Qt.ItemIsEditable)
            item_v = QTableWidgetItem(str(v))
            item_v.setFlags(item_v.flags() & ~Qt.ItemIsEditable)
            self.table.setItem(row, 0, item_k)
            self.table.setItem(row, 1, item_v)

        # Кнопки
        btn_h = QHBoxLayout()
        self.copy_btn = QPushButton("Копировать в буфер обмена", self)
        self.copy_btn.setObjectName("secondaryButton")
        self.copy_btn.setMinimumHeight(36)
        self.copy_btn.clicked.connect(self.copy_to_clipboard)
        btn_h.addWidget(self.copy_btn)

        self.update_ver_btn = QPushButton("🔄 Обновить версию", self)
        self.update_ver_btn.setObjectName("secondaryButton")
        self.update_ver_btn.setMinimumHeight(36)
        self.update_ver_btn.clicked.connect(self.on_check_update_clicked)
        btn_h.addWidget(self.update_ver_btn)

        btn_h.addStretch()

        self.close_btn = QPushButton("Закрыть", self)
        self.close_btn.setObjectName("secondaryButton")
        self.close_btn.setMinimumHeight(36)
        self.close_btn.clicked.connect(self.accept)
        btn_h.addWidget(self.close_btn)

        layout.addLayout(btn_h)

    def on_check_update_clicked(self):
        """Заглушка кнопки обновления версии."""
        pass

    def copy_to_clipboard(self):
        summary = format_build_summary()
        clipboard = QApplication.clipboard()
        clipboard.setText(summary)
        QMessageBox.information(self, "Буфер обмена", "Сведения о сборке скопированы в буфер обмена!")
