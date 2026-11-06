"""
Диалоговое окно управления конфигурацией клиентского приложения «Secure Chat».
Позволяет просматривать, редактировать, сохранять, сбрасывать, экспортировать и импортировать настройки.
"""

from pathlib import Path
from PyQt5.QtWidgets import (
    QDialog,
    QVBoxLayout,
    QHBoxLayout,
    QGridLayout,
    QLabel,
    QLineEdit,
    QDoubleSpinBox,
    QCheckBox,
    QComboBox,
    QPushButton,
    QFileDialog,
    QMessageBox,
    QGroupBox,
)
from PyQt5.QtCore import Qt

from common.config_manager import ConfigManager, ClientConfig, ConfigError


class ConfigDialog(QDialog):
    """
    Интерактивное окно настройки параметров приложения «Secure Chat».
    """

    def __init__(self, parent=None, config_manager: ConfigManager = None):
        super().__init__(parent)
        self.setWindowTitle("Управление конфигурацией")
        self.resize(720, 680)
        self.setMinimumSize(660, 600)
        self.cfg_mgr = config_manager or ConfigManager()
        self.config = self.cfg_mgr.config
        self.init_ui()
        self.load_values_to_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(10)

        title = QLabel("Параметры и управление конфигурацией")
        title.setObjectName("titleLabel")
        layout.addWidget(title)

        desc = QLabel("Настройка сетевого подключения, каталогов ключей и параметров безопасности.")
        desc.setObjectName("subtitleLabel")
        layout.addWidget(desc)

        # Группа 1: Сетевые настройки
        net_group = QGroupBox("Параметры сетевого подключения", self)
        net_layout = QGridLayout(net_group)
        net_layout.setContentsMargins(14, 16, 14, 12)
        net_layout.setHorizontalSpacing(12)
        net_layout.setVerticalSpacing(8)

        net_layout.addWidget(QLabel("URL REST API сервера:"), 0, 0)
        self.url_input = QLineEdit(self)
        self.url_input.setMinimumHeight(34)
        net_layout.addWidget(self.url_input, 0, 1)

        net_layout.addWidget(QLabel("Период опроса (сек):"), 1, 0)
        self.poll_spin = QDoubleSpinBox(self)
        self.poll_spin.setRange(0.2, 60.0)
        self.poll_spin.setSingleStep(0.5)
        self.poll_spin.setMinimumHeight(32)
        net_layout.addWidget(self.poll_spin, 1, 1)

        net_layout.addWidget(QLabel("Сетевой таймаут (сек):"), 2, 0)
        self.timeout_spin = QDoubleSpinBox(self)
        self.timeout_spin.setRange(1.0, 120.0)
        self.timeout_spin.setSingleStep(1.0)
        self.timeout_spin.setMinimumHeight(32)
        net_layout.addWidget(self.timeout_spin, 2, 1)

        layout.addWidget(net_group)

        # Группа 2: Безопасность и хранение ключей
        sec_group = QGroupBox("Безопасность и криптографические ключи", self)
        sec_layout = QGridLayout(sec_group)
        sec_layout.setContentsMargins(14, 16, 14, 12)
        sec_layout.setHorizontalSpacing(12)
        sec_layout.setVerticalSpacing(8)

        sec_layout.addWidget(QLabel("Каталог ключей:"), 0, 0)
        dir_h = QHBoxLayout()
        self.keys_dir_input = QLineEdit(self)
        self.keys_dir_input.setMinimumHeight(34)
        self.browse_btn = QPushButton("Обзор...", self)
        self.browse_btn.setObjectName("secondaryButton")
        self.browse_btn.setMinimumHeight(34)
        self.browse_btn.clicked.connect(self.browse_keys_dir)
        dir_h.addWidget(self.keys_dir_input)
        dir_h.addWidget(self.browse_btn)
        sec_layout.addLayout(dir_h, 0, 1)

        self.integrity_cb = QCheckBox("Выполнять контроль целостности ПО при старте", self)
        sec_layout.addWidget(self.integrity_cb, 1, 0, 1, 2)

        self.reconnect_cb = QCheckBox("Автоматическое переподключение при сбоях сети", self)
        sec_layout.addWidget(self.reconnect_cb, 2, 0, 1, 2)

        layout.addWidget(sec_group)

        # Группа 3: Интерфейс и системный журнал
        ui_group = QGroupBox("Интерфейс и системный журнал", self)
        ui_layout = QGridLayout(ui_group)
        ui_layout.setContentsMargins(14, 16, 14, 12)
        ui_layout.setHorizontalSpacing(12)
        ui_layout.setVerticalSpacing(8)

        ui_layout.addWidget(QLabel("Тема оформления:"), 0, 0)
        self.theme_combo = QComboBox(self)
        self.theme_combo.addItems(["dark", "light"])
        self.theme_combo.setMinimumHeight(32)
        ui_layout.addWidget(self.theme_combo, 0, 1)

        ui_layout.addWidget(QLabel("Уровень логирования:"), 1, 0)
        self.log_combo = QComboBox(self)
        self.log_combo.addItems(["DEBUG", "INFO", "WARNING", "ERROR"])
        self.log_combo.setMinimumHeight(32)
        ui_layout.addWidget(self.log_combo, 1, 1)

        layout.addWidget(ui_group)

        # Кнопки импорта / экспорта
        import_export_h = QHBoxLayout()
        self.export_btn = QPushButton("Экспорт в JSON...", self)
        self.export_btn.setObjectName("secondaryButton")
        self.export_btn.setMinimumHeight(36)
        self.export_btn.clicked.connect(self.export_config)
        import_export_h.addWidget(self.export_btn)

        self.import_btn = QPushButton("Импорт из JSON...", self)
        self.import_btn.setObjectName("secondaryButton")
        self.import_btn.setMinimumHeight(36)
        self.import_btn.clicked.connect(self.import_config)
        import_export_h.addWidget(self.import_btn)

        self.reset_btn = QPushButton("Сброс по умолчанию", self)
        self.reset_btn.setObjectName("secondaryButton")
        self.reset_btn.setMinimumHeight(36)
        self.reset_btn.clicked.connect(self.reset_defaults)
        import_export_h.addWidget(self.reset_btn)

        import_export_h.addStretch()
        layout.addLayout(import_export_h)

        # Нижние кнопки
        bottom_h = QHBoxLayout()
        bottom_h.addStretch()

        self.cancel_btn = QPushButton("Отмена", self)
        self.cancel_btn.setObjectName("secondaryButton")
        self.cancel_btn.setMinimumHeight(40)
        self.cancel_btn.setMinimumWidth(100)
        self.cancel_btn.clicked.connect(self.reject)
        bottom_h.addWidget(self.cancel_btn)

        self.save_btn = QPushButton("Применить и сохранить", self)
        self.save_btn.setObjectName("successButton")
        self.save_btn.setMinimumHeight(40)
        self.save_btn.setMinimumWidth(180)
        self.save_btn.clicked.connect(self.save_config)
        bottom_h.addWidget(self.save_btn)

        layout.addLayout(bottom_h)

    def load_values_to_ui(self):
        """Заполняет виджеты значениями текущей конфигурации."""
        cfg = self.config
        self.url_input.setText(cfg.server_url)
        self.poll_spin.setValue(cfg.poll_interval_sec)
        self.timeout_spin.setValue(cfg.request_timeout_sec)
        self.keys_dir_input.setText(cfg.keys_dir)
        self.integrity_cb.setChecked(cfg.verify_integrity_on_startup)
        self.reconnect_cb.setChecked(cfg.auto_reconnect)

        idx_theme = self.theme_combo.findText(cfg.theme)
        if idx_theme >= 0:
            self.theme_combo.setCurrentIndex(idx_theme)

        idx_log = self.log_combo.findText(cfg.log_level)
        if idx_log >= 0:
            self.log_combo.setCurrentIndex(idx_log)

    def browse_keys_dir(self):
        chosen = QFileDialog.getExistingDirectory(self, "Выберите папку для ключей", self.keys_dir_input.text())
        if chosen:
            self.keys_dir_input.setText(chosen)

    def save_config(self):
        try:
            updated = ClientConfig(
                server_url=self.url_input.text().strip(),
                poll_interval_sec=self.poll_spin.value(),
                request_timeout_sec=self.timeout_spin.value(),
                keys_dir=self.keys_dir_input.text().strip(),
                theme=self.theme_combo.currentText(),
                log_level=self.log_combo.currentText(),
                verify_integrity_on_startup=self.integrity_cb.isChecked(),
                auto_reconnect=self.reconnect_cb.isChecked(),
            )
            self.cfg_mgr.save_config(updated)
            self.config = updated
            QMessageBox.information(self, "Конфигурация", "Настройки успешно сохранены в config.json!")
            self.accept()
        except Exception as exc:
            QMessageBox.critical(self, "Ошибка валидации", f"Недопустимые параметры: {exc}")

    def reset_defaults(self):
        reply = QMessageBox.question(
            self,
            "Подтверждение",
            "Сбросить все параметры конфигурации к заводским значениям?",
            QMessageBox.Yes | QMessageBox.No,
        )
        if reply == QMessageBox.Yes:
            self.config = self.cfg_mgr.reset_defaults()
            self.load_values_to_ui()
            QMessageBox.information(self, "Сброс", "Параметры сброшены по умолчанию.")

    def export_config(self):
        path, _ = QFileDialog.getSaveFileName(self, "Экспорт конфигурации в JSON", "config_export.json", "JSON (*.json)")
        if path:
            try:
                self.cfg_mgr.export_config(path)
                QMessageBox.information(self, "Экспорт", f"Конфигурация успешно экспортирована в:\n{path}")
            except Exception as exc:
                QMessageBox.critical(self, "Ошибка экспорта", str(exc))

    def import_config(self):
        path, _ = QFileDialog.getOpenFileName(self, "Импорт конфигурации из JSON", "", "JSON (*.json)")
        if path:
            try:
                self.config = self.cfg_mgr.import_config(path)
                self.load_values_to_ui()
                QMessageBox.information(self, "Импорт", f"Конфигурация успешно импортирована из:\n{path}")
            except Exception as exc:
                QMessageBox.critical(self, "Ошибка импорта", f"Не удалось импортировать конфигурацию:\n{exc}")
