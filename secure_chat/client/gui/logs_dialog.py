"""
Диалоговое окно централизованного просмотра журналов событий и аудита безопасности.
Отображает:
  * Вкладку 1: Логи работы клиента и криптографических операций в реальном времени (E2EE / СТБ 34.101);
  * Вкладку 2: Серверный журнал аудита безопасности (Security Audit Log);
  * Фильтрацию по уровням важности (INFO, WARN, ERROR, DEBUG) и поисковым подстрокам;
  * Функции экспорта в форматы CSV и TXT, очистки и автопрокрутки.
"""

from typing import List, Optional
from pathlib import Path

from PyQt5.QtWidgets import (
    QDialog,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QTabWidget,
    QWidget,
    QLineEdit,
    QComboBox,
    QCheckBox,
    QMessageBox,
    QFileDialog,
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor, QFont

from common.logger import LogEntry, log_service
from ..network.api_client import ApiClient


class LogsDialog(QDialog):
    """
    Интерактивная панель мониторинга системных журналов и аудита.
    """

    COLOR_MAP = {
        "DEBUG": QColor("#94A3B8"),     # Серый
        "INFO": QColor("#38BDF8"),      # Небесно-голубой
        "WARNING": QColor("#FBBF24"),   # Золотистый / Янтарный
        "ERROR": QColor("#F87171"),     # Кораллово-красный
        "CRITICAL": QColor("#EF4444"),  # Ярко-красный
    }

    def __init__(self, api_client: Optional[ApiClient] = None, parent=None):
        super().__init__(parent)
        self.api = api_client
        self.setWindowTitle("Журнал событий и аудит безопасности — Secure Chat")
        self.resize(1080, 640)
        self.setMinimumSize(980, 560)

        self._cached_entries: List[LogEntry] = []
        self._cached_audit: List[dict] = []

        self.init_ui()

        # Подключаем реактивное получение логов в реальном времени
        log_service.entry_added.connect(self._on_new_log_entry)

        # Первичная загрузка локальных логов клиента
        self.refresh_client_logs()

        # Отложенная загрузка серверного аудита только при выборе соответствующей вкладки
        self.tabs.currentChanged.connect(self._on_tab_changed)

    def _on_tab_changed(self, index: int):
        """Ленивая загрузка журнала аудита сервера при переходе на Вкладку 2."""
        if index == 1 and not self._cached_audit and self.api:
            self.refresh_server_audit()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.setContentsMargins(18, 16, 18, 16)

        # Заголовок
        header_h = QHBoxLayout()
        v_title = QVBoxLayout()
        title = QLabel("Системный журнал событий и аудит безопасности")
        title.setObjectName("titleLabel")
        v_title.addWidget(title)

        subtitle = QLabel("Мониторинг криптографии СТБ 34.101, сетевых обменов E2EE и базы данных")
        subtitle.setObjectName("subtitleLabel")
        v_title.addWidget(subtitle)
        header_h.addLayout(v_title)

        header_h.addStretch()

        self.refresh_all_btn = QPushButton("🔄 Обновить всё", self)
        self.refresh_all_btn.setObjectName("secondaryButton")
        self.refresh_all_btn.clicked.connect(self.refresh_both)
        header_h.addWidget(self.refresh_all_btn)
        layout.addLayout(header_h)

        # Вкладки
        self.tabs = QTabWidget(self)

        # ======================================================================
        # ВКЛАДКА 1: Логи клиента и криптографии в реальном времени
        # ======================================================================
        tab_client = QWidget()
        v_client = QVBoxLayout(tab_client)
        v_client.setSpacing(8)

        # Панель фильтров
        filter_box = QHBoxLayout()
        filter_box.addWidget(QLabel("Уровень:"))
        self.level_combo = QComboBox(self)
        self.level_combo.addItems([
            "Все уровни",
            "INFO",
            "WARNING",
            "ERROR",
            "DEBUG",
            "Только КРИПТО",
        ])
        self.level_combo.currentIndexChanged.connect(self.apply_client_filter)
        filter_box.addWidget(self.level_combo)

        filter_box.addWidget(QLabel("Поиск:"))
        self.search_input = QLineEdit(self)
        self.search_input.setPlaceholderText("Фильтр по сообщению или модулю...")
        self.search_input.textChanged.connect(self.apply_client_filter)
        filter_box.addWidget(self.search_input)

        self.autoscroll_check = QCheckBox("Автопрокрутка", self)
        self.autoscroll_check.setChecked(True)
        filter_box.addWidget(self.autoscroll_check)

        filter_box.addStretch()

        self.stats_lbl = QLabel("Всего: 0 | Ошибок: 0")
        self.stats_lbl.setStyleSheet("color: #94A3B8; font-size: 11px;")
        filter_box.addWidget(self.stats_lbl)
        v_client.addLayout(filter_box)

        # Таблица логов клиента
        self.logs_table = QTableWidget(self)
        self.logs_table.setColumnCount(4)
        self.logs_table.setHorizontalHeaderLabels([
            "Время",
            "Уровень",
            "Источник",
            "Событие / Детализация",
        ])
        self.logs_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.logs_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.logs_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.logs_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.logs_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.logs_table.setAlternatingRowColors(True)
        self.logs_table.verticalHeader().setVisible(False)
        v_client.addWidget(self.logs_table)

        # Панель действий вкладки 1
        client_actions = QHBoxLayout()
        self.export_csv_btn = QPushButton("💾 Экспорт в CSV...", self)
        self.export_csv_btn.setObjectName("secondaryButton")
        self.export_csv_btn.clicked.connect(self.export_client_csv)
        client_actions.addWidget(self.export_csv_btn)

        self.export_txt_btn = QPushButton("📄 Экспорт в TXT...", self)
        self.export_txt_btn.setObjectName("secondaryButton")
        self.export_txt_btn.clicked.connect(self.export_client_txt)
        client_actions.addWidget(self.export_txt_btn)

        self.clear_btn = QPushButton("🧹 Очистить журнал", self)
        self.clear_btn.setObjectName("secondaryButton")
        self.clear_btn.clicked.connect(self.clear_client_logs)
        client_actions.addWidget(self.clear_btn)

        client_actions.addStretch()
        v_client.addLayout(client_actions)
        self.tabs.addTab(tab_client, "Логи приложения и криптографии (Client Runtime)")

        # ======================================================================
        # ВКЛАДКА 2: Серверный журнал аудита безопасности
        # ======================================================================
        tab_audit = QWidget()
        v_audit = QVBoxLayout(tab_audit)
        v_audit.setSpacing(8)

        # Панель фильтра аудита
        audit_filter_box = QHBoxLayout()
        audit_filter_box.addWidget(QLabel("Фильтр по пользователю:"))
        self.audit_user_input = QLineEdit(self)
        self.audit_user_input.setPlaceholderText("Логин абонента (пусто — все)...")
        self.audit_user_input.returnPressed.connect(self.refresh_server_audit)
        audit_filter_box.addWidget(self.audit_user_input)

        self.audit_fetch_btn = QPushButton("Загрузить с сервера", self)
        self.audit_fetch_btn.setObjectName("secondaryButton")
        self.audit_fetch_btn.clicked.connect(self.refresh_server_audit)
        audit_filter_box.addWidget(self.audit_fetch_btn)

        audit_filter_box.addStretch()

        self.audit_stats_lbl = QLabel("Статус аудита: готов к запросу")
        self.audit_stats_lbl.setStyleSheet("color: #94A3B8; font-size: 11px;")
        audit_filter_box.addWidget(self.audit_stats_lbl)
        v_audit.addLayout(audit_filter_box)

        # Таблица аудита
        self.audit_table = QTableWidget(self)
        self.audit_table.setColumnCount(5)
        self.audit_table.setHorizontalHeaderLabels([
            "ID",
            "Временная метка (UTC)",
            "Тип события",
            "Пользователь",
            "Детализация безопасности",
        ])
        self.audit_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.audit_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.audit_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.audit_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.audit_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.audit_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.audit_table.setAlternatingRowColors(True)
        self.audit_table.verticalHeader().setVisible(False)
        v_audit.addWidget(self.audit_table)

        # Панель действий вкладки 2
        audit_actions = QHBoxLayout()
        self.audit_export_btn = QPushButton("💾 Экспорт аудита в CSV...", self)
        self.audit_export_btn.setObjectName("secondaryButton")
        self.audit_export_btn.clicked.connect(self.export_audit_csv)
        audit_actions.addWidget(self.audit_export_btn)

        audit_actions.addStretch()
        v_audit.addLayout(audit_actions)
        self.tabs.addTab(tab_audit, "Журнал аудита сервера (Server Audit Log)")

        layout.addWidget(self.tabs)

        # Нижняя панель
        bottom_h = QHBoxLayout()
        bottom_h.addStretch()
        self.close_btn = QPushButton("Закрыть", self)
        self.close_btn.setObjectName("secondaryButton")
        self.close_btn.clicked.connect(self.accept)
        bottom_h.addWidget(self.close_btn)
        layout.addLayout(bottom_h)

    # =========================================================================
    # ЛОГИКА ВКЛАДКИ 1: Логи клиента
    # =========================================================================
    def refresh_client_logs(self):
        """Перечитывает все логи из сервиса LogService."""
        self._cached_entries = log_service.get_entries()
        self.apply_client_filter()

    def _on_new_log_entry(self, entry: LogEntry):
        """Реактивный обработчик нового лога: добавляет строку в таблицу."""
        self._cached_entries.append(entry)
        if self._matches_filter(entry):
            self._append_table_row(entry)
            self._update_stats_label()
            if self.autoscroll_check.isChecked():
                self.logs_table.scrollToBottom()

    def _matches_filter(self, e: LogEntry) -> bool:
        selected_level = self.level_combo.currentText()
        if selected_level == "Только КРИПТО":
            if "crypto" not in e.source.lower() and "belt" not in e.message.lower() and "bign" not in e.message.lower():
                return False
        elif selected_level != "Все уровни":
            if e.level != selected_level:
                return False

        search_txt = self.search_input.text().strip().lower()
        if search_txt:
            if search_txt not in e.message.lower() and search_txt not in e.source.lower():
                return False

        return True

    def apply_client_filter(self):
        """Фильтрует и перерисовывает таблицу клиентских логов."""
        self.logs_table.setRowCount(0)
        filtered = [e for e in self._cached_entries if self._matches_filter(e)]

        self.logs_table.setSortingEnabled(False)
        for e in filtered:
            self._append_table_row(e)
        self.logs_table.setSortingEnabled(True)

        self._update_stats_label()
        if self.autoscroll_check.isChecked():
            self.logs_table.scrollToBottom()

    def _append_table_row(self, e: LogEntry):
        row = self.logs_table.rowCount()
        self.logs_table.insertRow(row)

        # Время
        item_time = QTableWidgetItem(e.timestamp)
        item_time.setTextAlignment(Qt.AlignCenter)
        item_time.setForeground(QColor("#94A3B8"))

        # Уровень с цветовым акцентом
        item_level = QTableWidgetItem(f"[{e.level}]")
        item_level.setTextAlignment(Qt.AlignCenter)
        level_color = self.COLOR_MAP.get(e.level, QColor("#FFFFFF"))
        item_level.setForeground(level_color)
        font = item_level.font()
        font.setBold(True)
        item_level.setFont(font)

        # Источник
        clean_source = e.source.replace("secure_chat.", "")
        item_source = QTableWidgetItem(clean_source)
        if "crypto" in clean_source:
            item_source.setForeground(QColor("#A78BFA"))  # Фиолетовый
        elif "network" in clean_source or "api" in clean_source:
            item_source.setForeground(QColor("#34D399"))  # Изумрудный
        else:
            item_source.setForeground(QColor("#CBD5E1"))

        # Сообщение
        item_msg = QTableWidgetItem(e.message)
        if e.level in ("ERROR", "CRITICAL"):
            item_msg.setForeground(QColor("#FCA5A5"))
        elif e.level == "WARNING":
            item_msg.setForeground(QColor("#FDE68A"))
        elif "belt" in e.message.lower() or "bign" in e.message.lower():
            item_msg.setForeground(QColor("#E0E7FF"))
        else:
            item_msg.setForeground(QColor("#F8FAFC"))

        self.logs_table.setItem(row, 0, item_time)
        self.logs_table.setItem(row, 1, item_level)
        self.logs_table.setItem(row, 2, item_source)
        self.logs_table.setItem(row, 3, item_msg)

    def _update_stats_label(self):
        stats = log_service.get_stats()
        errors = stats.get("ERROR", 0) + stats.get("CRITICAL", 0)
        warns = stats.get("WARNING", 0)
        self.stats_lbl.setText(
            f"Всего: {stats.get('total', 0)} | Ошибок: {errors} | Предупреждений: {warns}"
        )

    def clear_client_logs(self):
        reply = QMessageBox.question(
            self,
            "Подтверждение",
            "Очистить текущий журнал событий в памяти?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if reply == QMessageBox.Yes:
            log_service.clear()
            self._cached_entries.clear()
            self.logs_table.setRowCount(0)
            self._update_stats_label()

    def closeEvent(self, event):
        """Отключает сигнал глобального логгера для предотвращения утечки ресурсов."""
        try:
            log_service.entry_added.disconnect(self._on_new_log_entry)
        except Exception:
            pass
        event.accept()

    def export_client_csv(self):
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Экспорт журнала в CSV",
            str(Path.cwd() / "logs.csv"),
            "CSV файлы (*.csv);;Все файлы (*.*)",
        )
        if path:
            try:
                import csv
                filtered = [e for e in self._cached_entries if self._matches_filter(e)]
                with open(path, "w", encoding="utf-8-sig", newline="") as f:
                    writer = csv.writer(f, delimiter=";")
                    writer.writerow(["Временная метка", "Уровень", "Источник", "Сообщение"])
                    for e in filtered:
                        writer.writerow([e.timestamp, e.level, e.source, e.message])
                QMessageBox.information(
                    self,
                    "Экспорт завершен",
                    f"Успешно экспортировано записей (с учетом фильтра): {len(filtered)}\nФайл: {path}",
                )
            except Exception as exc:
                QMessageBox.critical(self, "Ошибка экспорта", f"Не удалось сохранить CSV: {exc}")

    def export_client_txt(self):
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Экспорт журнала в TXT",
            str(Path.cwd() / "logs.txt"),
            "Текстовые файлы (*.txt *.log);;Все файлы (*.*)",
        )
        if path:
            try:
                filtered = [e for e in self._cached_entries if self._matches_filter(e)]
                with open(path, "w", encoding="utf-8") as f:
                    for e in filtered:
                        f.write(f"[{e.timestamp}] [{e.level:5s}] [{e.source}] {e.message}\n")
                QMessageBox.information(
                    self,
                    "Экспорт завершен",
                    f"Успешно экспортировано записей (с учетом фильтра): {len(filtered)}\nФайл: {path}",
                )
            except Exception as exc:
                QMessageBox.critical(self, "Ошибка экспорта", f"Не удалось сохранить TXT: {exc}")

    # =========================================================================
    # ЛОГИКА ВКЛАДКИ 2: Аудит сервера
    # =========================================================================
    def refresh_server_audit(self):
        if not self.api:
            self.audit_stats_lbl.setText("Сетевой клиент не настроен")
            return

        user_filter = self.audit_user_input.text().strip() or None
        try:
            if hasattr(self.api, "get_db_audit_logs"):
                logs = self.api.get_db_audit_logs(limit=200, user_id=user_filter, silent=True)
            else:
                logs = self.api.get_audit_logs(limit=200, user_id=user_filter)
            self._cached_audit = logs
            self.populate_audit_table(logs)
            self.audit_stats_lbl.setText(f"Записей аудита: {len(logs)} (источник: REST API)")
        except Exception:
            self.audit_stats_lbl.setText("Сервер офлайн (127.0.0.1:8000). Запустите сервер для загрузки аудита.")
            self.populate_audit_table([])

    def populate_audit_table(self, logs: List[dict]):
        self.audit_table.setRowCount(0)
        self.audit_table.setSortingEnabled(False)

        for row, item in enumerate(logs):
            self.audit_table.insertRow(row)

            item_id = QTableWidgetItem(str(item.get("id", "")))
            item_id.setTextAlignment(Qt.AlignCenter)
            self.audit_table.setItem(row, 0, item_id)

            t_val = str(item.get("timestamp", ""))
            if "T" in t_val:
                t_val = t_val.replace("T", " ")[:19]
            item_time = QTableWidgetItem(t_val)
            item_time.setTextAlignment(Qt.AlignCenter)
            item_time.setForeground(QColor("#94A3B8"))
            self.audit_table.setItem(row, 1, item_time)

            evt = str(item.get("event_type", ""))
            item_evt = QTableWidgetItem(evt)
            item_evt.setTextAlignment(Qt.AlignCenter)
            if "FAIL" in evt or "ATTACK" in evt or "TAMPER" in evt:
                item_evt.setForeground(QColor("#EF4444"))
            elif "REGISTER" in evt or "LOGIN" in evt:
                item_evt.setForeground(QColor("#10B981"))
            else:
                item_evt.setForeground(QColor("#38BDF8"))
            font = item_evt.font()
            font.setBold(True)
            item_evt.setFont(font)
            self.audit_table.setItem(row, 2, item_evt)

            item_user = QTableWidgetItem(str(item.get("user_id", "") or "-"))
            item_user.setTextAlignment(Qt.AlignCenter)
            item_user.setForeground(QColor("#60A5FA"))
            self.audit_table.setItem(row, 3, item_user)

            item_details = QTableWidgetItem(str(item.get("details", "")))
            self.audit_table.setItem(row, 4, item_details)

        self.audit_table.setSortingEnabled(True)

    def export_audit_csv(self):
        if not self._cached_audit:
            QMessageBox.information(self, "Экспорт", "Журнал аудита пуст.")
            return

        path, _ = QFileDialog.getSaveFileName(
            self,
            "Экспорт аудита в CSV",
            str(Path.cwd() / "server_audit.csv"),
            "CSV файлы (*.csv);;Все файлы (*.*)",
        )
        if path:
            import csv
            try:
                with open(path, "w", encoding="utf-8-sig", newline="") as f:
                    writer = csv.writer(f, delimiter=";")
                    writer.writerow(["ID", "Timestamp", "EventType", "UserID", "Details"])
                    for row in self._cached_audit:
                        writer.writerow([
                            row.get("id"),
                            row.get("timestamp"),
                            row.get("event_type"),
                            row.get("user_id"),
                            row.get("details"),
                        ])
                QMessageBox.information(
                    self,
                    "Экспорт завершен",
                    f"Успешно экспортировано {len(self._cached_audit)} записей аудита.",
                )
            except Exception as exc:
                QMessageBox.critical(self, "Ошибка экспорта", f"Сбой при сохранении CSV: {exc}")

    def refresh_both(self):
        self.refresh_client_logs()
        if self.api:
            self.refresh_server_audit()
