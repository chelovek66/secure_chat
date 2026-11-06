"""
Диалоговое окно администрирования и управления базой данных пользователей и ключей.
Отображает:
  * Зарегистрированных абонентов и их открытые ключи bign (СТБ 34.101.45-2013);
  * Даты подключения, последний вход, IP-адреса и статусы;
  * Журнал аудита событий безопасности;
  * Функции экспорта данных в JSON и CSV.
"""

from typing import Optional
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
    QMessageBox,
    QFileDialog,
    QInputDialog,
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor

from ..network.api_client import ApiClient, ApiClientError


class DatabaseDialog(QDialog):
    """
    Панель управления базой данных абонентов и криптографических открытых ключей.
    """

    def __init__(self, api_client: ApiClient, parent=None):
        super().__init__(parent)
        self.api = api_client
        self.setWindowTitle("Управление базой данных — Абоненты и открытые ключи bign")
        self.resize(1040, 620)
        self.setMinimumSize(940, 540)
        self.init_ui()
        self.refresh_all_data()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(10)

        # Заголовок
        header_h = QHBoxLayout()
        v_title = QVBoxLayout()
        title = QLabel("Реестр абонентов и криптографических открытых ключей")
        title.setObjectName("titleLabel")
        v_title.addWidget(title)

        self.stats_lbl = QLabel("Загрузка статистики БД...")
        self.stats_lbl.setObjectName("subtitleLabel")
        v_title.addWidget(self.stats_lbl)
        header_h.addLayout(v_title)

        header_h.addStretch()

        self.refresh_btn = QPushButton("Обновить данные", self)
        self.refresh_btn.setObjectName("secondaryButton")
        self.refresh_btn.clicked.connect(self.refresh_all_data)
        header_h.addWidget(self.refresh_btn)
        layout.addLayout(header_h)

        # Панель управления состоянием базы данных (Включена / Выключена)
        db_control_frame = QHBoxLayout()
        self.db_status_badge = QLabel("Статус БД: Определение...", self)
        self.db_status_badge.setStyleSheet(
            "padding: 6px 12px; border-radius: 6px; font-weight: bold; font-size: 12px;"
        )
        db_control_frame.addWidget(self.db_status_badge)

        self.db_desc_lbl = QLabel(
            "Включенная БД сохраняет открытые ключи пользователей персистентно в SQLite.", self
        )
        self.db_desc_lbl.setStyleSheet("color: #94A3B8; font-size: 11px;")
        db_control_frame.addWidget(self.db_desc_lbl)
        db_control_frame.addStretch()

        self.db_toggle_btn = QPushButton("Переключить режим БД", self)
        self.db_toggle_btn.setObjectName("secondaryButton")
        self.db_toggle_btn.clicked.connect(self.toggle_db_mode)
        db_control_frame.addWidget(self.db_toggle_btn)
        layout.addLayout(db_control_frame)

        # Вкладки: 1) Пользователи и ключи; 2) Журнал аудита
        self.tabs = QTabWidget(self)

        # --- ВКЛАДКА 1: Пользователи и ключи ---
        tab_users = QWidget()
        v_users = QVBoxLayout(tab_users)

        # Фильтр поиска
        filter_h = QHBoxLayout()
        filter_h.addWidget(QLabel("Поиск по логину / ключу:"))
        self.search_input = QLineEdit(self)
        self.search_input.setPlaceholderText("Фильтрация списка...")
        self.search_input.textChanged.connect(self.filter_users_table)
        filter_h.addWidget(self.search_input)
        v_users.addLayout(filter_h)

        # Таблица пользователей
        self.users_table = QTableWidget(self)
        self.users_table.setColumnCount(6)
        self.users_table.setHorizontalHeaderLabels([
            "User ID",
            "Открытый ключ bign (64 байта / hex)",
            "Статус",
            "Дата регистрации",
            "Посл. активность",
            "IP-адрес",
        ])
        self.users_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.users_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.users_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.users_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.users_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.users_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeToContents)
        self.users_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.users_table.setSelectionMode(QTableWidget.SingleSelection)
        self.users_table.setAlternatingRowColors(True)
        self.users_table.verticalHeader().setVisible(False)
        v_users.addWidget(self.users_table)

        # Панель действий над пользователем
        users_btn_h = QHBoxLayout()
        self.toggle_status_btn = QPushButton("Сменить статус (Active/Blocked)", self)
        self.toggle_status_btn.setObjectName("secondaryButton")
        self.toggle_status_btn.clicked.connect(self.toggle_user_status)
        users_btn_h.addWidget(self.toggle_status_btn)

        self.delete_user_btn = QPushButton("Удалить запись", self)
        self.delete_user_btn.setObjectName("secondaryButton")
        self.delete_user_btn.clicked.connect(self.delete_user)
        users_btn_h.addWidget(self.delete_user_btn)

        users_btn_h.addStretch()

        self.export_csv_btn = QPushButton("Экспорт в CSV...", self)
        self.export_csv_btn.setObjectName("secondaryButton")
        self.export_csv_btn.clicked.connect(self.export_csv)
        users_btn_h.addWidget(self.export_csv_btn)

        self.export_json_btn = QPushButton("Экспорт в JSON...", self)
        self.export_json_btn.setObjectName("secondaryButton")
        self.export_json_btn.clicked.connect(self.export_json)
        users_btn_h.addWidget(self.export_json_btn)

        v_users.addLayout(users_btn_h)
        self.tabs.addTab(tab_users, "Реестр абонентов (Users & Keys)")

        # --- ВКЛАДКА 2: Журнал аудита ---
        tab_audit = QWidget()
        v_audit = QVBoxLayout(tab_audit)

        self.audit_table = QTableWidget(self)
        self.audit_table.setColumnCount(5)
        self.audit_table.setHorizontalHeaderLabels([
            "ID",
            "Временная метка (UTC)",
            "Тип события",
            "Пользователь",
            "Детализация",
        ])
        self.audit_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.audit_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.audit_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.audit_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.audit_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.audit_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.audit_table.verticalHeader().setVisible(False)
        v_audit.addWidget(self.audit_table)

        audit_btn_h = QHBoxLayout()
        self.export_audit_btn = QPushButton("💾 Экспорт журнала аудита в CSV...", self)
        self.export_audit_btn.setObjectName("secondaryButton")
        self.export_audit_btn.clicked.connect(self.export_audit_csv)
        audit_btn_h.addWidget(self.export_audit_btn)
        audit_btn_h.addStretch()
        v_audit.addLayout(audit_btn_h)

        self.tabs.addTab(tab_audit, "Журнал аудита подключений (Security Audit Log)")
        layout.addWidget(self.tabs)

        # Нижняя кнопка
        bottom_h = QHBoxLayout()
        bottom_h.addStretch()
        self.close_btn = QPushButton("Закрыть", self)
        self.close_btn.setObjectName("secondaryButton")
        self.close_btn.clicked.connect(self.accept)
        bottom_h.addWidget(self.close_btn)
        layout.addLayout(bottom_h)

        self._cached_users = []

    def toggle_db_mode(self):
        """Переключает режим активности персистентной базы данных (включена / выключена)."""
        if not self.api.check_health(timeout=0.3):
            QMessageBox.warning(
                self,
                "Сервер недоступен",
                "Сервер не запущен (127.0.0.1:8000). Запустите сервер для управления БД.",
            )
            return

        try:
            res = self.api.toggle_db()
            is_enabled = res.get("enabled", True)
            status_text = (
                "ВКЛЮЧЕНА (персистентное сохранение открытых ключей в SQLite)"
                if is_enabled
                else "ВЫКЛЮЧЕНА (открытые ключи хранятся только в ОЗУ)"
            )
            QMessageBox.information(
                self,
                "Режим базы данных изменен",
                f"База данных сервера теперь: {status_text}.",
            )
            self.refresh_all_data()
        except Exception as exc:
            QMessageBox.critical(self, "Ошибка", f"Не удалось изменить режим БД сервера: {exc}")

    def refresh_all_data(self):
        """Запрашивает актуальные данные из SQLite БД сервера."""
        if not self.api.check_health(timeout=0.3):
            self.db_status_badge.setText("🔴 Сервер офлайн (127.0.0.1:8000)")
            self.db_status_badge.setStyleSheet(
                "background-color: #7F1D1D; color: #FCA5A5; padding: 6px 12px; border-radius: 6px; font-weight: bold; border: 1px solid #DC2626;"
            )
            self.db_desc_lbl.setText("Сервер выключен. Запустите сервер (py server/app.py) для просмотра данных.")
            self.stats_lbl.setText("Сервер недоступен. База данных сервера не может быть опрошена.")
            self.populate_users_table([])
            self.populate_audit_table([])
            return

        # 1. Статус и режим активности БД
        try:
            status = self.api.get_db_status()
            is_enabled = status.get("enabled", True)
            if is_enabled:
                self.db_status_badge.setText("🟢 БД ВКЛЮЧЕНА: сохранение открытых ключей в SQLite")
                self.db_status_badge.setStyleSheet(
                    "background-color: #064E3B; color: #34D399; padding: 6px 12px; border-radius: 6px; font-weight: bold; border: 1px solid #059669;"
                )
                self.db_toggle_btn.setText("⏸️ Выключить сохранение в БД")
                self.db_desc_lbl.setText("Ключи абонентов сохраняются в файл SQLite и доступны после перезапуска.")
            else:
                self.db_status_badge.setText("🟡 БД ВЫКЛЮЧЕНА: открытые ключи хранятся только в ОЗУ")
                self.db_status_badge.setStyleSheet(
                    "background-color: #78350F; color: #FBBF24; padding: 6px 12px; border-radius: 6px; font-weight: bold; border: 1px solid #D97706;"
                )
                self.db_toggle_btn.setText("▶️ Включить сохранение в БД")
                self.db_desc_lbl.setText("Ключи абонентов находятся в оперативной памяти сервера (после рестарта будут стёрты).")

            size_kb = status.get("db_size_bytes", 0) / 1024
            self.stats_lbl.setText(
                f"Файл БД: {status.get('db_path', 'secure_chat.db')} | "
                f"Ключей в БД: {status.get('user_count_in_db', 0)} | "
                f"Ключей в ОЗУ: {status.get('user_count_in_memory', 0)} | "
                f"Событий: {status.get('log_count', 0)} | "
                f"Размер: {size_kb:.1f} КБ"
            )
        except Exception as exc:
            self.stats_lbl.setText(f"Статистика сервера недоступна: {exc}")
            self.db_status_badge.setText("⚪ Сервер не отвечает")
            self.db_status_badge.setStyleSheet("color: #94A3B8;")

        # 2. Список пользователей
        try:
            self._cached_users = self.api.get_db_users()
            self.populate_users_table(self._cached_users)
        except Exception as exc:
            # Fallback на обычный get_users
            try:
                raw_users = self.api.get_users()
                self._cached_users = [
                    {"user_id": u["user_id"], "public_key": u["public_key"], "status": "active",
                     "registered_at": "-", "last_seen_at": "-", "ip_address": "127.0.0.1"}
                    for u in raw_users
                ]
                self.populate_users_table(self._cached_users)
            except Exception as e2:
                self._cached_users = []
                self.populate_users_table([])

        # 3. Журнал аудита
        try:
            audit_logs = self.api.get_db_audit_logs(limit=200)
            self.populate_audit_table(audit_logs)
        except Exception:
            pass

    def populate_users_table(self, users: list):
        self.users_table.setRowCount(len(users))
        for row, u in enumerate(users):
            item_id = QTableWidgetItem(str(u.get("user_id", "")))
            item_id.setFlags(item_id.flags() & ~Qt.ItemIsEditable)

            pk_str = str(u.get("public_key", ""))
            short_pk = pk_str[:16] + "..." + pk_str[-16:] if len(pk_str) > 36 else pk_str
            item_pk = QTableWidgetItem(short_pk)
            item_pk.setToolTip(pk_str)
            item_pk.setFlags(item_pk.flags() & ~Qt.ItemIsEditable)

            status_str = str(u.get("status", "active"))
            item_status = QTableWidgetItem(status_str.upper())
            if status_str == "active":
                item_status.setForeground(QColor("#34D399"))
            else:
                item_status.setForeground(QColor("#F87171"))
            item_status.setFlags(item_status.flags() & ~Qt.ItemIsEditable)

            reg_at = str(u.get("registered_at", "")).replace("T", " ")[:19]
            item_reg = QTableWidgetItem(reg_at)
            item_reg.setFlags(item_reg.flags() & ~Qt.ItemIsEditable)

            last_at = str(u.get("last_seen_at", "")).replace("T", " ")[:19]
            item_last = QTableWidgetItem(last_at)
            item_last.setFlags(item_last.flags() & ~Qt.ItemIsEditable)

            ip_str = str(u.get("ip_address", "127.0.0.1"))
            item_ip = QTableWidgetItem(ip_str)
            item_ip.setFlags(item_ip.flags() & ~Qt.ItemIsEditable)

            self.users_table.setItem(row, 0, item_id)
            self.users_table.setItem(row, 1, item_pk)
            self.users_table.setItem(row, 2, item_status)
            self.users_table.setItem(row, 3, item_reg)
            self.users_table.setItem(row, 4, item_last)
            self.users_table.setItem(row, 5, item_ip)

    def populate_audit_table(self, logs: list):
        self.audit_table.setRowCount(len(logs))
        for row, item in enumerate(logs):
            it_id = QTableWidgetItem(str(item.get("id", "")))
            it_id.setFlags(it_id.flags() & ~Qt.ItemIsEditable)

            ts = str(item.get("timestamp", "")).replace("T", " ")[:19]
            it_ts = QTableWidgetItem(ts)
            it_ts.setFlags(it_ts.flags() & ~Qt.ItemIsEditable)

            ev = str(item.get("event_type", ""))
            it_ev = QTableWidgetItem(ev)
            it_ev.setFlags(it_ev.flags() & ~Qt.ItemIsEditable)

            usr = str(item.get("user_id", "") or "-")
            it_usr = QTableWidgetItem(usr)
            it_usr.setFlags(it_usr.flags() & ~Qt.ItemIsEditable)

            det = str(item.get("details", "") or "")
            it_det = QTableWidgetItem(det)
            it_det.setToolTip(det)
            it_det.setFlags(it_det.flags() & ~Qt.ItemIsEditable)

            self.audit_table.setItem(row, 0, it_id)
            self.audit_table.setItem(row, 1, it_ts)
            self.audit_table.setItem(row, 2, it_ev)
            self.audit_table.setItem(row, 3, it_usr)
            self.audit_table.setItem(row, 4, it_det)

    def filter_users_table(self, query: str):
        query = query.strip().lower()
        if not query:
            self.populate_users_table(self._cached_users)
            return

        filtered = [
            u for u in self._cached_users
            if query in str(u.get("user_id", "")).lower() or query in str(u.get("public_key", "")).lower()
        ]
        self.populate_users_table(filtered)

    def _get_selected_user_id(self) -> Optional[str]:
        cur_row = self.users_table.currentRow()
        if cur_row < 0:
            QMessageBox.warning(self, "Выбор", "Выберите строку с пользователем в таблице!")
            return None
        return self.users_table.item(cur_row, 0).text()

    def toggle_user_status(self):
        uid = self._get_selected_user_id()
        if not uid:
            return

        cur_status = self.users_table.item(self.users_table.currentRow(), 2).text().lower()
        new_status = "blocked" if cur_status == "active" else "active"

        try:
            self.api.update_user_status(uid, new_status)
            QMessageBox.information(self, "Статус обновлен", f"Пользователю '{uid}' назначен статус: {new_status.upper()}")
            self.refresh_all_data()
        except Exception as exc:
            QMessageBox.critical(self, "Ошибка", f"Не удалось обновить статус: {exc}")

    def delete_user(self):
        uid = self._get_selected_user_id()
        if not uid:
            return

        reply = QMessageBox.question(
            self,
            "Подтверждение удаления",
            f"Вы действительно хотите удалить пользователя '{uid}' и его открытый ключ bign из БД?",
            QMessageBox.Yes | QMessageBox.No,
        )
        if reply == QMessageBox.Yes:
            try:
                self.api.delete_db_user(uid)
                QMessageBox.information(self, "Удалено", f"Пользователь '{uid}' удален из базы данных.")
                self.refresh_all_data()
            except Exception as exc:
                QMessageBox.critical(self, "Ошибка", f"Не удалось удалить пользователя: {exc}")

    def export_csv(self):
        path, _ = QFileDialog.getSaveFileName(self, "Экспорт абонентов в CSV", "users_export.csv", "CSV (*.csv)")
        if path:
            try:
                import csv
                with open(path, "w", newline="", encoding="utf-8-sig") as f:
                    writer = csv.writer(f)
                    writer.writerow(["user_id", "public_key", "registered_at", "last_seen_at", "status", "ip_address"])
                    for u in self._cached_users:
                        writer.writerow([
                            u.get("user_id"),
                            u.get("public_key"),
                            u.get("registered_at"),
                            u.get("last_seen_at"),
                            u.get("status"),
                            u.get("ip_address"),
                        ])
                QMessageBox.information(self, "Экспорт CSV", f"Данные успешно экспортированы в:\n{path}")
            except Exception as exc:
                QMessageBox.critical(self, "Ошибка экспорта", str(exc))

    def export_json(self):
        path, _ = QFileDialog.getSaveFileName(self, "Экспорт абонентов в JSON", "users_export.json", "JSON (*.json)")
        if path:
            try:
                import json
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(self._cached_users, f, indent=2, ensure_ascii=False)
                QMessageBox.information(self, "Экспорт JSON", f"Данные успешно экспортированы в:\n{path}")
            except Exception as exc:
                QMessageBox.critical(self, "Ошибка экспорта", str(exc))

    def export_audit_csv(self):
        """Экспортирует таблицу аудита в CSV файл."""
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Экспорт журнала аудита в CSV",
            "audit_logs_export.csv",
            "CSV (*.csv);;Все файлы (*.*)",
        )
        if not path:
            return
        try:
            import csv
            with open(path, "w", newline="", encoding="utf-8-sig") as f:
                writer = csv.writer(f, delimiter=";")
                writer.writerow(["ID", "Timestamp (UTC)", "Event Type", "User ID", "Details"])
                for r in range(self.audit_table.rowCount()):
                    writer.writerow([
                        self.audit_table.item(r, 0).text() if self.audit_table.item(r, 0) else "",
                        self.audit_table.item(r, 1).text() if self.audit_table.item(r, 1) else "",
                        self.audit_table.item(r, 2).text() if self.audit_table.item(r, 2) else "",
                        self.audit_table.item(r, 3).text() if self.audit_table.item(r, 3) else "",
                        self.audit_table.item(r, 4).text() if self.audit_table.item(r, 4) else "",
                    ])
            QMessageBox.information(self, "Экспорт аудита", f"Журнал аудита успешно сохранен в:\n{path}")
        except Exception as exc:
            QMessageBox.critical(self, "Ошибка экспорта", f"Не удалось сохранить CSV: {exc}")
