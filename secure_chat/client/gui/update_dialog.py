"""
Графический диалог безопасного обновления ПО «Secure Chat» (ПЗ-4).
Реализует:
  * Проверку наличия обновлений онлайн через REST API сервера;
  * Выбор локального пакета обновления (офлайн-режим через manifest.json);
  * Визуальный журнал шагов верификации (Ed25519, SHA-256, SBOM CycloneDX, Staging, Backup, Swap);
  * Индикатор прогресса скачивания и распаковки;
  * Информацию об аппаратном идентификаторе (device_id) и текущей версии ПО.
"""

from pathlib import Path
from typing import Optional

from PyQt5.QtCore import QObject, Qt, QThread, pyqtSignal
from PyQt5.QtWidgets import (
    QDialog,
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
)

from common.build_info import get_build_info
from client.updater import (
    FileSource,
    HttpSource,
    Updater,
    get_device_id,
)


class UpdateWorker(QObject):
    """Фоновый рабочий поток выполнения процесса обновления."""
    progress_changed = pyqtSignal(int, int)
    log_message = pyqtSignal(str)
    finished = pyqtSignal(bool, str)

    def __init__(self, updater: Updater):
        super().__init__()
        self.updater = updater
        self.updater.log_callback = self._on_log

    def _on_log(self, msg: str):
        self.log_message.emit(msg)

    def _on_progress(self, current: int, total: int):
        self.progress_changed.emit(current, total)

    def run(self):
        try:
            success = self.updater.run_update(progress_cb=self._on_progress)
            self.finished.emit(success, "Обновление успешно установлено!")
        except Exception as exc:
            self.finished.emit(False, str(exc))


class UpdateDialog(QDialog):
    """
    Диалоговое окно управления безопасным обновлением ПО.
    """

    def __init__(self, parent=None, api_client=None):
        super().__init__(parent)
        self.setWindowTitle("Безопасное обновление ПО (ПЗ-4)")
        self.resize(760, 560)
        self.setMinimumSize(700, 500)

        self.api_client = api_client
        self.build_info = get_build_info()
        self.current_version = self.build_info.version.split("-")[0]
        self.device_id = get_device_id()
        self.server_url = getattr(api_client, "base_url", "http://127.0.0.1:8000")

        self.app_dir = Path(__file__).resolve().parent.parent.parent

        self.active_source = None
        self.target_release_info = None
        self._thread: Optional[QThread] = None
        self._worker: Optional[UpdateWorker] = None

        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.setContentsMargins(18, 16, 18, 16)

        # 1. Заголовок
        title = QLabel("Подсистема безопасного обновления ПО")
        title.setStyleSheet("font-size: 16px; font-weight: bold; color: #1E293B;")
        layout.addWidget(title)

        subtitle = QLabel("Контроль целостности, цифровая подпись Ed25519, валидация SBOM и атомарный откат")
        subtitle.setStyleSheet("font-size: 12px; color: #64748B;")
        layout.addWidget(subtitle)

        # 2. Информационная панель
        info_box = QGroupBox("Параметры текущей установки")
        info_layout = QHBoxLayout(info_box)

        lbl_cur_ver = QLabel(f"<b>Установленная версия:</b> {self.build_info.version}")
        lbl_device = QLabel(f"<b>Аппаратный Device ID:</b> <code>{self.device_id}</code>")
        info_layout.addWidget(lbl_cur_ver)
        info_layout.addStretch()
        info_layout.addWidget(lbl_device)
        layout.addWidget(info_box)

        # 3. Панель доступного релиза
        release_box = QGroupBox("Состояние релиза")
        rel_layout = QVBoxLayout(release_box)
        self.lbl_release_status = QLabel("Нажмите «Проверить онлайн» или выберите локальный manifest.json")
        self.lbl_release_status.setStyleSheet("color: #475569; font-weight: bold;")
        rel_layout.addWidget(self.lbl_release_status)
        layout.addWidget(release_box)

        # 4. Панель управления действиями
        action_layout = QHBoxLayout()

        self.btn_check_online = QPushButton("🌐 Проверить обновления онлайн", self)
        self.btn_check_online.setStyleSheet("padding: 7px 14px; font-weight: bold;")
        self.btn_check_online.clicked.connect(self.check_online_update)
        action_layout.addWidget(self.btn_check_online)

        self.btn_select_offline = QPushButton("📁 Выбрать пакет офлайн...", self)
        self.btn_select_offline.setStyleSheet("padding: 7px 14px;")
        self.btn_select_offline.clicked.connect(self.select_offline_manifest)
        action_layout.addWidget(self.btn_select_offline)

        self.btn_install = QPushButton("🚀 Установить обновление", self)
        self.btn_install.setStyleSheet(
            "padding: 7px 14px; font-weight: bold; background-color: #2563EB; color: white;"
        )
        self.btn_install.setEnabled(False)
        self.btn_install.clicked.connect(self.start_installation)
        action_layout.addWidget(self.btn_install)

        layout.addLayout(action_layout)

        # 5. Прогресс-бар
        self.progress_bar = QProgressBar(self)
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(True)
        layout.addWidget(self.progress_bar)

        # 6. Журнал выполнения процесса обновления
        layout.addWidget(QLabel("Журнал операций обновления и аудита безопасности:"))
        self.log_text = QTextEdit(self)
        self.log_text.setReadOnly(True)
        self.log_text.setStyleSheet(
            "background-color: #0F172A; color: #38BDF8; font-family: Consolas, monospace; font-size: 11px;"
        )
        layout.addWidget(self.log_text)

        # 7. Нижняя панель
        bottom_layout = QHBoxLayout()
        bottom_layout.addStretch()
        self.btn_close = QPushButton("Закрыть", self)
        self.btn_close.clicked.connect(self.close)
        bottom_layout.addWidget(self.btn_close)
        layout.addLayout(bottom_layout)

    def append_log(self, text: str):
        """Добавляет строку в журнал."""
        self.log_text.append(text)
        sb = self.log_text.verticalScrollBar()
        sb.setValue(sb.maximum())

    def check_online_update(self):
        """Проверяет наличие обновления через REST API сервера."""
        self.append_log("--- Запрос проверки обновлений на сервере ---")
        self.append_log(f"Сервер: {self.server_url}, текущая версия: {self.current_version}")
        try:
            http_source = HttpSource(
                base_url=self.server_url,
                device_id=self.device_id,
            )
            res = http_source.check_update(current_version=self.current_version)
            if res and res.get("update_available"):
                ver = res.get("version")
                min_sup = res.get("min_supported", "1.0.0")
                self.lbl_release_status.setText(
                    f"🟢 Доступно онлайн-обновление: v{ver} (мин. поддерживаемая: v{min_sup})"
                )
                self.lbl_release_status.setStyleSheet("color: #16A34A; font-weight: bold;")
                self.append_log(f"Найдена новая версия: {ver} (мин. поддерживаемая: {min_sup})")
                self.active_source = http_source
                self.target_release_info = res
                self.btn_install.setEnabled(True)
            else:
                self.lbl_release_status.setText("⚪ У вас установлена актуальная версия ПО. Обновлений нет.")
                self.lbl_release_status.setStyleSheet("color: #475569; font-weight: bold;")
                self.append_log("На сервере нет более свежих версий для данной платформы.")
                self.btn_install.setEnabled(False)
        except Exception as exc:
            self.lbl_release_status.setText(f"🔴 Ошибка проверки обновлений: {exc}")
            self.lbl_release_status.setStyleSheet("color: #DC2626; font-weight: bold;")
            self.append_log(f"Ошибка соединения с сервером: {exc}")
            self.btn_install.setEnabled(False)

    def select_offline_manifest(self):
        """Открывает диалог выбора manifest.json для офлайн-обновления."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Выберите файл манифеста обновления",
            str(self.app_dir),
            "Manifest Files (manifest*.json *.json);;All Files (*.*)",
        )
        if not file_path:
            return

        self.append_log(f"--- Выбран локальный манифест: {file_path} ---")
        try:
            file_source = FileSource(manifest_file=file_path)
            res = file_source.check_update(current_version=self.current_version)
            manifest = file_source.get_manifest()
            ver = manifest.get("version", "unknown")
            min_sup = manifest.get("min_supported", "1.0.0")

            self.lbl_release_status.setText(
                f"📦 Офлайн-пакет выбран: v{ver} (файл: {Path(file_path).name})"
            )
            self.lbl_release_status.setStyleSheet("color: #0284C7; font-weight: bold;")
            self.append_log(f"Манифест загружен. Целевая версия: {ver}, min_supported: {min_sup}")
            self.active_source = file_source
            self.target_release_info = manifest
            self.btn_install.setEnabled(True)
        except Exception as exc:
            self.lbl_release_status.setText(f"🔴 Ошибка загрузки манифеста: {exc}")
            self.lbl_release_status.setStyleSheet("color: #DC2626; font-weight: bold;")
            self.append_log(f"Ошибка парсинга манифеста: {exc}")
            self.btn_install.setEnabled(False)

    def start_installation(self):
        """Запускает процесс безопасного обновления в фоновом потоке."""
        if not self.active_source:
            QMessageBox.warning(self, "Внимание", "Источник обновления не определен.")
            return

        self.btn_install.setEnabled(False)
        self.btn_check_online.setEnabled(False)
        self.btn_select_offline.setEnabled(False)
        self.progress_bar.setValue(0)
        self.append_log(">>> Инициализация процесса безопасного обновления ПО...")

        updater = Updater(
            source=self.active_source,
            current_version=self.current_version,
            app_dir=self.app_dir,
            device_id=self.device_id,
        )

        self._thread = QThread()
        self._worker = UpdateWorker(updater)
        self._worker.moveToThread(self._thread)

        self._thread.started.connect(self._worker.run)
        self._worker.log_message.connect(self.append_log)
        self._worker.progress_changed.connect(self._on_progress_update)
        self._worker.finished.connect(self._on_install_finished)

        self._thread.start()

    def _on_progress_update(self, current: int, total: int):
        if total > 0:
            percent = int((current / total) * 100)
            self.progress_bar.setValue(min(percent, 100))

    def _on_install_finished(self, success: bool, message: str):
        if self._thread:
            self._thread.quit()
            self._thread.wait()

        self.btn_check_online.setEnabled(True)
        self.btn_select_offline.setEnabled(True)

        if success:
            self.progress_bar.setValue(100)
            self.lbl_release_status.setText("✅ Обновление успешно установлено!")
            self.lbl_release_status.setStyleSheet("color: #16A34A; font-weight: bold;")
            QMessageBox.information(
                self,
                "Обновление завершено",
                "Обновление успешно установлено!\nДля применения всех изменений рекомендуется перезапустить приложение.",
            )
        else:
            self.lbl_release_status.setText(f"❌ Ошибка установки: {message}")
            self.lbl_release_status.setStyleSheet("color: #DC2626; font-weight: bold;")
            QMessageBox.critical(
                self,
                "Сбой обновления",
                f"Не удалось завершить обновление ПО:\n{message}\n\nФайлы приложения были автоматически восстановлены из резервной копии.",
            )
