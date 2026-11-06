import csv
from datetime import datetime
import json
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Dict, List, Optional

import requests
from PyQt6.QtCore import QObject, QThread, pyqtSignal
from PyQt6.QtGui import QColor, QTextCharFormat
from PyQt6.QtWidgets import (
    QApplication,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QStatusBar,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

# =====================================================================
# DATA ACCESS LAYER & МОДЕЛИ
# =====================================================================

@dataclass
class LogEntry:
    timestamp: str
    level: str
    message: str


@dataclass
class ApiClientConfig:
    base_url: str = "http://localhost:5157"
    timeout_seconds: int = 30


@dataclass
class RequestResult:
    success: bool
    status_code: int
    data: Optional[str] = None
    error_message: Optional[str] = None


# Сервис логирования (с поддержкой экспорта в CSV - Вариант 4)
class LoggerService(QObject):
    # Сигнал для передачи сообщения в UI: (текст, уровень)
    log_emitted = pyqtSignal(str, str)

    def __init__(self):
        super().__init__()
        self._logs: List[LogEntry] = []

    def _log(self, level: str, message: str):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self._logs.append(LogEntry(timestamp=timestamp, level=level, message=message))
        self.log_emitted.emit(f"[{timestamp}] [{level}] {message}", level)

    def log_info(self, message: str):
        self._log("INFO", message)

    def log_warning(self, message: str):
        self._log("WARN", message)

    def log_error(self, message: str):
        self._log("ERROR", message)

    def export_to_csv(self, filepath: str) -> bool:
        """Экспорт накопленных логов в CSV-файл (Вариант 4)."""
        if not self._logs:
            self.log_warning("Журнал логов пуст. Экспорт отменён.")
            return False
        try:
            with open(filepath, mode="w", newline="", encoding="utf-8-sig") as f:
                writer = csv.writer(f, delimiter=";")
                writer.writerow(["Timestamp", "Level", "Message"])
                for entry in self._logs:
                    writer.writerow([entry.timestamp, entry.level, entry.message])
            self.log_info(f"Логи успешно экспортированы в {filepath}")
            return True
        except Exception as e:
            self.log_error(f"Ошибка экспорта в CSV: {e}")
            return False


# =====================================================================
# BUSINESS LOGIC LAYER (Запросы)
# =====================================================================

class BaseRequest(ABC):
    @property
    @abstractmethod
    def endpoint(self) -> str:
        pass

    @property
    @abstractmethod
    def http_method(self) -> str:
        pass

    @abstractmethod
    def build_body(self) -> Optional[str]:
        pass

    def get_headers(self) -> Dict[str, str]:
        return {}


class InitRequest(BaseRequest):
    @property
    def endpoint(self) -> str:
        return "/state/init"

    @property
    def http_method(self) -> str:
        return "GET"

    def build_body(self) -> Optional[str]:
        return None


class SetRequest(BaseRequest):
    def __init__(self, request_id: str, theme: str, person: dict):
        self._id = request_id
        self._theme = theme
        self._person = person

    @property
    def endpoint(self) -> str:
        return "/state/set"

    @property
    def http_method(self) -> str:
        return "POST"

    def build_body(self) -> Optional[str]:
        payload = {"theme": self._theme, "person": self._person}
        return json.dumps(payload, ensure_ascii=False)

    def get_headers(self) -> Dict[str, str]:
        return {
            "X-Request-Id": self._id,
            "Content-Type": "application/json"
        }


class StatusRequest(BaseRequest):
    def __init__(self, request_id: str):
        self._id = request_id

    @property
    def endpoint(self) -> str:
        return "/state/status"

    @property
    def http_method(self) -> str:
        return "POST"

    def build_body(self) -> Optional[str]:
        payload = {"id": self._id}
        return json.dumps(payload, ensure_ascii=False)

    def get_headers(self) -> Dict[str, str]:
        return {"Content-Type": "application/json"}


class HttpClientService:
    def __init__(self, config: ApiClientConfig, logger: LoggerService):
        self._config = config
        self._logger = logger

    def send(self, request: BaseRequest) -> RequestResult:
        base_url = self._config.base_url.rstrip("/")
        url = f"{base_url}{request.endpoint}"
        body = request.build_body()
        headers = request.get_headers()

        try:
            self._logger.log_info(f"→ {request.http_method} {request.endpoint}")
            response = requests.request(
                method=request.http_method,
                url=url,
                data=body.encode("utf-8") if body else None,
                headers=headers,
                timeout=self._config.timeout_seconds
            )

            status = response.status_code
            self._logger.log_info(f"← {status} {response.reason}")

            if status == 204:
                self._logger.log_info("204: Нет содержимого (No Content)")
            elif status == 400:
                self._logger.log_warning("400: Неверный запрос (Bad Request)")
            elif status == 401:
                self._logger.log_warning("401: Не авторизован (Unauthorized)")
            elif status == 404:
                self._logger.log_warning("404: Ресурс не найден (Not Found)")

            return RequestResult(
                success=response.ok,
                status_code=status,
                data=response.text
            )
        except Exception as ex:
            self._logger.log_error(f"Сетевая ошибка: {ex}")
            return RequestResult(success=False, status_code=0, error_message=str(ex))


# =====================================================================
# THREAD WORKER (Асинхронность в GUI)
# =====================================================================

class AsyncRequestWorker(QThread):
    finished_signal = pyqtSignal(RequestResult, str)

    def __init__(self, client: HttpClientService, request: BaseRequest, action_type: str):
        super().__init__()
        self._client = client
        self._request = request
        self._action_type = action_type

    def run(self):
        result = self._client.send(self._request)
        self.finished_signal.emit(result, self._action_type)


# =====================================================================
# PRESENTATION LAYER (GUI на PyQt6)
# =====================================================================

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Клиент для работы с сервером ЭЦП")
        self.resize(850, 700)

        # Сервисы
        self.logger = LoggerService()
        self.config = ApiClientConfig()
        self.client = HttpClientService(self.config, self.logger)

        self.saved_id: Optional[str] = None
        self.worker: Optional[AsyncRequestWorker] = None

        self._init_ui()
        self.logger.log_emitted.connect(self._append_log)

    def _init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        # 1. Параметры подключения и состояние
        config_group = QGroupBox("Параметры соединения")
        config_layout = QFormLayout(config_group)

        self.url_input = QLineEdit("http://localhost:5157")
        self.url_input.textChanged.connect(self._update_base_url)
        self.id_display = QLineEdit()
        self.id_display.setReadOnly(True)
        self.id_display.setPlaceholderText("ID не получен (нажмите 'Инициализация')")

        config_layout.addRow("Базовый URL:", self.url_input)
        config_layout.addRow("Сохранённый ID:", self.id_display)
        main_layout.addWidget(config_group)

        # 2. Ввод данных для запроса POST /state/set
        data_group = QGroupBox("Данные запроса")
        data_layout = QFormLayout(data_group)

        self.theme_input = QLineEdit("Подписание документов")
        self.person_input = QTextEdit()
        default_person = {
            "name": "Иван Иванов",
            "age": 30,
            "role": "Инженер"
        }
        self.person_input.setPlainText(json.dumps(default_person, indent=2, ensure_ascii=False))
        self.person_input.setMaximumHeight(100)

        data_layout.addRow("Тема (theme):", self.theme_input)
        data_layout.addRow("Person (JSON, мин. 3 поля):", self.person_input)
        main_layout.addWidget(data_group)

        # 3. Кнопки действий
        btn_layout = QHBoxLayout()
        self.btn_init = QPushButton("1. Инициализация (GET)")
        self.btn_set = QPushButton("2. Отправить данные (POST)")
        self.btn_status = QPushButton("3. Проверить статус (POST)")
        self.btn_auto = QPushButton("Авто-сценарий")
        self.btn_csv = QPushButton("Экспорт в CSV (Вар. 4)")

        btn_layout.addWidget(self.btn_init)
        btn_layout.addWidget(self.btn_set)
        btn_layout.addWidget(self.btn_status)
        btn_layout.addWidget(self.btn_auto)
        btn_layout.addWidget(self.btn_csv)
        main_layout.addLayout(btn_layout)

        # Привязка обработчиков событий к кнопкам
        self.btn_init.clicked.connect(self._handle_init)
        self.btn_set.clicked.connect(self._handle_set)
        self.btn_status.clicked.connect(self._handle_status)
        self.btn_auto.clicked.connect(self._handle_auto)
        self.btn_csv.clicked.connect(self._handle_export_csv)

        # 4. Лог-консоль (RichText)
        log_group = QGroupBox("Журнал событий")
        log_layout = QVBoxLayout(log_group)
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        log_layout.addWidget(self.log_text)
        main_layout.addWidget(log_group)

        # 5. Строка состояния (StatusStrip)
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Готов к работе")

    def _update_base_url(self, text: str):
        self.config.base_url = text.strip()

    # --- Асинхронное выполнение запросов ---
    def _execute_request(self, request: BaseRequest, action_type: str):
        self._set_ui_enabled(False)
        self.status_bar.showMessage(f"Выполняется: {request.http_method} {request.endpoint}...")

        self.worker = AsyncRequestWorker(self.client, request, action_type)
        self.worker.finished_signal.connect(self._on_request_finished)
        self.worker.start()

    def _set_ui_enabled(self, enabled: bool):
        self.btn_init.setEnabled(enabled)
        self.btn_set.setEnabled(enabled)
        self.btn_status.setEnabled(enabled)
        self.btn_auto.setEnabled(enabled)
        self.btn_csv.setEnabled(enabled)

    def _on_request_finished(self, result: RequestResult, action_type: str):
        self._set_ui_enabled(True)
        self.status_bar.showMessage(f"Готово. Код: {result.status_code}")

        if action_type == "INIT":
            if result.success and result.data:
                try:
                    data = json.loads(result.data)
                    self.saved_id = data.get("id", result.data.strip())
                except Exception:
                    self.saved_id = result.data.strip()
                self.id_display.setText(self.saved_id)
                self.logger.log_info(f"Получен и сохранён ID: {self.saved_id}")
            else:
                self.logger.log_error("Инициализация завершилась ошибкой.")

        elif action_type == "SET":
            if result.success:
                self.logger.log_info("Данные успешно зафиксированы на сервере.")

        elif action_type == "STATUS":
            if result.success:
                self.logger.log_info(f"Текущее состояние процесса: {result.data}")

        elif action_type == "AUTO_INIT":
            if result.success and result.data:
                try:
                    self.saved_id = json.loads(result.data).get("id", result.data.strip())
                except Exception:
                    self.saved_id = result.data.strip()
                self.id_display.setText(self.saved_id)
                self.logger.log_info(f"[Авто] Шаг 1 пройден. ID: {self.saved_id}")
                self._auto_step_2()
            else:
                self.logger.log_error("[Авто] Ошибка на шаге 1 (Init). Прервано.")

        elif action_type == "AUTO_SET":
            if result.success:
                self.logger.log_info("[Авто] Шаг 2 пройден (Данные отправлены).")
                self._auto_step_3()
            else:
                self.logger.log_error("[Авто] Ошибка на шаге 2 (Set). Прервано.")

        elif action_type == "AUTO_STATUS":
            if result.success:
                self.logger.log_info(f"[Авто] Шаг 3 пройден. Статус: {result.data}")
                self.logger.log_info("--- Автоматический сценарий успешно завершен ---")

    # --- Обработчики нажатий кнопок ---
    def _handle_init(self):
        self._execute_request(InitRequest(), "INIT")

    def _handle_set(self):
        if not self.saved_id:
            self.logger.log_warning("Сначала выполните инициализацию (ID пуст)!")
            return

        theme = self.theme_input.text().strip()
        try:
            person = json.loads(self.person_input.toPlainText())
            if not isinstance(person, dict) or len(person) < 3:
                self.logger.log_warning("Объект Person должен быть JSON-объектом минимум с 3 полями!")
                return
        except Exception as e:
            self.logger.log_error(f"Некорректный JSON в поле Person: {e}")
            return

        self._execute_request(SetRequest(self.saved_id, theme, person), "SET")

    def _handle_status(self):
        if not self.saved_id:
            self.logger.log_warning("Сначала выполните инициализацию (ID пуст)!")
            return
        self._execute_request(StatusRequest(self.saved_id), "STATUS")

    def _handle_auto(self):
        self.logger.log_info("--- Запуск автоматического сценария (Шаги 1 -> 2 -> 3) ---")
        self._execute_request(InitRequest(), "AUTO_INIT")

    def _auto_step_2(self):
        default_person = {"name": "Авто-Пользователь", "age": 28, "role": "Тестировщик"}
        self._execute_request(SetRequest(self.saved_id, "Авто-Тема", default_person), "AUTO_SET")

    def _auto_step_3(self):
        self._execute_request(StatusRequest(self.saved_id), "AUTO_STATUS")

    def _handle_export_csv(self):
        """Диалог сохранения файла для Варианта 4."""
        filepath, _ = QFileDialog.getSaveFileName(
            self, "Сохранить логи в CSV", "logs.csv", "CSV Files (*.csv)"
        )
        if filepath:
            self.logger.export_to_csv(filepath)

    # --- Цветное форматирование логов в QTextEdit ---
    def _append_log(self, text: str, level: str):
        fmt = QTextCharFormat()
        if level == "INFO":
            fmt.setForeground(QColor("#2ecc71"))  # Зелёный
        elif level == "WARN":
            fmt.setForeground(QColor("#f39c12"))  # Жёлтый / Оранжевый
        elif level == "ERROR":
            fmt.setForeground(QColor("#e74c3c"))  # Красный
        else:
            fmt.setForeground(QColor("#ffffff"))

        cursor = self.log_text.textCursor()
        cursor.movePosition(cursor.MoveOperation.End)
        cursor.insertText(text + "\n", fmt)
        self.log_text.setTextCursor(cursor)
        self.log_text.ensureCursorVisible()

    # --- Подтверждение закрытия окна ---
    def closeEvent(self, event):
        reply = QMessageBox.question(
            self,
            "Подтверждение выхода",
            "Вы уверены, что хотите закрыть приложение?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            event.accept()
        else:
            event.ignore()


# =====================================================================
# ТОЧКА ВХОДА
# =====================================================================
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())