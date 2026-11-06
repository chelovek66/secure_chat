"""
Модуль централизованного журналирования и аудита событий «Secure Chat».
Реализует:
  * Потокобезопасный кольцевой буфер журнальных записей в оперативной памяти;
  * Интеграцию со стандартной библиотекой Python logging через AppLogHandler;
  * Реактивные сигналы PyQt5 (pyqtSignal) для обновления GUI в реальном времени;
  * Экспорт журналов в форматы CSV (с разделителем ';') и структурированный TXT;
  * Фильтрацию записей по уровню важности, модулю-источнику и подстроке поиска.
"""

import csv
import logging
import threading
from collections import deque
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, List, Optional, Union

# Безопасный импорт PyQt5 для работы как в GUI, так и в headless/CLI режимах
try:
    from PyQt5.QtCore import QObject, pyqtSignal
    _HAS_PYQT = True
except ImportError:
    _HAS_PYQT = False
    class QObject:
        def __init__(self, *args, **kwargs):
            pass

    def pyqtSignal(*args, **kwargs):
        class _SignalStub:
            def emit(self, *a, **kw):
                pass
            def connect(self, *a, **kw):
                pass
            def disconnect(self, *a, **kw):
                pass
        return _SignalStub()


@dataclass(frozen=True)
class LogEntry:
    """
    Неизменяемая структура записи журнала событий (DTO).
    """
    timestamp: str
    level: str
    source: str
    message: str

    def to_dict(self) -> Dict[str, str]:
        return {
            "timestamp": self.timestamp,
            "level": self.level,
            "source": self.source,
            "message": self.message,
        }

    def to_csv_row(self) -> List[str]:
        return [self.timestamp, self.level, self.source, self.message]

    def to_formatted_str(self) -> str:
        return f"[{self.timestamp}] [{self.level:7s}] [{self.source}] {self.message}"


class AppLogHandler(logging.Handler):
    """
    Пользовательский обработчик logging.Handler, перенаправляющий
    все системные вызовы logging в сервис LogService.
    """

    def __init__(self, service: "LogService"):
        super().__init__()
        self.service = service

    def emit(self, record: logging.LogRecord):
        try:
            msg = self.format(record) if self.formatter else record.getMessage()
            t_str = datetime.fromtimestamp(record.created).strftime("%Y-%m-%d %H:%M:%S")
            self.service.record(
                level=record.levelname,
                source=record.name,
                message=msg,
                timestamp=t_str,
            )
        except Exception:
            self.handleError(record)


class LogService(QObject):
    """
    Централизованный сервис сбора, хранения и маршрутизации событий журнала.
    Поддерживает Qt-сигналы, фильтрацию и экспорт.
    """
    # Сигнал для GUI: передает объект LogEntry
    entry_added = pyqtSignal(object)

    def __init__(self, max_entries: int = 5000):
        super().__init__()
        self._max_entries = max_entries
        self._buffer: deque[LogEntry] = deque(maxlen=max_entries)
        self._lock = threading.RLock()
        self._listeners: List[Callable[[LogEntry], None]] = []
        self._handler_installed = False

    def record(
        self,
        level: str,
        source: str,
        message: str,
        timestamp: Optional[str] = None,
    ) -> LogEntry:
        """
        Регистрирует новую запись в журнале, уведомляет GUI и внешних подписчиков.
        """
        if timestamp is None:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        entry = LogEntry(
            timestamp=timestamp,
            level=level.upper(),
            source=source,
            message=message,
        )

        with self._lock:
            self._buffer.append(entry)
            listeners_copy = list(self._listeners)

        # Уведомляем Qt GUI (потокобезопасно через queued signal)
        if _HAS_PYQT and hasattr(self, "entry_added"):
            try:
                self.entry_added.emit(entry)
            except Exception:
                pass

        # Уведомляем синхронные колбэки
        for listener in listeners_copy:
            try:
                listener(entry)
            except Exception:
                pass

        return entry

    def info(self, source: str, message: str) -> LogEntry:
        return self.record("INFO", source, message)

    def warning(self, source: str, message: str) -> LogEntry:
        return self.record("WARNING", source, message)

    def error(self, source: str, message: str) -> LogEntry:
        return self.record("ERROR", source, message)

    def debug(self, source: str, message: str) -> LogEntry:
        return self.record("DEBUG", source, message)

    def get_entries(
        self,
        level: Optional[str] = None,
        source: Optional[str] = None,
        search: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> List[LogEntry]:
        """
        Возвращает список записей с опциональной фильтрацией.
        """
        level_upper = level.upper() if level and level.upper() != "ALL" else None
        source_lower = source.lower() if source else None
        search_lower = search.lower() if search else None

        with self._lock:
            entries = list(self._buffer)

        result: List[LogEntry] = []
        for e in entries:
            if level_upper and e.level != level_upper:
                continue
            if source_lower and source_lower not in e.source.lower():
                continue
            if search_lower and (
                search_lower not in e.message.lower()
                and search_lower not in e.source.lower()
            ):
                continue
            result.append(e)

        if limit is not None and limit > 0:
            return result[-limit:]
        return result

    def get_stats(self) -> Dict[str, int]:
        """Возвращает агрегированную статистику по уровням сообщений."""
        with self._lock:
            entries = list(self._buffer)

        stats = {
            "total": len(entries),
            "DEBUG": 0,
            "INFO": 0,
            "WARNING": 0,
            "ERROR": 0,
            "CRITICAL": 0,
        }
        for e in entries:
            if e.level in stats:
                stats[e.level] += 1
            else:
                stats[e.level] = 1
        return stats

    def clear(self) -> None:
        """Очищает буфер записей в памяти."""
        with self._lock:
            self._buffer.clear()

    def add_listener(self, callback: Callable[[LogEntry], None]) -> None:
        """Добавляет слушателя новых событий журнала."""
        with self._lock:
            if callback not in self._listeners:
                self._listeners.append(callback)

    def remove_listener(self, callback: Callable[[LogEntry], None]) -> None:
        """Удаляет слушателя."""
        with self._lock:
            if callback in self._listeners:
                self._listeners.remove(callback)

    def export_to_csv(
        self,
        filepath: Union[str, Path],
        entries: Optional[List[LogEntry]] = None,
    ) -> int:
        """
        Экспортирует записи журнала в формат CSV (разделитель ';', кодировка UTF-8 c BOM).
        Возвращает количество экспортированных строк.
        """
        target = Path(filepath)
        target.parent.mkdir(parents=True, exist_ok=True)

        if entries is None:
            entries = self.get_entries()

        with target.open("w", encoding="utf-8-sig", newline="") as f:
            writer = csv.writer(f, delimiter=";")
            writer.writerow(["Timestamp", "Level", "Source", "Message"])
            for e in entries:
                writer.writerow(e.to_csv_row())

        return len(entries)

    def export_to_txt(
        self,
        filepath: Union[str, Path],
        entries: Optional[List[LogEntry]] = None,
    ) -> int:
        """
        Экспортирует записи журнала в текстовый файл с форматированием.
        Возвращает количество экспортированных строк.
        """
        target = Path(filepath)
        target.parent.mkdir(parents=True, exist_ok=True)

        if entries is None:
            entries = self.get_entries()

        with target.open("w", encoding="utf-8") as f:
            f.write(f"=== ЖУРНАЛ СОБЫТИЙ «SECURE CHAT» — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ===\n")
            f.write(f"Всего записей: {len(entries)}\n\n")
            for e in entries:
                f.write(e.to_formatted_str() + "\n")

        return len(entries)

    def setup_logging(
        self,
        root_level: str = "INFO",
        log_file: Optional[Union[str, Path]] = None,
        attach_root: bool = False,
    ) -> None:
        """
        Интегрирует сервис с модулем standard logging Python.
        Перехватывает логгеры 'secure_chat' и (опционально) корневой.
        """
        if self._handler_installed:
            return

        level_num = getattr(logging, root_level.upper(), logging.INFO)
        handler = AppLogHandler(self)
        handler.setLevel(level_num)

        # Настраиваем форматирование для читаемости
        formatter = logging.Formatter("%(message)s")
        handler.setFormatter(formatter)

        # Подключаем к родительскому логгеру приложения 'secure_chat'
        sc_logger = logging.getLogger("secure_chat")
        sc_logger.setLevel(level_num)
        sc_logger.addHandler(handler)

        if attach_root:
            logging.getLogger().addHandler(handler)

        # Опциональная запись в файл
        if log_file:
            path = Path(log_file)
            path.parent.mkdir(parents=True, exist_ok=True)
            file_h = logging.FileHandler(path, encoding="utf-8")
            file_h.setLevel(level_num)
            file_formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
            file_h.setFormatter(file_formatter)
            sc_logger.addHandler(file_h)

        self._handler_installed = True


# Глобальный разделяемый экземпляр сервиса журналирования
log_service = LogService()
