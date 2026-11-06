"""
Модульные тесты подсистемы централизованного журналирования и аудита (common.logger).
Проверяют:
  1. Создание, сериализацию и строковое представление LogEntry;
  2. Запись событий различных уровней (INFO, WARNING, ERROR, DEBUG);
  3. Фильтрацию записей по уровню, источнику и подстроке;
  4. Корректность экспорта в формат CSV с разделителем ';' и кодировкой UTF-8-SIG;
  5. Корректность экспорта в формат TXT;
  6. Работу механизма слушателей (listeners);
  7. Ограничение емкости кольцевого буфера (max_entries);
  8. Интеграцию с AppLogHandler и стандартным модулем logging Python.
"""

import csv
import logging
from pathlib import Path
import pytest

from common.logger import LogEntry, LogService, AppLogHandler


def test_log_entry_dataclass():
    entry = LogEntry(
        timestamp="2026-10-24 10:00:00",
        level="INFO",
        source="secure_chat.crypto",
        message="Тестовое сообщение",
    )
    assert entry.timestamp == "2026-10-24 10:00:00"
    assert entry.level == "INFO"
    assert entry.source == "secure_chat.crypto"
    assert entry.message == "Тестовое сообщение"

    d = entry.to_dict()
    assert d["level"] == "INFO"
    assert d["source"] == "secure_chat.crypto"

    row = entry.to_csv_row()
    assert row == ["2026-10-24 10:00:00", "INFO", "secure_chat.crypto", "Тестовое сообщение"]

    formatted = entry.to_formatted_str()
    assert "[INFO   ]" in formatted
    assert "[secure_chat.crypto]" in formatted


def test_log_service_recording_and_stats():
    svc = LogService(max_entries=50)
    svc.clear()

    svc.info("test.module", "Info message")
    svc.warning("test.module", "Warning message")
    svc.error("test.crypto", "Error message")
    svc.debug("test.network", "Debug message")

    stats = svc.get_stats()
    assert stats["total"] == 4
    assert stats["INFO"] == 1
    assert stats["WARNING"] == 1
    assert stats["ERROR"] == 1
    assert stats["DEBUG"] == 1


def test_log_service_filtering():
    svc = LogService(max_entries=50)
    svc.clear()

    svc.info("secure_chat.crypto.belt", "Belt encryption started")
    svc.info("secure_chat.crypto.bign", "Bign key generated")
    svc.warning("secure_chat.network.api", "Connection slow")
    svc.error("secure_chat.crypto.belt", "MAC mismatch")

    # Фильтр по уровню
    assert len(svc.get_entries(level="INFO")) == 2
    assert len(svc.get_entries(level="WARNING")) == 1
    assert len(svc.get_entries(level="ERROR")) == 1

    # Фильтр по источнику
    assert len(svc.get_entries(source="crypto")) == 3
    assert len(svc.get_entries(source="network")) == 1

    # Поиск по подстроке
    assert len(svc.get_entries(search="mismatch")) == 1
    assert len(svc.get_entries(search="Bign")) == 1


def test_log_service_csv_export(tmp_path: Path):
    svc = LogService(max_entries=50)
    svc.clear()

    svc.info("crypto", "Key generated; 256 bits")
    svc.error("network", "HTTP 500 error")

    csv_path = tmp_path / "test_logs.csv"
    count = svc.export_to_csv(csv_path)
    assert count == 2
    assert csv_path.is_file()

    with csv_path.open("r", encoding="utf-8-sig", newline="") as f:
        reader = list(csv.reader(f, delimiter=";"))
        assert len(reader) == 3  # заголовок + 2 записи
        assert reader[0] == ["Timestamp", "Level", "Source", "Message"]
        assert reader[1][1] == "INFO"
        assert reader[1][2] == "crypto"
        assert "Key generated; 256 bits" in reader[1][3]
        assert reader[2][1] == "ERROR"


def test_log_service_txt_export(tmp_path: Path):
    svc = LogService(max_entries=50)
    svc.clear()

    svc.info("audit", "User alice registered")
    txt_path = tmp_path / "test_logs.txt"
    count = svc.export_to_txt(txt_path)
    assert count == 1
    assert txt_path.is_file()

    content = txt_path.read_text(encoding="utf-8")
    assert "User alice registered" in content
    assert "Всего записей: 1" in content


def test_log_service_listeners():
    svc = LogService(max_entries=50)
    captured = []

    def on_log(entry: LogEntry):
        captured.append(entry)

    svc.add_listener(on_log)
    svc.info("test", "Message 1")
    svc.warning("test", "Message 2")

    assert len(captured) == 2
    assert captured[0].message == "Message 1"

    svc.remove_listener(on_log)
    svc.info("test", "Message 3")
    assert len(captured) == 2  # Не увеличилось


def test_log_service_buffer_limit():
    svc = LogService(max_entries=5)
    for i in range(10):
        svc.info("test", f"Msg {i}")

    entries = svc.get_entries()
    assert len(entries) == 5
    assert entries[0].message == "Msg 5"
    assert entries[-1].message == "Msg 9"


def test_app_log_handler_integration():
    svc = LogService(max_entries=50)
    handler = AppLogHandler(svc)
    handler.setLevel(logging.INFO)

    test_logger = logging.getLogger("secure_chat.test_logger")
    test_logger.setLevel(logging.INFO)
    test_logger.addHandler(handler)

    test_logger.info("Direct python logging message")
    test_logger.warning("Direct python warning message")

    entries = svc.get_entries()
    assert len(entries) >= 2
    assert any("Direct python logging message" in e.message for e in entries)
    assert any("Direct python warning message" in e.message for e in entries)
