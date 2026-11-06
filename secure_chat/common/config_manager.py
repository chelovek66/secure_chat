"""
Модуль централизованного управления конфигурацией клиентского приложения «Secure Chat».
Реализует спецификацию настроек сетевого подключения, криптографических путей,
таймаутов опроса, интерфейсных тем и параметров ведения журнала.
"""

import json
import logging
import threading
from pathlib import Path
from typing import Callable, List, Optional, Union

from pydantic import BaseModel, Field, field_validator, ValidationError

logger = logging.getLogger("secure_chat.config")


class ConfigError(ValueError):
    """Исключение при синтаксических или логических ошибках конфигурации."""
    pass


class ClientConfig(BaseModel):
    """
    Модель конфигурационных параметров клиентского приложения «Secure Chat».
    Содержит сетевые таймауты, интервалы опроса, пути к ключевым носителям и UI-настройки.
    """
    server_url: str = Field(default="http://127.0.0.1:8000", description="URL REST API сервера маршрутизации")
    poll_interval_sec: float = Field(default=2.0, description="Период опроса входящих сообщений в секундах")
    request_timeout_sec: float = Field(default=10.0, description="Сетевой таймаут ожидания ответа сервера")
    keys_dir: str = Field(default="keys", description="Каталог хранения закрытых/открытых ключей bign")
    theme: str = Field(default="dark", description="Цветовая тема оформления ('dark', 'light')")
    log_level: str = Field(default="INFO", description="Уровень логирования (DEBUG, INFO, WARNING, ERROR)")
    verify_integrity_on_startup: bool = Field(default=True, description="Флаг проверки АЦП/ЭЦП при запуске")
    auto_reconnect: bool = Field(default=True, description="Флаг автоматического восстановления подключения")

    model_config = {
        "validate_assignment": True,
        "extra": "ignore",
    }

    @field_validator("server_url")
    @classmethod
    def validate_server_url(cls, v: str) -> str:
        clean = v.strip()
        if not clean:
            raise ValueError("server_url не может быть пустым")
        if not (clean.startswith("http://") or clean.startswith("https://")):
            raise ValueError("server_url должен начинаться с http:// или https://")
        return clean.rstrip("/")

    @field_validator("poll_interval_sec")
    @classmethod
    def validate_poll_interval(cls, v: float) -> float:
        if v <= 0:
            raise ValueError("poll_interval_sec должен быть положительным числом (> 0)")
        return v

    @field_validator("request_timeout_sec")
    @classmethod
    def validate_request_timeout(cls, v: float) -> float:
        if v <= 0:
            raise ValueError("request_timeout_sec должен быть положительным числом (> 0)")
        return v

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        upper_v = v.strip().upper()
        if upper_v not in valid_levels:
            raise ValueError(f"Недопустимый уровень логирования: {v}. Разрешены: {sorted(valid_levels)}")
        return upper_v

    def to_dict(self) -> dict:
        """Экспорт настроек в стандартный словарь Python."""
        return self.model_dump()

    def to_json(self, indent: int = 4) -> str:
        """Сериализация настроек в форматированную JSON-строку."""
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    @classmethod
    def from_dict(cls, data: dict) -> "ClientConfig":
        """Создание экземпляра конфигурации из словаря с валидацией."""
        try:
            return cls.model_validate(data)
        except ValidationError as e:
            raise ConfigError(f"Ошибка валидации параметров конфигурации: {e}") from e

    @classmethod
    def from_json(cls, json_str: str) -> "ClientConfig":
        """Создание экземпляра конфигурации из JSON-строки с валидацией."""
        try:
            data = json.loads(json_str)
            return cls.from_dict(data)
        except json.JSONDecodeError as e:
            raise ConfigError(f"Ошибка синтаксиса JSON конфигурации: {e}") from e


DEFAULT_CONFIG_PATH = Path("config.json")


class ConfigManager:
    """
    Потокобезопасный менеджер конфигурации приложения.
    Обеспечивает чтение, запись, валидацию, сброс к умолчаниям, экспорт, импорт
    и оповещение подписанных слушателей об изменении конфигурации.
    """

    def __init__(self, config_path: Optional[Union[str, Path]] = None):
        self.config_path = Path(config_path) if config_path is not None else DEFAULT_CONFIG_PATH
        self._config: Optional[ClientConfig] = None
        self._lock = threading.RLock()
        self._callbacks: List[Callable[[ClientConfig], None]] = []

    def get_config(self) -> ClientConfig:
        """Возвращает текущую активную конфигурацию, загружая её при необходимости."""
        with self._lock:
            if self._config is None:
                return self.load_config()
            return self._config

    @property
    def config(self) -> ClientConfig:
        """Свойство доступа к текущей конфигурации."""
        return self.get_config()

    def load_config(self, fallback_on_error: bool = False) -> ClientConfig:
        """
        Загружает конфигурацию из файла config_path.
        Если файл отсутствует, создает его со значениями по умолчанию.
        При некорректном JSON либо выбрасывает ConfigError, либо откатывается к defaults
        (если fallback_on_error=True).
        """
        with self._lock:
            if not self.config_path.exists():
                logger.info(f"Конфигурационный файл {self.config_path} не найден. Создание с параметрами по умолчанию.")
                default_cfg = ClientConfig()
                self.save_config(default_cfg)
                self._config = default_cfg
                return self._config

            try:
                content = self.config_path.read_text(encoding="utf-8")
                cfg = ClientConfig.from_json(content)
                self._config = cfg
                logger.debug(f"Конфигурация успешно загружена из {self.config_path}")
                return self._config
            except (ConfigError, json.JSONDecodeError, ValidationError) as err:
                logger.warning(f"Ошибка при разборе файла конфигурации {self.config_path}: {err}")
                if fallback_on_error:
                    logger.info("Активирован откат к настройкам по умолчанию.")
                    self._config = ClientConfig()
                    return self._config
                raise ConfigError(f"Не удалось загрузить конфигурацию из {self.config_path}: {err}") from err

    def save_config(self, config: Optional[ClientConfig] = None) -> None:
        """
        Сохраняет конфигурацию в файл config_path и уведомляет зарегистрированные слушатели.
        """
        with self._lock:
            if config is not None:
                self._config = config
            elif self._config is None:
                self._config = ClientConfig()

            # Создание директории, если путь содержит каталоги
            if self.config_path.parent != Path("."):
                self.config_path.parent.mkdir(parents=True, exist_ok=True)

            json_text = self._config.to_json(indent=4)
            self.config_path.write_text(json_text, encoding="utf-8")
            logger.debug(f"Конфигурация сохранена в {self.config_path}")

            self._notify_change(self._config)

    def reset_defaults(self) -> ClientConfig:
        """
        Сбрасывает конфигурацию к эталонным значениям ТЗ, перезаписывает файл и возвращает модель.
        """
        with self._lock:
            default_cfg = ClientConfig()
            self.save_config(default_cfg)
            return default_cfg

    def export_config(self, path: Union[str, Path]) -> None:
        """
        Экспортирует текущую конфигурацию в указанный внешний файл.
        """
        target = Path(path)
        with self._lock:
            cfg = self.get_config()
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(cfg.to_json(indent=4), encoding="utf-8")
            logger.info(f"Конфигурация экспортирована в: {target}")

    def import_config(self, path: Union[str, Path]) -> ClientConfig:
        """
        Импортирует конфигурацию из указанного файла, валидирует её,
        устанавливает в качестве текущей, сохраняет в основной config_path
        и оповещает слушателей.
        """
        src = Path(path)
        if not src.is_file():
            raise FileNotFoundError(f"Файл для импорта конфигурации не найден: {src}")

        with self._lock:
            content = src.read_text(encoding="utf-8")
            cfg = ClientConfig.from_json(content)
            self.save_config(cfg)
            logger.info(f"Конфигурация успешно импортирована из: {src}")
            return cfg

    def add_change_listener(self, callback: Callable[[ClientConfig], None]) -> None:
        """Регистрация функции обратного вызова при изменении настроек."""
        with self._lock:
            if callback not in self._callbacks:
                self._callbacks.append(callback)

    def remove_change_listener(self, callback: Callable[[ClientConfig], None]) -> None:
        """Удаление зарегистрированной функции обратного вызова."""
        with self._lock:
            if callback in self._callbacks:
                self._callbacks.remove(callback)

    def _notify_change(self, config: ClientConfig) -> None:
        """Оповещение всех зарегистрированных подписчиков."""
        for cb in list(self._callbacks):
            try:
                cb(config)
            except Exception as err:
                logger.error(f"Ошибка в обработчике изменения конфигурации {cb}: {err}")
