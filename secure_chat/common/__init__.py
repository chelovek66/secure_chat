"""
Общие модули и компоненты программного комплекса «Secure Chat».
Включает управление конфигурацией, данные сборки и контроль целостности ПО.
"""

from .config_manager import ClientConfig, ConfigManager, ConfigError
from .build_info import BuildInfo, get_build_info, generate_build_metadata, format_build_summary
from .logger import LogEntry, LogService, log_service

__all__ = [
    "ClientConfig",
    "ConfigManager",
    "ConfigError",
    "BuildInfo",
    "get_build_info",
    "generate_build_metadata",
    "format_build_summary",
    "LogEntry",
    "LogService",
    "log_service",
]
