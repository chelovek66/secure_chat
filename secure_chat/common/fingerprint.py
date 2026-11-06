"""
Модуль сбора цифрового отпечатка устройства (Device Fingerprint) для «Secure Chat».
Вычисляет уникальный криптографический идентификатор устройства (SHA-256)
на основе аппаратных и системных параметров узла.
"""

import hashlib
import platform
import uuid
import sys
from typing import Dict, Any


def get_machine_guid() -> str:
    """
    Получает MachineGuid из системного реестра Windows
    (HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography\\MachineGuid).
    Для других платформ или при ошибке чтения используется устойчивый fallback.
    """
    if platform.system() == "Windows":
        try:
            import winreg
            # Сначала пробуем 64-битную ветку реестра
            try:
                with winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SOFTWARE\Microsoft\Cryptography",
                    0,
                    winreg.KEY_READ | getattr(winreg, "KEY_WOW64_64KEY", 0),
                ) as key:
                    guid, _ = winreg.QueryValueEx(key, "MachineGuid")
                    if guid:
                        return str(guid).strip()
            except Exception:
                pass

            # Обычное открытие ключа
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Cryptography",
            ) as key:
                guid, _ = winreg.QueryValueEx(key, "MachineGuid")
                if guid:
                    return str(guid).strip()
        except Exception:
            pass

    elif platform.system() == "Linux":
        for path in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    content = f.read().strip()
                    if content:
                        return content
            except Exception:
                pass

    # Безопасный fallback при отсутствии доступа к реестру/файлу
    node_part = hex(uuid.getnode())
    return f"fallback-guid-{platform.node()}-{node_part}"


def get_device_details() -> Dict[str, Any]:
    """
    Собирает детальные параметры устройства:
      * hostname: сетевое имя узла (platform.node())
      * platform: операционная система и релиз (platform.system() + ' ' + platform.release())
      * mac: MAC-адрес первичного сетевого интерфейса (hex(uuid.getnode()))
      * machine_id: идентификатор ОС (Windows MachineGuid или fallback)
      * raw_string: склеенная строка параметров: hostname|platform|mac|machine_id
      * device_id: итоговый SHA-256 хэш (hex)
    """
    hostname = platform.node()
    platform_info = f"{platform.system()} {platform.release()}"
    mac = hex(uuid.getnode())
    machine_id = get_machine_guid()

    raw_string = f"{hostname}|{platform_info}|{mac}|{machine_id}"
    device_id = hashlib.sha256(raw_string.encode("utf-8")).hexdigest()

    return {
        "hostname": hostname,
        "platform": platform_info,
        "mac": mac,
        "machine_id": machine_id,
        "raw_string": raw_string,
        "device_id": device_id,
    }


def get_device_fingerprint() -> str:
    """
    Вычисляет криптографический отпечаток текущего устройства (Device Fingerprint).
    Возвращает 64-символьную строку SHA-256 (hex) от комбинации параметров:
    hostname|platform|mac|machine_id
    """
    details = get_device_details()
    return details["device_id"]
