"""
Модуль симметричного блочного шифрования и имитозащиты Belt (СТБ 34.101.31-2011).
Реализует требования:
  * Пункт 5.3: Режим аутентифицированного шифрования belt-che (AEAD);
  * Пункт 5.1: Длина сессионного ключа — 256 бит (32 байта);
  * Пункт 5.2: Длина синхропосылки (IV) — 128 бит (16 байт);
  * Пункт 5.4: Длина имитовставки (MAC) — 128 бит (16 байт).
"""

from typing import Tuple
from .bee2_wrapper import engine


class BeltIntegrityError(Exception):
    """Исключение, вызываемое при нарушении имитозащиты или подмене шифротекста."""
    pass


class BeltCrypto:
    """
    Класс управления операциями симметричного блочного шифрования belt (СТБ 34.101.31-2011).
    Предоставляет методы генерации одноразовых сессионных ключей, синхропосылок,
    а также процедур аутентифицированного шифрования и дешифрования.
    """

    KEY_SIZE_BYTES = 32   # 256 бит
    IV_SIZE_BYTES = 16    # 128 бит
    MAC_SIZE_BYTES = 16   # 128 бит

    @classmethod
    def generate_key(cls) -> bytes:
        """
        Генерирует криптографически стойкий одноразовый сессионный ключ 256 бит.
        Использует сертифицированный генератор псевдослучайных чисел Bee2.
        """
        return engine.prng_random(cls.KEY_SIZE_BYTES)

    @classmethod
    def generate_iv(cls) -> bytes:
        """
        Генерирует уникальную синхропосылку (вектор инициализации IV) 128 бит.
        Повторное использование синхропосылки с одним сессионным ключом строго запрещено.
        """
        return engine.prng_random(cls.IV_SIZE_BYTES)

    @classmethod
    def encrypt(cls, plaintext: bytes, key: bytes, iv: bytes | None = None) -> Tuple[bytes, bytes, bytes]:
        """
        Выполняет симметричное блочное шифрование с выработкой имитовставки (belt-che).
        
        Параметры:
          plaintext: открытые данные в виде байтов.
          key: 256-битный сессионный ключ belt.
          iv: (опционально) 128-битная синхропосылка. Если не передана, генерируется автоматически.

        Возвращает:
          (ciphertext, mac, iv): шифротекст, 128-битная имитовставка и использованный вектор IV.
        """
        if len(key) != cls.KEY_SIZE_BYTES:
            raise ValueError(f"Длина ключа belt должна быть {cls.KEY_SIZE_BYTES} байт (передано: {len(key)})")

        used_iv = iv if iv is not None else cls.generate_iv()
        if len(used_iv) != cls.IV_SIZE_BYTES:
            raise ValueError(f"Длина IV должна быть {cls.IV_SIZE_BYTES} байт (передано: {len(used_iv)})")

        ciphertext, mac = engine.belt_che_encrypt(plaintext, key, used_iv)
        return ciphertext, mac, used_iv

    @classmethod
    def decrypt(cls, ciphertext: bytes, mac: bytes, key: bytes, iv: bytes) -> bytes:
        """
        Выполняет дешифрование и проверку целостности данных (belt-che).

        Параметры:
          ciphertext: зашифрованное тело сообщения.
          mac: 128-битная имитовставка.
          key: 256-битный сессионный ключ belt.
          iv: 128-битная синхропосылка.

        Возвращает:
          Открытые данные (bytes).

        Исключения:
          BeltIntegrityError: если хотя бы 1 бит шифротекста или синхропосылки искажен.
        """
        if len(key) != cls.KEY_SIZE_BYTES:
            raise ValueError(f"Некорректная длина сессионного ключа belt: {len(key)}")
        if len(iv) != cls.IV_SIZE_BYTES:
            raise ValueError(f"Некорректная длина синхропосылки IV: {len(iv)}")
        if len(mac) != cls.MAC_SIZE_BYTES:
            raise ValueError(f"Некорректная длина имитовставки MAC: {len(mac)}")

        try:
            plaintext = engine.belt_che_decrypt(ciphertext, mac, key, iv)
            return plaintext
        except ValueError as exc:
            raise BeltIntegrityError(f"Ошибка проверки имитозащиты СТБ 34.101.31-2011: {exc}") from exc
