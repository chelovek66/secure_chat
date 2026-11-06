"""
Модульные тесты симметричного блочного шифрования и имитозащиты Belt (СТБ 34.101.31-2011).
Проверяют требования ПМИ:
  * П-04: Корректность симметричного шифрования и дешифрования;
  * П-06: Обнаружение искажения шифротекста и срабатывание имитозащиты.
"""

import pytest
from client.crypto.belt import BeltCrypto, BeltIntegrityError


def test_belt_key_and_iv_generation():
    """Проверка генерации 256-битного ключа и 128-битного вектора IV."""
    key = BeltCrypto.generate_key()
    iv = BeltCrypto.generate_iv()

    assert isinstance(key, bytes)
    assert len(key) == 32  # 256 бит
    assert isinstance(iv, bytes)
    assert len(iv) == 16   # 128 бит
    # Проверка уникальности
    assert BeltCrypto.generate_key() != key
    assert BeltCrypto.generate_iv() != iv


def test_belt_che_encryption_decryption_roundtrip():
    """Тест полного цикла шифрования и расшифрования открытого текста."""
    key = BeltCrypto.generate_key()
    original_data = "Тестовое конфиденциальное сообщение согласно СТБ 34.101.31-2011!".encode("utf-8")

    ciphertext, mac, iv = BeltCrypto.encrypt(original_data, key)

    assert len(ciphertext) == len(original_data)
    assert len(mac) == 16  # 128-битная имитовставка
    assert len(iv) == 16
    assert ciphertext != original_data

    decrypted = BeltCrypto.decrypt(ciphertext, mac, key, iv)
    assert decrypted == original_data


def test_belt_che_tamper_detection_ciphertext():
    """Тест П-06: Модификация хотя бы одного байта шифротекста вызывает ошибку имитозащиты."""
    key = BeltCrypto.generate_key()
    data = b"Secret payload to be protected"

    ciphertext, mac, iv = BeltCrypto.encrypt(data, key)

    # Искажаем 1 байт шифротекста
    corrupted_ciphertext = bytearray(ciphertext)
    corrupted_ciphertext[0] ^= 0x01

    with pytest.raises(BeltIntegrityError):
        BeltCrypto.decrypt(bytes(corrupted_ciphertext), mac, key, iv)


def test_belt_che_tamper_detection_mac():
    """Искажение имитовставки должно блокировать дешифрование."""
    key = BeltCrypto.generate_key()
    data = b"Authentic payload"

    ciphertext, mac, iv = BeltCrypto.encrypt(data, key)

    corrupted_mac = bytearray(mac)
    corrupted_mac[0] ^= 0xFF

    with pytest.raises(BeltIntegrityError):
        BeltCrypto.decrypt(ciphertext, bytes(corrupted_mac), key, iv)


def test_belt_che_wrong_key():
    """Попытка расшифрования на чужом ключе вызывает ошибку имитозащиты."""
    key1 = BeltCrypto.generate_key()
    key2 = BeltCrypto.generate_key()
    data = b"Secure transmission"

    ciphertext, mac, iv = BeltCrypto.encrypt(data, key1)

    with pytest.raises(BeltIntegrityError):
        BeltCrypto.decrypt(ciphertext, mac, key2, iv)
