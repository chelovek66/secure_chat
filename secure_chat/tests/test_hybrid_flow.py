"""
Сквозные интеграционные тесты гибридного криптографического конвейера и KeyStore.
Проверяют требования ПМИ:
  * П-01: Создание файлов открытого и закрытого ключей;
  * П-02: Защита закрытого ключа паролем (belt-kwp);
  * П-04: Полный цикл гибридного шифрования E2EE.
"""

from client.crypto.bign import BignCrypto
from client.crypto.hybrid import HybridCrypto
from client.crypto.keystore import KeyStore, KeyStoreError


def test_keystore_save_and_load_without_password(tmp_path):
    """Тест П-01: Генерация и загрузка ключевой пары без пароля."""
    kp = BignCrypto.generate_keypair()
    pub_file, priv_file = KeyStore.save_keys(tmp_path, kp, password=None)

    assert pub_file.is_file()
    assert priv_file.is_file()

    loaded_kp = KeyStore.load_keys(tmp_path, password=None)
    assert loaded_kp.public_key == kp.public_key
    assert loaded_kp.private_key == kp.private_key


def test_keystore_save_and_load_with_password(tmp_path):
    """Тест П-02: Защита личного ключа паролем (bkey / belt-kwp)."""
    kp = BignCrypto.generate_keypair()
    password = "SuperSecretPassword123!"

    pub_file, priv_file = KeyStore.save_keys(tmp_path, kp, password=password)
    assert pub_file.is_file()
    assert priv_file.is_file()

    # Попытка чтения без пароля должна вызывать KeyStoreError
    import pytest
    with pytest.raises(KeyStoreError):
        KeyStore.load_private_key(tmp_path, password=None)

    # Попытка чтения с неверным паролем должна вызывать KeyStoreError
    with pytest.raises(KeyStoreError):
        KeyStore.load_private_key(tmp_path, password="WrongPassword")

    # Чтение с правильным паролем проходит успешно
    loaded_priv = KeyStore.load_private_key(tmp_path, password=password)
    assert loaded_priv == kp.private_key


def test_hybrid_crypto_full_e2ee_flow():
    """Тест П-04: Полный сквозной цикл шифрования сообщения от Алисы к Бобу."""
    alice_kp = BignCrypto.generate_keypair()
    bob_kp = BignCrypto.generate_keypair()

    message_text = "Конфиденциальное сообщение для Боба: подтверждение транзакции №789"

    # 1. Алиса шифрует и подписывает сообщение
    payload, signature = HybridCrypto.encrypt_message(
        plaintext=message_text,
        recipient_pubkey=bob_kp.public_key,
        sender_privkey=alice_kp.private_key,
    )

    # 2. Сериализация в Base64 (имитация передачи по сети)
    b64_dict = payload.to_dict_b64()

    # 3. Боб принимает пакет и восстанавливает объект полезной нагрузки
    from client.crypto.hybrid import HybridPayload
    received_payload = HybridPayload.from_dict_b64(b64_dict)

    # 4. Боб расшифровывает сообщение и проверяет ЭЦП Алисы
    decrypted_text, is_valid_sig = HybridCrypto.decrypt_message(
        payload=received_payload,
        recipient_privkey=bob_kp.private_key,
        sender_pubkey=alice_kp.public_key,
        signature=signature,
    )

    assert decrypted_text == message_text
    assert is_valid_sig is True
