"""
Модульные тесты асимметричных механизмов Bign (СТБ 34.101.45-2013).
Проверяют требования ПМИ:
  * П-01: Генерация ключевой пары bign;
  * П-04: Транспортирование сессионного ключа;
  * П-05: Формирование и проверка ЭЦП;
  * П-07: Обнаружение подмены открытого текста при проверке ЭЦП.
"""

from client.crypto.bign import BignCrypto, BignKeyPair
from client.crypto.belt import BeltCrypto


def test_bign_keypair_generation():
    """Тест П-01: Формирование асимметричной ключевой пары на эллиптических кривых."""
    kp = BignCrypto.generate_keypair()

    assert isinstance(kp, BignKeyPair)
    assert len(kp.private_key) == 32  # 256 бит
    assert len(kp.public_key) == 64   # 512 бит (координаты точки X, Y)
    assert len(kp.public_hex) == 128
    assert len(kp.private_hex) == 64


def test_bign_keytrans_roundtrip():
    """Тест П-04: Асимметричное транспортирование 256-битного ключа belt."""
    alice_kp = BignCrypto.generate_keypair()
    bob_kp = BignCrypto.generate_keypair()

    # Алиса вырабатывает сессионный ключ belt
    session_key = BeltCrypto.generate_key()

    # Алиса транспортирует ключ на открытом ключе Боба
    enc_key_package = BignCrypto.transport_key(session_key, bob_kp.public_key)
    assert len(enc_key_package) == 112
    assert enc_key_package != session_key

    # Боб извлекает сессионный ключ своим закрытым ключом
    extracted_key = BignCrypto.extract_key(enc_key_package, bob_kp.private_key)
    assert extracted_key == session_key


def test_bign_signature_success():
    """Тест П-05: Выработка и успешная верификация ЭЦП сообщения."""
    sender_kp = BignCrypto.generate_keypair()
    msg = "Документ с подтвержденной подлинностью по СТБ 34.101.45".encode("utf-8")

    sig = BignCrypto.sign(msg, sender_kp.private_key)
    assert len(sig) == 64  # 512 бит ЭЦП

    is_valid = BignCrypto.verify(msg, sig, sender_kp.public_key)
    assert is_valid is True


def test_bign_signature_tamper_detection():
    """Тест П-07: Обнаружение искажения открытого текста при верификации ЭЦП."""
    sender_kp = BignCrypto.generate_keypair()
    original_msg = b"Transfer 100 BYN to Alice"
    altered_msg = b"Transfer 900 BYN to Hacker"

    sig = BignCrypto.sign(original_msg, sender_kp.private_key)

    # Верификация на модифицированном тексте должна провалиться
    is_valid = BignCrypto.verify(altered_msg, sig, sender_kp.public_key)
    assert is_valid is False


def test_bign_signature_wrong_key():
    """Проверка ЭЦП на чужом открытом ключе должна возвращать False."""
    alice_kp = BignCrypto.generate_keypair()
    charlie_kp = BignCrypto.generate_keypair()
    msg = b"Signed by Alice"

    sig = BignCrypto.sign(msg, alice_kp.private_key)

    # Проверка ключом Чарли
    assert BignCrypto.verify(msg, sig, charlie_kp.public_key) is False
