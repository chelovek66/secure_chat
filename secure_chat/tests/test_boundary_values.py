"""
Тесты краевых и граничных значений для защищенного мессенджера «Secure Chat».
Практическая работа «Тестирование разрабатываемого ПО».

Набор тестов:
  * test_username_boundary_lengths: проверка длин логина
      (0 - недопустимо, 1 - недопустимо, 2 - минимальная граница, 32/64 - допустимо, 65+ - превышение);
  * test_password_boundary_lengths: пустой пароль (0 - отказ), 1 символ, 7 символов,
      8 символов (граница стойкости), длинный пароль (128 символов);
  * test_message_payload_boundaries: 1 байт, 1 КБ, 64 КБ, пустая строка;
  * test_config_poll_interval_boundaries: проверка границ периода опроса в ClientConfig (0.2 мин, 60.0 макс);
  * test_config_timeout_boundaries: проверка границ таймаута (1.0 мин, 120.0 макс).
"""

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from server.app import app
from server.database import DatabaseManager, hash_password_pbkdf2, verify_password_pbkdf2
from server.models import RegisterRequest, UserRegisterRequest, UserLoginRequest, SendMessageRequest
from server.storage import storage
from client.crypto.belt import BeltCrypto
from client.crypto.bign import BignCrypto
from client.crypto.hybrid import HybridCrypto
from client.gui.auth_dialog import AuthDialog
from common.config_manager import ClientConfig


@pytest.fixture
def temp_db(tmp_path):
    """Изолированная тестовая база данных SQLite и чистое состояние хранилища."""
    orig_db = storage.db
    db_file = str(tmp_path / "test_boundary.db")
    db = DatabaseManager(db_path=db_file, enabled=True)
    storage.db = db
    storage.reset()
    yield db
    storage.reset()
    storage.db = orig_db


@pytest.fixture
def test_client(temp_db):
    """Автономный клиент FastAPI TestClient с изолированной БД."""
    with TestClient(app) as client:
        yield client


# ============================================================================
# 1. ТЕСТ: Граничные значения длины имени пользователя (логина)
# ============================================================================


def test_username_boundary_lengths(test_client):
    """
    Тест граничных значений длины логина:
      - 0 символов: недопустимо (пустая строка);
      - 1 символ: недопустимо (ниже минимальной границы);
      - 2 символа: допустимо (минимальная граница длины);
      - 32 символа: допустимо (типовая средняя длина);
      - 64 символа: допустимо (максимальная верхняя граница);
      - 65+ символов: недопустимо (превышение допустимого лимита в 64 символа).
    """
    kp = BignCrypto.generate_keypair()
    pwd = "ValidPassword_2026!"

    # 1. Длина 0: пустой логин недопустим
    with pytest.raises(ValidationError):
        UserRegisterRequest(login="", password=pwd, public_key=kp.public_hex)

    resp_0 = test_client.post(
        "/register",
        json={"login": "", "password": pwd, "public_key": kp.public_hex},
    )
    assert resp_0.status_code == 422, "Пустой логин (0 символов) должен отклоняться с кодом 422"

    # 2. Длина 1: логин из 1 символа недопустим (требуется >= 2 символов)
    with pytest.raises(ValidationError):
        UserRegisterRequest(login="u", password=pwd, public_key=kp.public_hex)

    resp_1 = test_client.post(
        "/register",
        json={"login": "u", "password": pwd, "public_key": kp.public_hex},
    )
    assert resp_1.status_code == 422, "Логин из 1 символа должен отклоняться с кодом 422"

    # 3. Длина 2: минимальная допустимая граница
    req_2 = UserRegisterRequest(login="ab", password=pwd, public_key=kp.public_hex)
    assert req_2.get_user_id() == "ab"

    resp_2 = test_client.post(
        "/register",
        json={"login": "ab", "password": pwd, "public_key": kp.public_hex},
    )
    assert resp_2.status_code == 200, "Логин из 2 символов должен успешно регистрироваться"
    assert resp_2.json()["success"] is True

    # 4. Длина 32: допустимая граница
    user_32 = "a" * 32
    req_32 = UserRegisterRequest(login=user_32, password=pwd, public_key=kp.public_hex)
    assert len(req_32.get_user_id()) == 32

    resp_32 = test_client.post(
        "/register",
        json={"login": user_32, "password": pwd, "public_key": kp.public_hex},
    )
    assert resp_32.status_code == 200, "Логин из 32 символов должен приниматься сервером"

    # 5. Длина 64: максимальная верхняя граница
    user_64 = "b" * 64
    req_64 = UserRegisterRequest(login=user_64, password=pwd, public_key=kp.public_hex)
    assert len(req_64.get_user_id()) == 64

    resp_64 = test_client.post(
        "/register",
        json={"login": user_64, "password": pwd, "public_key": kp.public_hex},
    )
    assert resp_64.status_code == 200, "Логин из 64 символов должен успешно регистрироваться"

    # 6. Длина 65 (и более): превышение максимальной границы 64 символа
    user_65 = "c" * 65
    with pytest.raises(ValidationError):
        UserRegisterRequest(login=user_65, password=pwd, public_key=kp.public_hex)

    with pytest.raises(ValidationError):
        RegisterRequest(login=user_65, public_key=kp.public_hex)

    resp_65 = test_client.post(
        "/register",
        json={"login": user_65, "password": pwd, "public_key": kp.public_hex},
    )
    assert resp_65.status_code == 422, "Логин длиной 65 символов должен отклоняться сервером с кодом 422"


# ============================================================================
# 2. ТЕСТ: Граничные значения длины пароля и критерии стойкости
# ============================================================================


def test_password_boundary_lengths(test_client):
    """
    Тест граничных значений длины пароля:
      - 0 символов (пустой пароль): отказ;
      - 1 символ: отказ при регистрации (минимум 3 символа по модели, слабый по шкале);
      - 7 символов: принимается моделью (>= 3), но классифицируется как слабый (< 8);
      - 8 символов: граница криптостойкости (>= 8, регистры и цифры -> средний/надежный);
      - 128 символов: допустимый длинный пароль (верхний предел Pydantic-модели);
      - 129+ символов: отказ (превышение максимальной длины 128 символов).
    """
    kp = BignCrypto.generate_keypair()

    # 1. Длина 0: пустой пароль
    with pytest.raises(ValidationError):
        UserRegisterRequest(login="test_user_p0", password="", public_key=kp.public_hex)
    with pytest.raises(ValidationError):
        UserLoginRequest(login="test_user_p0", password="")

    pct_0, status_0, _, _ = AuthDialog._evaluate_password_strength(None, "")
    assert pct_0 == 0
    assert status_0 == "—"

    # 2. Длина 1: 1 символ
    with pytest.raises(ValidationError):
        UserRegisterRequest(login="test_user_p1", password="x", public_key=kp.public_hex)

    pct_1, status_1, _, _ = AuthDialog._evaluate_password_strength(None, "x")
    assert status_1 == "Слабый"
    assert pct_1 == 30

    # 3. Длина 7: ниже границы стойкости 8 символов
    pwd_7 = "Pass123"  # 7 символов (буквы верхнего/нижнего регистра и цифры)
    req_7 = UserRegisterRequest(login="user_len_7", password=pwd_7, public_key=kp.public_hex)
    assert req_7.password == pwd_7

    pct_7, status_7, _, _ = AuthDialog._evaluate_password_strength(None, pwd_7)
    assert status_7 == "Слабый", "Пароль длиной 7 символов должен классифицироваться как слабый"

    # 4. Длина 8: граница криптостойкости (8 символов)
    pwd_8 = "Pass1234"  # 8 символов
    req_8 = UserRegisterRequest(login="user_len_8", password=pwd_8, public_key=kp.public_hex)
    assert len(req_8.password) == 8

    pct_8, status_8, _, _ = AuthDialog._evaluate_password_strength(None, pwd_8)
    assert status_8 in ("Средний", "Надежный"), "Пароль от 8 символов с разным регистром и цифрами преодолевает порог стойкости"
    assert pct_8 >= 70

    # Проверка регистрации и хэширования 8-символьного пароля
    resp_8 = test_client.post(
        "/register",
        json={"login": "user_len_8", "password": pwd_8, "public_key": kp.public_hex},
    )
    assert resp_8.status_code == 200

    # 5. Длина 128: максимальная верхняя граница для пароля
    pwd_128 = "A" * 125 + "1!b"  # 128 символов
    req_128 = UserRegisterRequest(login="user_len_128", password=pwd_128, public_key=kp.public_hex)
    assert len(req_128.password) == 128

    resp_128 = test_client.post(
        "/register",
        json={"login": "user_len_128", "password": pwd_128, "public_key": kp.public_hex},
    )
    assert resp_128.status_code == 200
    assert resp_128.json()["success"] is True

    # Проверка хэширования PBKDF2 для длинного 128-символьного пароля
    digest, salt = hash_password_pbkdf2(pwd_128)
    assert verify_password_pbkdf2(pwd_128, salt, digest) is True
    assert verify_password_pbkdf2(pwd_128 + "x", salt, digest) is False

    # 6. Длина 129+: превышение максимальной границы длины пароля
    pwd_129 = "A" * 129
    with pytest.raises(ValidationError):
        UserRegisterRequest(login="user_len_129", password=pwd_129, public_key=kp.public_hex)

    with pytest.raises(ValidationError):
        UserLoginRequest(login="user_len_129", password=pwd_129)


# ============================================================================
# 3. ТЕСТ: Граничные размеры передаваемых сообщений (Message Payload)
# ============================================================================


def test_message_payload_boundaries():
    """
    Тест граничных размеров полезной нагрузки сообщений:
      - 1 байт: минимальный одиночный байт;
      - 1 КБ (1024 байта): стандартный объем пакета;
      - 64 КБ (65536 байтов): максимальный размер блока;
      - пустая строка (0 байтов): обработка пустого сообщения на уровне криптодвижка и сетевой модели.
    """
    key = BeltCrypto.generate_key()
    alice_kp = BignCrypto.generate_keypair()
    bob_kp = BignCrypto.generate_keypair()

    # 1. Граница: 1 байт
    payload_1b = b"X"
    ct_1b, mac_1b, iv_1b = BeltCrypto.encrypt(payload_1b, key)
    assert len(ct_1b) == 1
    assert len(mac_1b) == 16
    assert len(iv_1b) == 16
    assert BeltCrypto.decrypt(ct_1b, mac_1b, key, iv_1b) == payload_1b

    hyp_1b, sig_1b = HybridCrypto.encrypt_message("X", bob_kp.public_key, alice_kp.private_key)
    dec_1b, sig_ok_1b = HybridCrypto.decrypt_message(hyp_1b, bob_kp.private_key, alice_kp.public_key, sig_1b)
    assert dec_1b == "X"
    assert sig_ok_1b is True

    # 2. Граница: 1 КБ (1024 байта)
    payload_1kb = b"A" * 1024
    ct_1kb, mac_1kb, iv_1kb = BeltCrypto.encrypt(payload_1kb, key)
    assert len(ct_1kb) == 1024
    assert BeltCrypto.decrypt(ct_1kb, mac_1kb, key, iv_1kb) == payload_1kb

    str_1kb = "K" * 1024
    hyp_1kb, sig_1kb = HybridCrypto.encrypt_message(str_1kb, bob_kp.public_key, alice_kp.private_key)
    dec_1kb, sig_ok_1kb = HybridCrypto.decrypt_message(hyp_1kb, bob_kp.private_key, alice_kp.public_key, sig_1kb)
    assert dec_1kb == str_1kb
    assert sig_ok_1kb is True

    # 3. Граница: 64 КБ (65 536 байтов)
    payload_64kb = b"Z" * 65536
    ct_64kb, mac_64kb, iv_64kb = BeltCrypto.encrypt(payload_64kb, key)
    assert len(ct_64kb) == 65536
    assert BeltCrypto.decrypt(ct_64kb, mac_64kb, key, iv_64kb) == payload_64kb

    str_64kb = "M" * 65536
    hyp_64kb, sig_64kb = HybridCrypto.encrypt_message(str_64kb, bob_kp.public_key, alice_kp.private_key)
    dec_64kb, sig_ok_64kb = HybridCrypto.decrypt_message(hyp_64kb, bob_kp.private_key, alice_kp.public_key, sig_64kb)
    assert dec_64kb == str_64kb
    assert sig_ok_64kb is True

    # 4. Граница: пустая строка (0 байтов)
    # На уровне криптодвижка belt-che пустые данные шифруются с корректной имитовставкой
    ct_0, mac_0, iv_0 = BeltCrypto.encrypt(b"", key)
    assert len(ct_0) == 0
    assert len(mac_0) == 16
    assert len(iv_0) == 16
    assert BeltCrypto.decrypt(ct_0, mac_0, key, iv_0) == b""

    hyp_0, sig_0 = HybridCrypto.encrypt_message("", bob_kp.public_key, alice_kp.private_key)
    dec_0, sig_ok_0 = HybridCrypto.decrypt_message(hyp_0, bob_kp.private_key, alice_kp.public_key, sig_0)
    assert dec_0 == ""
    assert sig_ok_0 is True

    # На сетевом уровне (REST API) пустой шифротекст запрещен валидатором модели SendMessageRequest
    with pytest.raises(ValidationError):
        SendMessageRequest(
            from_id="alice",
            to_id="bob",
            ciphertext="",  # Недопустима пустая строка min_length=1
            nonce="bm9uY2U=",
            mac="bWFjMTIzNDU2Nzg5MDEy",
            encrypted_key="ZW5jX2tleQ==",
            signature="c2lnbmF0dXJl",
        )


# ============================================================================
# 4. ТЕСТ: Границы периода опроса poll_interval_sec в ClientConfig
# ============================================================================


def test_config_poll_interval_boundaries():
    """
    Тест граничных значений периода опроса poll_interval_sec в ClientConfig:
      - Минимальная граница: 0.2 секунды;
      - Максимальная граница: 60.0 секунд;
      - Значения ниже минимума (0.19, 0.0, -1.0): вызывают ошибку валидации;
      - Значения выше максимума (60.01, 100.0): вызывают ошибку валидации;
      - Динамическое присвоение свойства проверяется на валидацию.
    """
    # 1. Минимальная граница: 0.2 сек
    cfg_min = ClientConfig(poll_interval_sec=0.2)
    assert cfg_min.poll_interval_sec == 0.2

    # 2. Максимальная граница: 60.0 сек
    cfg_max = ClientConfig(poll_interval_sec=60.0)
    assert cfg_max.poll_interval_sec == 60.0

    # 3. Значения ниже минимальной границы (0.19, 0.0, отрицательные)
    with pytest.raises(ValidationError):
        ClientConfig(poll_interval_sec=0.19)

    with pytest.raises(ValidationError):
        ClientConfig(poll_interval_sec=0.0)

    with pytest.raises(ValidationError):
        ClientConfig(poll_interval_sec=-1.0)

    # 4. Значения выше максимальной границы (60.01, 100.0)
    with pytest.raises(ValidationError):
        ClientConfig(poll_interval_sec=60.01)

    with pytest.raises(ValidationError):
        ClientConfig(poll_interval_sec=100.0)

    # 5. Проверка изменения значения на существующем объекте
    cfg = ClientConfig()
    cfg.poll_interval_sec = 0.2
    assert cfg.poll_interval_sec == 0.2

    cfg.poll_interval_sec = 60.0
    assert cfg.poll_interval_sec == 60.0

    with pytest.raises(ValidationError):
        cfg.poll_interval_sec = 0.1

    with pytest.raises(ValidationError):
        cfg.poll_interval_sec = 65.0


# ============================================================================
# 5. ТЕСТ: Границы сетевого таймаута request_timeout_sec в ClientConfig
# ============================================================================


def test_config_timeout_boundaries():
    """
    Тест граничных значений сетевого таймаута request_timeout_sec в ClientConfig:
      - Минимальная граница: 1.0 секунда;
      - Максимальная граница: 120.0 секунд;
      - Значения ниже минимума (0.99, 0.0, -5.0): вызывают ошибку валидации;
      - Значения выше максимума (120.01, 300.0): вызывают ошибку валидации;
      - Динамическое присвоение свойства проверяется на валидацию.
    """
    # 1. Минимальная граница: 1.0 сек
    cfg_min = ClientConfig(request_timeout_sec=1.0)
    assert cfg_min.request_timeout_sec == 1.0

    # 2. Максимальная граница: 120.0 сек
    cfg_max = ClientConfig(request_timeout_sec=120.0)
    assert cfg_max.request_timeout_sec == 120.0

    # 3. Значения ниже минимальной границы (0.99, 0.0, отрицательные)
    with pytest.raises(ValidationError):
        ClientConfig(request_timeout_sec=0.99)

    with pytest.raises(ValidationError):
        ClientConfig(request_timeout_sec=0.0)

    with pytest.raises(ValidationError):
        ClientConfig(request_timeout_sec=-5.0)

    # 4. Значения выше максимальной границы (120.01, 300.0)
    with pytest.raises(ValidationError):
        ClientConfig(request_timeout_sec=120.01)

    with pytest.raises(ValidationError):
        ClientConfig(request_timeout_sec=300.0)

    # 5. Проверка изменения значения на существующем объекте
    cfg = ClientConfig()
    cfg.request_timeout_sec = 1.0
    assert cfg.request_timeout_sec == 1.0

    cfg.request_timeout_sec = 120.0
    assert cfg.request_timeout_sec == 120.0

    with pytest.raises(ValidationError):
        cfg.request_timeout_sec = 0.5

    with pytest.raises(ValidationError):
        cfg.request_timeout_sec = 150.0
