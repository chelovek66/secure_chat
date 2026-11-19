"""
Фаззинг-тесты на базе фреймворка Hypothesis (property-based testing).
Проверяют устойчивость криптографических парсеров, декодеров и сетевых моделей
к случайным, мутированным и экстремальным входным данным.
"""

import json
import pytest
from hypothesis import given, settings, strategies as st

from common.update_crypto import validate_cyclonedx_sbom, canonicalize_manifest
from client.crypto.bee2_wrapper import engine
from client.crypto.hybrid import HybridPayload, HybridCrypto
from client.crypto.belt import BeltCrypto, BeltIntegrityError
from server.models import UserRegisterRequest, UserLoginRequest


@settings(max_examples=50, deadline=1000)
@given(st.binary(min_size=0, max_size=1024))
def test_hypothesis_fuzz_sbom_validator_never_crashes(raw_bytes: bytes):
    """Фаззинг парсера SBOM CycloneDX произвольными бинарными данными."""
    try:
        text = raw_bytes.decode("utf-8", errors="ignore")
        data = json.loads(text)
        if isinstance(data, dict):
            validate_cyclonedx_sbom(data)
    except (ValueError, KeyError, TypeError, json.JSONDecodeError, UnicodeDecodeError):
        # Ожидаемый отказ при некорректном формате
        pass


@settings(max_examples=50, deadline=1000)
@given(st.dictionaries(keys=st.text(max_size=32), values=st.text(max_size=64), max_size=10))
def test_hypothesis_fuzz_manifest_canonicalizer(manifest_dict: dict):
    """Фаззинг канонизатора манифестов произвольными JSON-структурами."""
    try:
        canonical_bytes = canonicalize_manifest(manifest_dict)
        assert isinstance(canonical_bytes, bytes)
    except (ValueError, TypeError):
        pass


@settings(max_examples=50, deadline=1000)
@given(
    key=st.binary(min_size=0, max_size=64),
    iv=st.binary(min_size=0, max_size=32),
    ciphertext=st.binary(min_size=0, max_size=256),
    mac=st.binary(min_size=0, max_size=32),
)
def test_hypothesis_fuzz_belt_che_decrypt(key: bytes, iv: bytes, ciphertext: bytes, mac: bytes):
    """Фаззинг симметричного дешифратора belt-che некорректными ключами и MAC."""
    try:
        BeltCrypto.decrypt(ciphertext, mac, key, iv)
    except (ValueError, BeltIntegrityError):
        pass


@settings(max_examples=50, deadline=1000)
@given(raw_container=st.binary(min_size=0, max_size=256), pwd=st.text(max_size=64))
def test_hypothesis_fuzz_bkey_unwrap(raw_container: bytes, pwd: str):
    """Фаззинг снятия защиты контейнеров ключей bkey произвольными байтами."""
    try:
        engine.bkey_unwrap(raw_container, pwd)
    except (ValueError, KeyError, TypeError):
        pass


@settings(max_examples=50, deadline=1000)
@given(
    user_id=st.text(max_size=128),
    password=st.text(max_size=128),
    pubkey=st.text(max_size=256),
)
def test_hypothesis_fuzz_request_models(user_id: str, password: str, pubkey: str):
    """Фаззинг Pydantic-моделей регистрации и входа произвольными UTF-8 строками."""
    try:
        UserRegisterRequest.model_validate({"user_id": user_id, "password": password, "public_key": pubkey})
    except Exception:
        pass

    try:
        UserLoginRequest.model_validate({"user_id": user_id, "password": password})
    except Exception:
        pass
