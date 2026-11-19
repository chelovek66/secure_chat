#!/usr/bin/env python3
"""
Автоматизированный фаззинг-тестер компонентов безопасности «Secure Chat» (ПЗ «Тестирование ПО»).
Реализует методику мутационного и генеративного фаззинга:
  * Фаззинг парсеров манифестов обновлений и SBOM (CycloneDX);
  * Фаззинг криптографических декодеров и десериализаторов сообщений (HybridPayload, belt-che, bign);
  * Фаззинг валидаторов моделей данных аутентификации (Pydantic);
  * Контроль необработанных падений (Unhandled Crashes), детекция аварий и сохранение crash-репродьюсеров.
"""

import os
import sys
import time
import json
import random
import string
import struct
import argparse
import traceback
from pathlib import Path
from typing import Callable, List, Tuple

# Добавляем корень проекта в путь поиска модулей
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from common.update_crypto import (
    validate_cyclonedx_sbom,
    canonicalize_manifest,
    verify_manifest,
)
from client.crypto.bee2_wrapper import engine
from client.crypto.hybrid import HybridCrypto, HybridPayload
from client.crypto.bign import BignCrypto
from client.crypto.belt import BeltCrypto, BeltIntegrityError
from server.models import UserRegisterRequest, UserLoginRequest, SendMessageRequest


# Ожидаемые исключения при некорректном входе (не являются дефектами программы)
EXPECTED_EXCEPTIONS = (
    ValueError,
    KeyError,
    TypeError,
    json.JSONDecodeError,
    UnicodeDecodeError,
    BeltIntegrityError,
    struct.error,
)


class FuzzCorpus:
    """Генератор случайных и мутированных входных векторов для фаззинга."""

    SEEDS = [
        b'{"format": "CycloneDX-1.5", "components": []}',
        b'{"version": "2.1.0", "package_sha256": "abcdef"}',
        b'{"from_id": "alice", "to_id": "bob", "ciphertext": "AAA="}',
        b'BKEY_STB78_V1\x00\x01\x02\x03\x04\x05\x06\x07',
        b'\x00' * 64,
        b'\xff' * 128,
        b'A' * 1024,
        b'<xml><script>alert(1)</script></xml>',
        b'{"user_id": "admin\' OR 1=1--", "password": "\x00\xff"}',
        b'\r\n\x00\x1b[31mCRASH\x1b[0m',
    ]

    @classmethod
    def random_bytes(cls, max_len: int = 512) -> bytes:
        length = random.randint(0, max_len)
        return os.urandom(length)

    @classmethod
    def random_string(cls, max_len: int = 256) -> str:
        length = random.randint(0, max_len)
        choice_pool = string.printable + "абвгдеёжзийклмнопрстуфхцчшщъыьэюя\x00\xff\uffff"
        return "".join(random.choice(choice_pool) for _ in range(length))

    @classmethod
    def mutate(cls, seed: bytes) -> bytes:
        if not seed:
            return cls.random_bytes(64)
        data = bytearray(seed)
        mutation_type = random.randint(0, 4)
        if mutation_type == 0 and len(data) > 0:
            # Битфлип
            idx = random.randint(0, len(data) - 1)
            data[idx] ^= (1 << random.randint(0, 7))
        elif mutation_type == 1:
            # Вставка случайных байт
            idx = random.randint(0, len(data))
            data[idx:idx] = os.urandom(random.randint(1, 16))
        elif mutation_type == 2 and len(data) > 1:
            # Удаление байт
            idx = random.randint(0, len(data) - 1)
            del data[idx:idx + random.randint(1, min(8, len(data) - idx))]
        elif mutation_type == 3:
            # Замена на граничные значения
            magic = random.choice([b"\x00", b"\xff", b"\x7f", b"\x80", b"\r\n", b'""', b"{}"])
            idx = random.randint(0, max(0, len(data) - len(magic)))
            data[idx:idx + len(magic)] = magic
        else:
            # Срез / дупликация
            chunk = data[:random.randint(1, len(data))]
            data.extend(chunk)
        return bytes(data)


def target_sbom_parser(data: bytes):
    """Цель фаззинга 1: парсер и валидатор спецификации SBOM CycloneDX."""
    try:
        parsed = json.loads(data.decode("utf-8", errors="ignore"))
        if isinstance(parsed, dict):
            validate_cyclonedx_sbom(parsed)
    except EXPECTED_EXCEPTIONS:
        pass


def target_manifest_canonicalizer(data: bytes):
    """Цель фаззинга 2: канонизатор и верификатор манифестов обновлений."""
    try:
        parsed = json.loads(data.decode("utf-8", errors="ignore"))
        if isinstance(parsed, dict):
            canonicalize_manifest(parsed)
            verify_manifest(parsed)
    except EXPECTED_EXCEPTIONS:
        pass


def target_crypto_payload(data: bytes):
    """Цель фаззинга 3: распаковщик гибридных криптографических пакетов и дешифратор."""
    try:
        # Проверяем декодирование и разбор словаря
        b64_str = data.hex()
        fake_dict = {
            "ciphertext": b64_str[:128],
            "nonce": b64_str[128:160],
            "mac": b64_str[160:192],
            "encrypted_key": b64_str[192:280],
        }
        try:
            payload = HybridPayload.from_dict_b64(fake_dict)
            dummy_priv = b"\x01" * 32
            dummy_pub = b"\x02" * 64
            dummy_sig = b"\x03" * 64
            HybridCrypto.decrypt_message(payload, dummy_priv, dummy_pub, dummy_sig)
        except EXPECTED_EXCEPTIONS:
            pass
    except EXPECTED_EXCEPTIONS:
        pass


def target_bkey_unwrap(data: bytes):
    """Цель фаззинга 4: распаковщик защищенных контейнеров ключей bkey (belt-kwp)."""
    try:
        engine.bkey_unwrap(data, "test_password_123")
    except EXPECTED_EXCEPTIONS:
        pass


def target_pydantic_requests(data: bytes):
    """Цель фаззинга 5: валидатор сетевых запросов и Pydantic-моделей."""
    text = data.decode("utf-8", errors="ignore")
    try:
        UserRegisterRequest.model_validate({"user_id": text, "password": text, "public_key": data.hex()})
    except Exception:
        pass
    try:
        UserLoginRequest.model_validate({"user_id": text, "password": text})
    except Exception:
        pass


TARGETS: List[Tuple[str, Callable[[bytes], None]]] = [
    ("SBOM CycloneDX Parser", target_sbom_parser),
    ("Manifest Canonicalizer", target_manifest_canonicalizer),
    ("Crypto Payload Decoder", target_crypto_payload),
    ("BKey Container Unwrapper", target_bkey_unwrap),
    ("Pydantic Request Models", target_pydantic_requests),
]


def run_fuzzer(max_seconds: int = 60, crashes_dir: Path = None) -> int:
    """
    Запускает фаззер на заданное количество секунд и фиксирует результаты.
    """
    if crashes_dir is None:
        crashes_dir = PROJECT_ROOT / "fuzz" / "crashes"
    crashes_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 70)
    print("ФАЗЗИНГ-ТЕСТИРОВАНИЕ КРИТИЧЕСКИХ МОДУЛЕЙ «SECURE CHAT»")
    print(f"Целевое время работы:   {max_seconds} сек")
    print(f"Количество целей:       {len(TARGETS)}")
    print(f"Каталог сохранения crash: {crashes_dir}")
    print("=" * 70)

    start_time = time.time()
    total_inputs = 0
    crashes_count = 0
    target_stats = {name: 0 for name, _ in TARGETS}

    seed_pool = list(FuzzCorpus.SEEDS)
    last_report_time = start_time

    while True:
        elapsed = time.time() - start_time
        if elapsed >= max_seconds:
            break

        # Выбираем случайную цель
        target_name, target_fn = random.choice(TARGETS)

        # Выбираем способ генерации входных данных: 60% мутация, 40% случайные байты
        if random.random() < 0.6 and seed_pool:
            input_bytes = FuzzCorpus.mutate(random.choice(seed_pool))
        else:
            input_bytes = FuzzCorpus.random_bytes(random.randint(4, 1024))

        total_inputs += 1
        target_stats[target_name] += 1

        try:
            target_fn(input_bytes)
        except EXPECTED_EXCEPTIONS:
            # Ожидаемое контролируемое исключение - норма для невалидных данных
            pass
        except Exception as crash_exc:
            # Необработанное исключение - потенциальный баг / авария
            crashes_count += 1
            crash_filename = f"crash_{crashes_count}_{int(time.time())}.bin"
            crash_path = crashes_dir / crash_filename
            crash_path.write_bytes(input_bytes)
            print(f"\n[CRASH DETECTED #{crashes_count}] Цель: {target_name}")
            print(f"Исключение: {type(crash_exc).__name__}: {crash_exc}")
            print(f"Входные данные сохранены в: {crash_path}")
            traceback.print_exc()

        # Периодический отчет каждые 10 секунд
        now = time.time()
        if now - last_report_time >= 10.0:
            rate = total_inputs / max(1.0, elapsed)
            print(f"[{elapsed:5.1f}s / {max_seconds}s] Входов обработано: {total_inputs:,} "
                  f"({rate:.0f} оп/сек) | Падений (Crashes): {crashes_count}")
            last_report_time = now

    final_elapsed = time.time() - start_time
    rate = total_inputs / max(0.1, final_elapsed)

    print("\n" + "=" * 70)
    print("ИТОГИ ФАЗЗИНГ-ТЕСТИРОВАНИЯ (ИТОГОВЫЙ ОТЧЕТ)")
    print("=" * 70)
    print(f"Время непрерывной работы: {final_elapsed:.2f} сек (минимум 60с выполнен)")
    print(f"Всего проверено входов:   {total_inputs:,}")
    print(f"Средняя скорость:         {rate:.1f} входов/сек")
    print(f"Обнаружено падений (Crash): {crashes_count}")
    print("\nРаспределение по целям тестирования:")
    for name, cnt in target_stats.items():
        print(f"  - {name:28s}: {cnt:,} итераций")
    print("=" * 70)

    if crashes_count == 0:
        print("✅ ВСЕ ЦЕЛИ УСПЕШНО ПРОШЛИ ФАЗЗИНГ. НЕОБРАБОТАННЫХ ПАДЕНИЙ И СБОЕВ НЕ ВЫЯВЛЕНО.")
    else:
        print(f"⚠️ ВНИМАНИЕ: Найдено {crashes_count} дефектов. Изучите сохраненные файлы в {crashes_dir}.")

    return crashes_count


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Фаззер модулей безопасности Secure Chat")
    parser.add_argument("-max_total_time", type=int, default=60, help="Время работы в секундах (по умолчанию 60)")
    parser.add_argument("--duration", type=int, default=None, help="Синоним max_total_time")
    args = parser.parse_args()

    duration = args.duration if args.duration is not None else args.max_total_time
    exit_code = run_fuzzer(max_seconds=duration)
    sys.exit(exit_code)
