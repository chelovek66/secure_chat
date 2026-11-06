"""
Модуль криптографического обеспечения безопасного обновления ПО (ПЗ-4).
Реализует:
  * Асимметричную цифровую подпись манифеста на базе Ed25519 (RFC 8032);
  * Верификацию ЭЦП встроенным или сконфигурированным открытым ключом;
  * Контроль целостности пакетов обновлений и SBOM по алгоритму SHA-256;
  * Валидацию структуры SBOM в формате CycloneDX 1.5;
  * Управление ключевыми парами обновления ПО.
"""

import base64
import hashlib
import json
import logging
from pathlib import Path
from typing import Any, Dict, Optional, Tuple, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

logger = logging.getLogger("secure_chat.update_crypto")

# Встроенный открытый ключ разработчика / вендора по умолчанию (Base64 raw 32 bytes)
DEFAULT_UPDATE_PUBLIC_KEY_B64 = "k/VgH69DSpUM6/VY+pYta6yx8aLB7bfRuLq589ST+Ok="

# Встроенный открытый ключ в формате SubjectPublicKeyInfo PEM
DEFAULT_UPDATE_PUBLIC_KEY_PEM = (
    "-----BEGIN PUBLIC KEY-----\n"
    "MCowBQYDK2VwAyEAk/VgH69DSpUM6/VY+pYta6yx8aLB7bfRuLq589ST+Ok=\n"
    "-----END PUBLIC KEY-----\n"
)

# Закрытый ключ по умолчанию (для подписи релизов на сервере / CI/CD)
DEFAULT_UPDATE_PRIVATE_KEY_PEM = (
    "-----BEGIN PRIVATE KEY-----\n"
    "MC4CAQAwBQYDK2VwBCIEIGXT1M6Emob1x/8a9wg9w7J20dejl2F5MOBvLhtbJt6G\n"
    "-----END PRIVATE KEY-----\n"
)


def generate_keypair() -> Tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
    """Генерирует новую асимметричную ключевую пару Ed25519."""
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def export_private_key_pem(private_key: ed25519.Ed25519PrivateKey) -> str:
    """Экспортирует закрытый ключ Ed25519 в формат PKCS#8 PEM."""
    pem_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return pem_bytes.decode("ascii")


def export_public_key_pem(public_key: ed25519.Ed25519PublicKey) -> str:
    """Экспортирует открытый ключ Ed25519 в формат SubjectPublicKeyInfo PEM."""
    pem_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return pem_bytes.decode("ascii")


def export_public_key_b64(public_key: ed25519.Ed25519PublicKey) -> str:
    """Экспортирует открытый ключ Ed25519 в сырой Base64 (32 байта)."""
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw).decode("ascii")


def load_private_key(
    key_data: Union[str, bytes, Path, ed25519.Ed25519PrivateKey, None] = None
) -> ed25519.Ed25519PrivateKey:
    """
    Загружает закрытый ключ Ed25519 из файла, строки PEM, сырых байт или Base64.
    Если key_data is None, ищет в release_keys/ или использует встроенный ключ.
    """
    if key_data is None:
        project_root = Path(__file__).resolve().parent.parent
        for candidate in [
            project_root / "release_keys" / "update_private.key",
            project_root / "release_keys" / "update_signing_private.pem",
        ]:
            if candidate.is_file():
                try:
                    return serialization.load_pem_private_key(candidate.read_bytes(), password=None)
                except Exception:
                    pass
        return serialization.load_pem_private_key(
            DEFAULT_UPDATE_PRIVATE_KEY_PEM.encode("ascii"),
            password=None,
        )

    if isinstance(key_data, ed25519.Ed25519PrivateKey):
        return key_data

    if isinstance(key_data, Path) or (isinstance(key_data, str) and Path(key_data).is_file()):
        data = Path(key_data).read_bytes()
    elif isinstance(key_data, str):
        data = key_data.encode("utf-8")
    else:
        data = key_data

    # Попытка парсинга PEM
    if b"-----BEGIN PRIVATE KEY-----" in data or b"-----BEGIN OPENSSH PRIVATE KEY-----" in data:
        return serialization.load_pem_private_key(data, password=None)

    # Попытка парсинга сырых 32 байт
    if len(data) == 32:
        return ed25519.Ed25519PrivateKey.from_private_bytes(data)

    # Попытка декодирования Base64
    try:
        raw = base64.b64decode(data.strip())
        if len(raw) == 32:
            return ed25519.Ed25519PrivateKey.from_private_bytes(raw)
    except Exception:
        pass

    raise ValueError("Не удалось распознать формат закрытого ключа Ed25519")


def load_public_key(
    key_data: Union[str, bytes, Path, ed25519.Ed25519PublicKey, None] = None
) -> ed25519.Ed25519PublicKey:
    """
    Загружает открытый ключ Ed25519 из файла, строки PEM, сырых байт или Base64.
    Если key_data is None, ищет в release_keys/ или использует встроенный ключ.
    """
    if key_data is None:
        project_root = Path(__file__).resolve().parent.parent
        for candidate in [
            project_root / "release_keys" / "update_public.key",
            project_root / "release_keys" / "update_signing_public.pem",
        ]:
            if candidate.is_file():
                try:
                    return serialization.load_pem_public_key(candidate.read_bytes())
                except Exception:
                    pass
        return serialization.load_pem_public_key(
            DEFAULT_UPDATE_PUBLIC_KEY_PEM.encode("ascii")
        )

    if isinstance(key_data, ed25519.Ed25519PublicKey):
        return key_data

    if isinstance(key_data, Path) or (isinstance(key_data, str) and Path(key_data).is_file()):
        data = Path(key_data).read_bytes()
    elif isinstance(key_data, str):
        data = key_data.encode("utf-8")
    else:
        data = key_data

    # Попытка парсинга PEM
    if b"-----BEGIN PUBLIC KEY-----" in data:
        return serialization.load_pem_public_key(data)

    # Попытка парсинга сырых 32 байт
    if len(data) == 32:
        return ed25519.Ed25519PublicKey.from_public_bytes(data)

    # Попытка декодирования Base64
    try:
        raw = base64.b64decode(data.strip())
        if len(raw) == 32:
            return ed25519.Ed25519PublicKey.from_public_bytes(raw)
    except Exception:
        pass

    raise ValueError("Не удалось распознать формат открытого ключа Ed25519")


def canonicalize_manifest(manifest: Dict[str, Any]) -> bytes:
    """
    Канонизирует словарь манифеста перед подписью/проверкой.
    Исключает поле 'signature' (и 'manifest_sig', если есть),
    сортирует ключи и сериализует в компактный UTF-8 JSON без лишних пробелов.
    """
    clean_dict = {k: v for k, v in manifest.items() if k not in ("signature", "manifest_sig")}
    canonical_json = json.dumps(clean_dict, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return canonical_json.encode("utf-8")


def sign_manifest(
    manifest: Dict[str, Any],
    private_key: Optional[ed25519.Ed25519PrivateKey] = None,
) -> Dict[str, Any]:
    """
    Формирует цифровую подпись Ed25519 для манифеста и возвращает манифест с полем 'signature'.
    """
    if private_key is None:
        private_key = load_private_key()

    manifest_copy = dict(manifest)
    canonical_bytes = canonicalize_manifest(manifest_copy)
    sig_bytes = private_key.sign(canonical_bytes)
    sig_b64 = base64.b64encode(sig_bytes).decode("ascii")

    manifest_copy["signature"] = sig_b64
    return manifest_copy


def verify_manifest(
    manifest: Union[Dict[str, Any], str, bytes],
    public_key: Optional[Union[ed25519.Ed25519PublicKey, str, bytes, Path]] = None,
    signature: Optional[str] = None,
) -> bool:
    """
    Проверяет цифровую подпись Ed25519 манифеста.
    Если открытый ключ не передан, используется встроенный открытый ключ.
    Возвращает True при успешной верификации, иначе False.
    """
    try:
        pub = load_public_key(public_key)

        if isinstance(manifest, (str, bytes)):
            if isinstance(manifest, bytes):
                manifest = manifest.decode("utf-8")
            data_dict = json.loads(manifest)
        else:
            data_dict = dict(manifest)

        sig_b64 = signature or data_dict.get("signature")
        if not sig_b64:
            logger.warning("Верификация манифеста отклонена: поле 'signature' отсутствует")
            return False

        sig_bytes = base64.b64decode(sig_b64.strip())
        canonical_bytes = canonicalize_manifest(data_dict)

        pub.verify(sig_bytes, canonical_bytes)
        return True
    except (InvalidSignature, ValueError, json.JSONDecodeError, Exception) as exc:
        logger.warning(f"Ошибка верификации подписи манифеста Ed25519: {exc}")
        return False


def calculate_sha256(source: Union[str, Path, bytes]) -> str:
    """Вычисляет хэш SHA-256 файла или байтовой последовательности."""
    hasher = hashlib.sha256()
    if isinstance(source, bytes):
        hasher.update(source)
    else:
        path = Path(source)
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                hasher.update(chunk)
    return hasher.hexdigest().lower()


def verify_sha256(source: Union[str, Path, bytes], expected_sha256: str) -> bool:
    """Сверяет хэш SHA-256 файла или байт с эталонным значением."""
    actual = calculate_sha256(source)
    return actual.lower() == expected_sha256.strip().lower()


def validate_cyclonedx_sbom(sbom_data: Union[Dict[str, Any], str, bytes]) -> Tuple[bool, str]:
    """
    Проверяет структуру SBOM на соответствие спецификации CycloneDX 1.5.
    Проверяет наличие полей bomFormat='CycloneDX', specVersion, components.
    """
    try:
        if isinstance(sbom_data, (str, bytes)):
            if isinstance(sbom_data, bytes):
                sbom_data = sbom_data.decode("utf-8")
            data = json.loads(sbom_data)
        else:
            data = sbom_data

        if not isinstance(data, dict):
            return False, "SBOM не является JSON-объектом"

        if data.get("bomFormat") != "CycloneDX":
            return False, f"Неверный bomFormat: ожидается 'CycloneDX', получено '{data.get('bomFormat')}'"

        spec_ver = str(data.get("specVersion", ""))
        if not spec_ver.startswith("1."):
            return False, f"Неподдерживаемая версия CycloneDX specVersion: '{spec_ver}'"

        components = data.get("components")
        if not isinstance(components, list):
            return False, "Поле 'components' должно быть списком компонентов"

        return True, "CycloneDX SBOM валиден"
    except Exception as exc:
        return False, f"Ошибка синтаксического анализа SBOM: {exc}"
