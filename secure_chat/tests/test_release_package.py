"""
Тесты релизного пакета, SBOM, манифеста и цифровой подписи Ed25519 (ПЗ-4 п. 7).
"""

import os
import json
import base64
import hashlib
import zipfile
from pathlib import Path
import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization


@pytest.fixture(scope="module")
def project_root() -> Path:
    return Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def release_dir(project_root: Path) -> Path:
    return project_root / "release"


@pytest.fixture(scope="module")
def release_keys_dir(project_root: Path) -> Path:
    return project_root / "release_keys"


def sha256_of_file(file_path: Path) -> str:
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def test_release_files_exist(release_dir: Path, release_keys_dir: Path):
    """Проверяет существование всех ключевых артефактов релиза."""
    assert (release_keys_dir / "update_private.key").is_file(), "Отсутствует закрытый ключ Ed25519"
    assert (release_keys_dir / "update_public.key").is_file(), "Отсутствует открытый ключ Ed25519"

    zip_file = release_dir / "SecureClient-2.1.0-win-x64.zip"
    assert zip_file.is_file(), "Отсутствует ZIP-архив релиза"
    assert zip_file.stat().st_size > 10 * 1024 * 1024, "Размер ZIP-архива подозрительно мал"

    manifest_file = release_dir / "manifest.json"
    assert manifest_file.is_file(), "Отсутствует manifest.json"

    manifest_sig_file = release_dir / "manifest.sig"
    assert manifest_sig_file.is_file(), "Отсутствует manifest.sig"

    sbom_file = release_dir / "sbom.json"
    assert sbom_file.is_file(), "Отсутствует sbom.json"


def test_zip_archive_structure(release_dir: Path):
    """Проверяет структуру релизного ZIP-архива."""
    zip_file = release_dir / "SecureClient-2.1.0-win-x64.zip"
    with zipfile.ZipFile(zip_file, "r") as zf:
        namelist = zf.namelist()
        assert "SecureClient.exe" in namelist, "В архиве отсутствует SecureClient.exe"
        assert "bee2.dll" in namelist, "В архиве отсутствует bee2.dll"
        assert "config.json" in namelist, "В архиве отсутствует config.json"
        assert "sbom.json" in namelist, "В архиве отсутствует sbom.json"


def test_sbom_cyclonedx_specification(release_dir: Path):
    """Проверяет соответствие sbom.json спецификации CycloneDX 1.5."""
    sbom_file = release_dir / "sbom.json"
    data = json.loads(sbom_file.read_text(encoding="utf-8"))

    assert data.get("bomFormat") == "CycloneDX"
    assert data.get("specVersion") == "1.5"
    assert "components" in data

    comp_names = {c["name"] for c in data["components"]}
    expected_deps = {"cryptography", "PyQt5", "requests", "fastapi", "uvicorn", "bee2.dll"}
    assert expected_deps.issubset(comp_names), f"В SBOM отсутствуют компоненты: {expected_deps - comp_names}"


def test_manifest_structure_and_hashes(release_dir: Path):
    """Проверяет соответствие полей manifest.json и целостность SHA-256."""
    manifest_file = release_dir / "manifest.json"
    manifest = json.loads(manifest_file.read_text(encoding="utf-8"))

    assert manifest["version"] == "2.1.0"
    assert manifest["min_supported"] == "1.0.0"
    assert manifest["os"] == "windows"
    assert manifest["arch"] == "x64"
    assert manifest["package_url"] == "/updates/download/2.1.0"
    assert manifest["sbom"]["format"] == "CycloneDX-1.5"
    assert manifest["sbom"]["url"] == "/updates/sbom/2.1.0.json"
    assert manifest["critical"] is False

    # Проверка SHA-256 пакета
    zip_file = release_dir / "SecureClient-2.1.0-win-x64.zip"
    actual_zip_sha256 = sha256_of_file(zip_file)
    assert manifest["package_sha256"].lower() == actual_zip_sha256.lower()
    assert manifest["package_size"] == zip_file.stat().st_size

    # Проверка SHA-256 SBOM
    sbom_file = release_dir / "sbom.json"
    actual_sbom_sha256 = sha256_of_file(sbom_file)
    assert manifest["sbom"]["sha256"].lower() == actual_sbom_sha256.lower()


def test_manifest_ed25519_signatures(release_dir: Path, release_keys_dir: Path):
    """Проверяет цифровую подпись Ed25519 для manifest.json и отсоединенную manifest.sig."""
    pub_key_path = release_keys_dir / "update_public.key"
    pub_bytes = pub_key_path.read_bytes()
    if b"BEGIN" in pub_bytes:
        pub_key = serialization.load_pem_public_key(pub_bytes)
    else:
        pub_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes[:32])

    manifest_file = release_dir / "manifest.json"
    manifest = json.loads(manifest_file.read_text(encoding="utf-8"))

    # 1. Проверка поля signature внутри manifest.json
    sig_b64 = manifest["signature"]
    sig_bytes = base64.b64decode(sig_b64)
    to_verify = {k: v for k, v in manifest.items() if k != "signature"}
    canonical_bytes = json.dumps(to_verify, sort_keys=True, separators=(",", ":")).encode("utf-8")
    pub_key.verify(sig_bytes, canonical_bytes)

    # 2. Проверка отсоединенной подписи manifest.sig
    manifest_sig_file = release_dir / "manifest.sig"
    sig_file_text = manifest_sig_file.read_text(encoding="utf-8").strip()
    detached_sig_bytes = base64.b64decode(sig_file_text)
    manifest_bytes = manifest_file.read_bytes()
    pub_key.verify(detached_sig_bytes, manifest_bytes)
