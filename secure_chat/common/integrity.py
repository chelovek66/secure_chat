"""
Модуль контроля целостности и подлинности программного обеспечения (АЦП / ЭЦП).
Реализует требования стандартов Республики Беларусь:
  * СТБ 34.101.45-2013: Электронная цифровая подпись (ЭЦП) bign-sign и bign-verify;
  * СТБ 34.101.47-2017: Криптографическое хэширование файлов алгоритмом bash256.

Обеспечивает:
  1. Формирование эталонного манифеста файлов ПО с их контрольными суммами;
  2. Подписание манифеста закрытым ключом разработчика (ЭЦП bign);
  3. Проверку подлинности ЭЦП на открытом ключе разработчика/издателя;
  4. Пофайловый контроль целостности компонентов (выявление модификаций, внедрений, удаления).
"""

import json
import logging
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Set

from client.crypto.bee2_wrapper import engine
from client.crypto.bign import BignCrypto, BignKeyPair

logger = logging.getLogger("secure_chat.integrity")


# Каталоги и расширения файлов, подлежащих контролю целостности
PROTECTED_DIRS = ["client", "server", "common"]
PROTECTED_EXTENSIONS = {".py", ".json", ".md", ".yml", ".yaml", ".pyd", ".dll", ".exe"}

# Исключения из проверки (временные и локальные файлы)
EXCLUDE_PATTERNS = {
    "__pycache__",
    ".pytest_cache",
    ".git",
    "secure_chat.db",
    "secure_chat.db-journal",
    "secure_chat.db-wal",
    "secure_chat.db-shm",
    ".bkey",
    "manifest.json",
    "manifest.sig",
    "config.json",
    "build_info.json",
}


@dataclass
class FileIntegrityItem:
    """Информация о контрольной сумме отдельного файла."""
    rel_path: str
    size_bytes: int
    bash256_hash: str


@dataclass
class IntegrityReport:
    """Полный отчет о результатах проверки целостности и подлинности ПО."""
    status: str  # "AUTHENTIC_AND_INTACT", "TAMPERED", "SIGNATURE_INVALID", "MISSING_FILES", "ERROR"
    is_valid: bool
    signature_verified: bool
    developer_pubkey_hex: str
    total_files_checked: int
    checked_at: str
    tampered_files: List[Dict[str, str]] = field(default_factory=list)
    missing_files: List[str] = field(default_factory=list)
    injected_files: List[str] = field(default_factory=list)
    message: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


class SoftwareIntegrityManager:
    """
    Менеджер контроля целостности и подлинности программного обеспечения (ЭЦП СТБ).
    """

    MANIFEST_FILENAME = "software_manifest.json"
    RELEASE_KEY_DIR = "release_keys"

    def __init__(self, root_dir: Optional[str | Path] = None):
        if root_dir:
            self.root_dir = Path(root_dir)
        else:
            candidate = Path(__file__).resolve().parent.parent
            if (candidate / self.MANIFEST_FILENAME).is_file():
                self.root_dir = candidate
            else:
                self.root_dir = Path.cwd()
        self.manifest_path = self.root_dir / self.MANIFEST_FILENAME

    @staticmethod
    def calculate_file_hash(file_path: Path) -> str:
        """
        Вычисляет криптографический хэш содержимого файла алгоритмом bash256 (СТБ 34.101.47-2017).
        """
        content = file_path.read_bytes()
        digest = engine.bash256(content)
        return digest.hex()

    def scan_protected_files(self) -> List[Tuple[Path, str]]:
        """
        Сканирует защищаемые каталоги приложения и возвращает список (абсолютный_путь, относительный_путь).
        """
        files_to_check: List[Tuple[Path, str]] = []

        for dir_name in PROTECTED_DIRS:
            target_dir = self.root_dir / dir_name
            if not target_dir.is_dir():
                continue

            for file_path in target_dir.rglob("*"):
                if not file_path.is_file():
                    continue

                # Проверка исключений
                rel_path = file_path.relative_to(self.root_dir).as_posix()
                if any(ex in rel_path for ex in EXCLUDE_PATTERNS):
                    continue
                if file_path.suffix.lower() not in PROTECTED_EXTENSIONS:
                    continue

                files_to_check.append((file_path, rel_path))

        # Сортировка для детерминированности
        files_to_check.sort(key=lambda x: x[1])
        return files_to_check

    @staticmethod
    def compute_canonical_manifest_digest(files_dict: Dict[str, dict]) -> bytes:
        """
        Вычисляет канонический хэш bash256 от упорядоченного словаря файлов манифеста.
        Гарантирует детерминированность подписи независимо от форматирования JSON.
        """
        sorted_items = sorted(files_dict.items(), key=lambda kv: kv[0])
        canonical_str = json.dumps(sorted_items, separators=(",", ":"), ensure_ascii=True, sort_keys=True)
        return engine.bash256(canonical_str.encode("utf-8"))

    def generate_manifest(
        self,
        developer_keypair: Optional[BignKeyPair] = None,
        developer_id: str = "Secure Chat Release Authority (СТБ РБ)",
    ) -> dict:
        """
        Формирует манифест эталонных контрольных сумм bash256 (СТБ 34.101.47-2017).
        Если передан developer_keypair, манифест дополнительно подписывается ЭЦП bign-sign.
        """
        files = self.scan_protected_files()
        files_dict: Dict[str, dict] = {}

        for abs_p, rel_p in files:
            file_hash = self.calculate_file_hash(abs_p)
            files_dict[rel_p] = {
                "size_bytes": abs_p.stat().st_size,
                "bash256_hash": file_hash,
            }

        manifest = {
            "format_version": "1.0-STB",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "developer_id": developer_id,
            "hash_algorithm": "bash256 (СТБ 34.101.47-2017)",
            "files_count": len(files_dict),
            "files": files_dict,
        }

        # Если передан ключ разработчика - накладываем ЭЦП bign (СТБ 34.101.45-2013)
        if developer_keypair is not None:
            manifest_digest = self.compute_canonical_manifest_digest(files_dict)
            signature = BignCrypto.sign(manifest_digest, developer_keypair.private_key)
            manifest["signature_algorithm"] = "bign-sign-curve256v1 (СТБ 34.101.45-2013)"
            manifest["developer_public_key"] = developer_keypair.public_hex
            manifest["manifest_digest_hex"] = manifest_digest.hex()
            manifest["signature_hex"] = signature.hex()

        return manifest

    def save_manifest(
        self,
        manifest: dict,
        output_path: Optional[Path | str] = None,
    ) -> Path:
        """Сохраняет манифест в файл JSON."""
        dest = Path(output_path) if output_path else self.manifest_path
        dest.parent.mkdir(parents=True, exist_ok=True)
        with open(dest, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2, ensure_ascii=False)
        return dest

    def load_manifest(self, manifest_path: Optional[Path | str] = None) -> dict:
        """Загружает манифест из файла."""
        path = Path(manifest_path) if manifest_path else self.manifest_path
        if not path.is_file():
            raise FileNotFoundError(f"Файл манифеста не найден: {path}")
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)

    def verify_integrity(
        self,
        manifest_path: Optional[Path | str] = None,
        trusted_pubkey_hex: Optional[str] = None,
    ) -> IntegrityReport:
        """
        Выполняет комплексный контроль подлинности и целостности ПО:
          1. Проверка подлинности ЭЦП bign-verify манифеста;
          2. Пофайловое сравнение хэшей bash256;
          3. Выявление удаленных или незарегистрированных внедренных файлов.
        """
        now_iso = datetime.now(timezone.utc).isoformat()
        try:
            manifest = self.load_manifest(manifest_path)
        except Exception as exc:
            return IntegrityReport(
                status="ERROR",
                is_valid=False,
                signature_verified=False,
                developer_pubkey_hex="",
                total_files_checked=0,
                checked_at=now_iso,
                message=f"Ошибка чтения манифеста целостности: {exc}",
            )

        pubkey_hex = trusted_pubkey_hex or manifest.get("developer_public_key", "")
        sig_hex = manifest.get("signature_hex", "")
        files_dict = manifest.get("files", {})

        sig_valid = True
        # 1. Если манифест содержит цифровую подпись - проверяем её
        if pubkey_hex and sig_hex:
            try:
                expected_digest = self.compute_canonical_manifest_digest(files_dict)
                pubkey_bytes = bytes.fromhex(pubkey_hex)
                sig_bytes = bytes.fromhex(sig_hex)
                sig_valid = BignCrypto.verify(expected_digest, sig_bytes, pubkey_bytes)
            except Exception as exc:
                return IntegrityReport(
                    status="SIGNATURE_INVALID",
                    is_valid=False,
                    signature_verified=False,
                    developer_pubkey_hex=pubkey_hex,
                    total_files_checked=0,
                    checked_at=now_iso,
                    message=f"Сбой криптографической верификации ЭЦП: {exc}",
                )

            if not sig_valid:
                return IntegrityReport(
                    status="SIGNATURE_INVALID",
                    is_valid=False,
                    signature_verified=False,
                    developer_pubkey_hex=pubkey_hex,
                    total_files_checked=0,
                    checked_at=now_iso,
                    message="Электронная цифровая подпись (ЭЦП) манифеста недействительна! Возможно несанкционированное изменение ПО.",
                )

        # 2. Пофайловая проверка контрольных сумм bash256 (СТБ 34.101.47-2017)
        tampered: List[Dict[str, str]] = []
        missing: List[str] = []
        checked_count = 0

        manifest_rel_paths: Set[str] = set(files_dict.keys())

        for rel_path, file_meta in files_dict.items():
            abs_path = self.root_dir / rel_path
            checked_count += 1
            if not abs_path.is_file():
                missing.append(rel_path)
                continue

            current_hash = self.calculate_file_hash(abs_path)
            expected_hash = file_meta.get("bash256_hash", "")
            if current_hash != expected_hash:
                tampered.append({
                    "rel_path": rel_path,
                    "expected_hash": expected_hash,
                    "actual_hash": current_hash,
                })

        # 3. Поиск внедренных файлов (untracked files в защищенных директориях)
        current_files = self.scan_protected_files()
        injected: List[str] = []
        for _, rel_p in current_files:
            if rel_p not in manifest_rel_paths:
                injected.append(rel_p)

        # Анализ общего статуса
        if tampered:
            status = "TAMPERED"
            msg = f"ОБНАРУЖЕНА МОДИФИКАЦИЯ ФАЙЛОВ! Изменено файлов: {len(tampered)}"
            is_valid = False
        elif missing:
            status = "MISSING_FILES"
            msg = f"ОБНАРУЖЕНО ОТСУТСТВИЕ КОМПОНЕНТОВ! Отсутствует файлов: {len(missing)}"
            is_valid = False
        elif injected:
            status = "INJECTED_FILES"
            msg = f"ОБНАРУЖЕНЫ НЕАВТОРИЗОВАННЫЕ ФАЙЛЫ ПО! Новых файлов: {len(injected)}"
            is_valid = False
        else:
            status = "AUTHENTIC_AND_INTACT"
            msg = "Целостность ПО успешно подтверждена: все контрольные суммы bash256 совпадают с эталоном."
            is_valid = True

        return IntegrityReport(
            status=status,
            is_valid=is_valid,
            signature_verified=sig_valid,
            developer_pubkey_hex=pubkey_hex,
            total_files_checked=checked_count,
            checked_at=now_iso,
            tampered_files=tampered,
            missing_files=missing,
            injected_files=injected,
            message=msg,
        )

    def get_or_create_developer_keys(self) -> BignKeyPair:
        """
        Загружает или генерирует мастер-ключи разработчика (ЭЦП bign) в папке release_keys.
        """
        keys_path = self.root_dir / self.RELEASE_KEY_DIR
        keys_path.mkdir(parents=True, exist_ok=True)
        priv_file = keys_path / "developer_private.bkey"
        pub_file = keys_path / "developer_public.bkey"

        if priv_file.is_file() and pub_file.is_file():
            priv_bytes = bytes.fromhex(priv_file.read_text(encoding="utf-8").strip())
            pub_bytes = bytes.fromhex(pub_file.read_text(encoding="utf-8").strip())
            return BignKeyPair(private_key=priv_bytes, public_key=pub_bytes)

        # Генерация новой ключевой пары разработчика
        kp = BignCrypto.generate_keypair()
        priv_file.write_text(kp.private_hex, encoding="utf-8")
        pub_file.write_text(kp.public_hex, encoding="utf-8")
        return kp
