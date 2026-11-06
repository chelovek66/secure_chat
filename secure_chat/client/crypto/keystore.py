"""
Модуль безопасного долговременного хранения ключевых контейнеров (СТБ 34.101.78-2017).
Обеспечивает:
  * Надежное сохранение и импорт ключевых пар bign;
  * Персонализацию ключей по имени пользователя ({username}_public.bkey, {username}_private.bkey);
  * Защиту от несанкционированного импорта или использования чужих ключей;
  * Парольную защиту файла закрытого ключа (алгоритм обертывания belt-kwp);
  * Валидацию контрольных сумм и форматов контейнеров.
"""

import logging
from pathlib import Path
from typing import Optional, Tuple
from .bee2_wrapper import engine
from .bign import BignKeyPair, BignCrypto

logger = logging.getLogger("secure_chat.keystore")


class KeyStoreError(Exception):
    """Исключение при операциях сохранения, чтения или расшифрования ключей."""
    pass


class KeyStore:
    """
    Репозиторий локального управления ключевыми контейнерами пользователя.
    """

    PUBLIC_KEY_FILENAME = "public.bkey"
    PRIVATE_KEY_FILENAME = "private.bkey"

    @classmethod
    def extract_metadata(cls, data: bytes) -> tuple[Optional[str], bytes]:
        """
        Извлекает имя пользователя из метаданных контейнера, если оно присутствует.
        Возвращает (meta_username, clean_data).
        """
        meta_username = None
        # Зашифрованный контейнер с заголовком метаданных
        if data.startswith(b"BKEY_META_V1\n"):
            parts = data.split(b"\n", 2)
            if len(parts) >= 2 and parts[1].startswith(b"USER:"):
                meta_username = parts[1][5:].decode("utf-8", errors="ignore").strip()
            if len(parts) >= 3:
                return meta_username, parts[2]
            return meta_username, b""

        # Текстовые контейнеры (BKEY_PUB_V1 или BKEY_RAW_V1)
        if data.startswith(b"BKEY_PUB_V1\n") or data.startswith(b"BKEY_RAW_V1\n"):
            lines = data.split(b"\n")
            for line in lines:
                if line.startswith(b"USER:"):
                    meta_username = line[5:].decode("utf-8", errors="ignore").strip()
                    break
            return meta_username, data

        return None, data

    @classmethod
    def _verify_username(cls, file_path: Path, meta_username: Optional[str], expected_username: Optional[str]):
        """
        Проверяет, соответствует ли файл ключа ожидаемому пользователю:
        1. Если указаны метаданные, проверяется точное совпадение логина;
        2. Если метаданных нет, проверяется наличие имени пользователя в названии файла.
        Если не совпадает — выбрасывает KeyStoreError.
        """
        if not expected_username:
            return

        expected = expected_username.strip()
        if not expected:
            return

        # 1. Проверка метаданных
        if meta_username is not None:
            if meta_username.lower() != expected.lower():
                raise KeyStoreError(
                    f"Ключ принадлежит другому пользователю или не соответствует логину '{expected}'"
                )
            return

        # 2. Проверка имени файла
        if expected.lower() in file_path.name.lower():
            return

        raise KeyStoreError(
            f"Ключ принадлежит другому пользователю или не соответствует логину '{expected}'"
        )

    @classmethod
    def find_user_keys(cls, directory: str | Path, username: Optional[str] = None) -> Tuple[Path, Path]:
        """
        Ищет файлы открытого и закрытого ключей пользователя в директории.
        Если username указан:
          1. Ищет {username}_public.bkey и {username}_private.bkey;
          2. Если не найдены, выполняет fallback на public.bkey и private.bkey.
        Если username не указан:
          Возвращает пути public.bkey и private.bkey.
        """
        p = Path(directory)
        if username and username.strip():
            u = username.strip()
            user_pub = p / f"{u}_{cls.PUBLIC_KEY_FILENAME}"
            user_priv = p / f"{u}_{cls.PRIVATE_KEY_FILENAME}"
            if user_pub.is_file() and user_priv.is_file():
                return user_pub, user_priv
            if user_pub.is_file() or user_priv.is_file():
                return user_pub, user_priv
            # Fallback на стандартные имена
            default_pub = p / cls.PUBLIC_KEY_FILENAME
            default_priv = p / cls.PRIVATE_KEY_FILENAME
            if default_pub.is_file() or default_priv.is_file():
                return default_pub, default_priv
            return user_pub, user_priv
        return p / cls.PUBLIC_KEY_FILENAME, p / cls.PRIVATE_KEY_FILENAME

    @classmethod
    def save_keys(
        cls,
        target_dir: str | Path,
        keypair: BignKeyPair,
        password: Optional[str] = None,
        username: Optional[str] = None,
    ) -> Tuple[Path, Path]:
        """
        Сохраняет ключевую пару в указанную директорию.
        Если username передан, файлы именуются {username}_public.bkey и {username}_private.bkey,
        а имя пользователя записывается в метаданные контейнеров.
        Если username не передан, сохраняются public.bkey и private.bkey для обратной совместимости.
        Если указан пароль, закрытый ключ шифруется функцией bkey_wrap (belt-kwp).
        """
        path = Path(target_dir)
        path.mkdir(parents=True, exist_ok=True)

        u = username.strip() if username and username.strip() else None

        if u:
            pub_file = path / f"{u}_{cls.PUBLIC_KEY_FILENAME}"
            priv_file = path / f"{u}_{cls.PRIVATE_KEY_FILENAME}"
        else:
            pub_file = path / cls.PUBLIC_KEY_FILENAME
            priv_file = path / cls.PRIVATE_KEY_FILENAME

        try:
            # 1. Сохранение открытого ключа (64 байта) с метаданными при наличии
            if u:
                pub_data = f"BKEY_PUB_V1\nUSER:{u}\n{keypair.public_key.hex()}".encode("utf-8")
            else:
                pub_data = b"BKEY_PUB_V1\n" + keypair.public_key.hex().encode("ascii")
            pub_file.write_bytes(pub_data)

            # 2. Сохранение закрытого ключа (с паролем или в открытом виде)
            if password:
                wrapped_priv = engine.bkey_wrap(keypair.private_key, password)
                if u:
                    priv_data = f"BKEY_META_V1\nUSER:{u}\n".encode("utf-8") + wrapped_priv
                else:
                    priv_data = wrapped_priv
                priv_file.write_bytes(priv_data)
            else:
                if u:
                    priv_data = f"BKEY_RAW_V1\nUSER:{u}\n{keypair.private_key.hex()}".encode("utf-8")
                else:
                    priv_data = b"BKEY_RAW_V1\n" + keypair.private_key.hex().encode("ascii")
                priv_file.write_bytes(priv_data)

            return pub_file, priv_file

        except Exception as exc:
            raise KeyStoreError(f"Не удалось сохранить ключевую пару в {target_dir}: {exc}") from exc

    @classmethod
    def load_public_key(cls, file_or_dir: str | Path, expected_username: Optional[str] = None) -> bytes:
        """
        Загружает открытый ключ bign из файла или директории.
        Если указан expected_username, проверяет, что имя файла содержит expected_username
        или в метаданных указан тот же пользователь. Если не совпадает — выбрасывает KeyStoreError.
        """
        path = Path(file_or_dir)
        if path.is_file():
            pub_file = path
        else:
            pub_file, _ = cls.find_user_keys(path, expected_username)

        if not pub_file.is_file():
            raise KeyStoreError(f"Файл открытого ключа не найден: {pub_file}")

        try:
            data = pub_file.read_bytes()
            meta_username, clean_data = cls.extract_metadata(data)

            # Проверка принадлежности ключа пользователю
            cls._verify_username(pub_file, meta_username, expected_username)

            lines = [line.strip() for line in clean_data.split(b"\n") if line.strip()]
            if len(lines) >= 2 and lines[0] == b"BKEY_PUB_V1":
                pk = bytes.fromhex(lines[-1].decode("ascii"))
            elif len(clean_data) == 64:
                pk = clean_data
            else:
                raise KeyStoreError("Некорректная структура файла открытого ключа bkey")

            if len(pk) != 64:
                raise KeyStoreError(f"Недопустимая длина открытого ключа bign: ожидается 64 байта, получено {len(pk)}")
            return pk
        except KeyStoreError:
            raise
        except Exception as exc:
            raise KeyStoreError(f"Ошибка чтения открытого ключа: {exc}") from exc

    @classmethod
    def load_private_key(
        cls,
        file_or_dir: str | Path,
        password: Optional[str] = None,
        expected_username: Optional[str] = None,
    ) -> bytes:
        """
        Загружает личный закрытый ключ bign из файла или директории.
        При необходимости запрашивает и применяет пароль.
        Если указан expected_username, проверяет, что имя файла содержит expected_username
        или в метаданных указан тот же пользователь. Если не совпадает — выбрасывает KeyStoreError.
        """
        path = Path(file_or_dir)
        if path.is_file():
            priv_file = path
        else:
            _, priv_file = cls.find_user_keys(path, expected_username)

        if not priv_file.is_file():
            raise KeyStoreError(f"Файл закрытого ключа не найден: {priv_file}")

        try:
            data = priv_file.read_bytes()
            meta_username, clean_data = cls.extract_metadata(data)

            # Проверка принадлежности ключа пользователю
            cls._verify_username(priv_file, meta_username, expected_username)

            # Проверка, зашифрован ли контейнер
            if clean_data.startswith(b"BKEY_STB78_V1") or clean_data.startswith(b"BKEY_V1"):
                if not password:
                    raise KeyStoreError("Для загрузки закрытого ключа требуется пароль!")
                privkey = engine.bkey_unwrap(clean_data, password)
                return privkey

            # Незашифрованный формат
            lines = [line.strip() for line in clean_data.split(b"\n") if line.strip()]
            if len(lines) >= 2 and lines[0] == b"BKEY_RAW_V1":
                privkey = bytes.fromhex(lines[-1].decode("ascii"))
            elif len(clean_data) == 32:
                privkey = clean_data
            else:
                raise KeyStoreError("Нераспознанный формат файла закрытого ключа")

            if len(privkey) != 32:
                raise KeyStoreError(f"Недопустимая длина закрытого ключа bign: ожидается 32 байта, получено {len(privkey)}")
            return privkey

        except KeyStoreError:
            raise
        except ValueError as err:
            raise KeyStoreError(str(err)) from err
        except Exception as exc:
            raise KeyStoreError(f"Ошибка загрузки закрытого ключа: {exc}") from exc

    @classmethod
    def load_keys(
        cls,
        file_or_dir: str | Path,
        password: Optional[str] = None,
        expected_username: Optional[str] = None,
    ) -> BignKeyPair:
        """
        Загружает и валидирует полную ключевую пару bign с проверкой криптографического соответствия.
        """
        path = Path(file_or_dir)
        if path.is_file():
            raise KeyStoreError(f"Ожидается директория с ключами, передан файл: {path}")

        pub_file, priv_file = cls.find_user_keys(path, expected_username)
        pubkey = cls.load_public_key(pub_file, expected_username=expected_username)
        privkey = cls.load_private_key(priv_file, password=password, expected_username=expected_username)

        # Криптографическая верификация соответствия пары
        try:
            expected_pub = BignCrypto.pubkey_from_privkey(privkey)
            if expected_pub != pubkey:
                raise KeyStoreError(
                    "Критическая ошибка: открытый ключ не соответствует закрытому ключу!"
                )
        except KeyStoreError:
            raise
        except Exception as exc:
            logger.warning(f"Не удалось проверить соответствие ключевой пары: {exc}")

        return BignKeyPair(private_key=privkey, public_key=pubkey)
