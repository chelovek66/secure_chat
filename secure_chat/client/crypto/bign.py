"""
Модуль асимметричной криптографии Bign (СТБ 34.101.45-2013).
Реализует требования:
  * Пункт 6.1: Генерация ключевых пар на эллиптических кривых над простыми полями (256 бит);
  * Пункт 6.3: Процедура асимметричного транспортирования сессионного ключа bign-keytrans;
  * Пункт 6.2: Формирование и верификация электронной цифровой подписи (ЭЦП);
  * СТБ 34.101.47-2017: Криптографическое хэширование bash256 при формировании ЭЦП.
"""

from dataclasses import dataclass
from .bee2_wrapper import engine


class BignSignatureError(Exception):
    """Исключение, вызываемое при нарушении подлинности ЭЦП или авторства сообщения."""
    pass


@dataclass(frozen=True)
class BignKeyPair:
    """
    Контейнер асимметричной ключевой пары bign (СТБ 34.101.45-2013).
    private_key: 32 байта (личный секретный ключ).
    public_key: 64 байта (открытый ключ, координаты точки эллиптической кривой).
    """
    private_key: bytes
    public_key: bytes

    @property
    def public_hex(self) -> str:
        """Шестнадцатеричное представление открытого ключа."""
        return self.public_key.hex()

    @property
    def private_hex(self) -> str:
        """Шестнадцатеричное представление закрытого ключа."""
        return self.private_key.hex()


class BignCrypto:
    """
    Класс асимметричных криптографических процедур Bign на базе библиотеки Bee2 (НИИ ППМИ БГУ).
    """

    PRIVATE_KEY_LEN = 32
    PUBLIC_KEY_LEN = 64
    SIGNATURE_LEN = 64

    @classmethod
    def generate_keypair(cls) -> BignKeyPair:
        """
        Генерирует пару асимметричных ключей bign (bign-curve256v1).
        """
        priv, pub = engine.bign_generate_keypair()
        return BignKeyPair(private_key=priv, public_key=pub)

    @classmethod
    def pubkey_from_privkey(cls, privkey: bytes) -> bytes:
        """
        Вычисляет открытый ключ bign (64 байта) по личному закрытому ключу (32 байта).
        """
        if len(privkey) != cls.PRIVATE_KEY_LEN:
            raise ValueError(f"Личный ключ bign должен составлять {cls.PRIVATE_KEY_LEN} байт")
        return engine.bign_pubkey_from_privkey(privkey)

    @classmethod
    def keypair_from_privkey(cls, privkey: bytes) -> BignKeyPair:
        """
        Создает полную ключевую пару BignKeyPair на основе одного лишь закрытого ключа.
        """
        pubkey = cls.pubkey_from_privkey(privkey)
        return BignKeyPair(private_key=privkey, public_key=pubkey)

    @classmethod
    def transport_key(cls, belt_key: bytes, recipient_pubkey: bytes) -> bytes:
        """
        Зашифровывает 256-битный сессионный ключ belt на открытом ключе получателя
        с использованием процедуры bign-keytrans (СТБ 34.101.45-2013).
        """
        if len(belt_key) != 32:
            raise ValueError("Сессионный ключ belt должен составлять ровно 32 байта")
        if len(recipient_pubkey) != cls.PUBLIC_KEY_LEN:
            raise ValueError(f"Открытый ключ получателя bign должен составлять {cls.PUBLIC_KEY_LEN} байт")

        encrypted_key_package = engine.bign_keytrans_encrypt(belt_key, recipient_pubkey)
        return encrypted_key_package

    @classmethod
    def extract_key(cls, encrypted_key_package: bytes, recipient_privkey: bytes) -> bytes:
        """
        Расшифровывает транспортированный сессионный ключ belt с помощью личного ключа получателя.
        """
        if len(recipient_privkey) != cls.PRIVATE_KEY_LEN:
            raise ValueError(f"Личный ключ bign должен составлять {cls.PRIVATE_KEY_LEN} байт")

        belt_key = engine.bign_keytrans_decrypt(encrypted_key_package, recipient_privkey)
        return belt_key

    @classmethod
    def sign(cls, message: bytes, privkey: bytes) -> bytes:
        """
        Формирует электронную цифровую подпись (ЭЦП) исходного открытого текста сообщения.
        Использует хэширование bash256 (СТБ 34.101.47-2017) и алгоритм bign-sign (СТБ 34.101.45-2013).
        """
        if len(privkey) != cls.PRIVATE_KEY_LEN:
            raise ValueError(f"Личный ключ bign должен составлять {cls.PRIVATE_KEY_LEN} байт")

        signature = engine.bign_sign(message, privkey)
        return signature

    @classmethod
    def verify(cls, message: bytes, signature: bytes, pubkey: bytes) -> bool:
        """
        Выполняет проверку электронной цифровой подписи (ЭЦП) bign-verify (СТБ 34.101.45-2013).
        Возвращает True, если подпись подлинна и сообщение не изменялось; иначе False.
        """
        if len(pubkey) != cls.PUBLIC_KEY_LEN or len(signature) != cls.SIGNATURE_LEN:
            return False

        is_valid = engine.bign_verify(message, signature, pubkey)
        return is_valid
