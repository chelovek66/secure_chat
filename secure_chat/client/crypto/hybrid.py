"""
Фасад гибридной криптографической защиты «Secure Chat» (Facade Pattern).
Связывает в единый сквозной конвейер (E2EE):
  1. Симметричное блочное шифрование и имитозащиту данных (СТБ 34.101.31-2011, BeltCrypto);
  2. Асимметричное транспортирование сессионного ключа (СТБ 34.101.45-2013, BignCrypto);
  3. Формирование и проверку электронной цифровой подписи (СТБ 34.101.45-2013 / СТБ 34.101.47-2017).
"""

import logging
from dataclasses import dataclass
from typing import Tuple
from .belt import BeltCrypto, BeltIntegrityError
from .bign import BignCrypto, BignSignatureError

logger = logging.getLogger("secure_chat.crypto.hybrid")


@dataclass(frozen=True)
class HybridPayload:
    """
    Неизменяемый объект передачи зашифрованных данных (DTO).
    * encrypted_key: сессионный 256-битный ключ belt, зашифрованный bign-keytrans на открытом ключе получателя.
    * nonce: 128-битная одноразовая синхропосылка (IV) для шифра belt-che.
    * ciphertext: зашифрованное тело сообщения.
    * mac: 128-битная имитовставка для контроля целостности.
    """
    encrypted_key: bytes
    nonce: bytes
    ciphertext: bytes
    mac: bytes

    def to_dict_b64(self) -> dict[str, str]:
        """Сериализует криптографические байты в Base64/Hex для сетевой передачи."""
        import base64
        return {
            "encrypted_key": base64.b64encode(self.encrypted_key).decode("ascii"),
            "nonce": base64.b64encode(self.nonce).decode("ascii"),
            "ciphertext": base64.b64encode(self.ciphertext).decode("ascii"),
            "mac": base64.b64encode(self.mac).decode("ascii"),
        }

    @classmethod
    def from_dict_b64(cls, d: dict[str, str]) -> "HybridPayload":
        """Восстанавливает объект полезной нагрузки из словаря Base64."""
        import base64
        return cls(
            encrypted_key=base64.b64decode(d["encrypted_key"]),
            nonce=base64.b64decode(d["nonce"]),
            ciphertext=base64.b64decode(d["ciphertext"]),
            mac=base64.b64decode(d["mac"]),
        )


class HybridCrypto:
    """
    Фасад гибридной защиты данных по стандартам Республики Беларусь.
    """

    @classmethod
    def encrypt_message(
        cls,
        plaintext: str,
        recipient_pubkey: bytes,
        sender_privkey: bytes,
    ) -> Tuple[HybridPayload, bytes]:
        """
        Полный конвейер шифрования исходящего сообщения:
          1. Текст переводится в UTF-8 байты.
          2. Вырабатывается ЭЦП bign-sign от открытого текста закрытым ключом отправителя.
          3. Генерируется одноразовый 256-битный сессионный ключ belt и синхропосылка.
          4. Тело сообщения шифруется с расчетом 128-битной имитовставки (belt-che).
          5. Сессионный ключ belt зашифровывается открытым ключом адресата (bign-keytrans).

        Возвращает:
          (HybridPayload, signature_bytes).
        """
        msg_bytes = plaintext.encode("utf-8")

        # 1. Формирование ЭЦП от открытого текста (гарантия авторства и неотказуемости)
        signature = BignCrypto.sign(msg_bytes, sender_privkey)
        logger.info(f"HybridCrypto: выработана ЭЦП bign-sign ({len(signature)} байт)")

        # 2. Выработка сессионного ключа belt
        session_key = BeltCrypto.generate_key()

        # 3. Симметричное шифрование с имитозащитой
        ciphertext, mac, iv = BeltCrypto.encrypt(msg_bytes, session_key)
        logger.info(
            f"HybridCrypto: шифрование belt-che (размер: {len(msg_bytes)} байт, MAC: {len(mac)} байт, IV: {len(iv)} байт)"
        )

        # 4. Транспортирование сессионного ключа
        encrypted_key = BignCrypto.transport_key(session_key, recipient_pubkey)
        logger.info(f"HybridCrypto: сессионный ключ belt зашифрован bign-keytrans ({len(encrypted_key)} байт)")

        payload = HybridPayload(
            encrypted_key=encrypted_key,
            nonce=iv,
            ciphertext=ciphertext,
            mac=mac,
        )
        return payload, signature

    @classmethod
    def decrypt_message(
        cls,
        payload: HybridPayload,
        recipient_privkey: bytes,
        sender_pubkey: bytes,
        signature: bytes,
    ) -> Tuple[str, bool]:
        """
        Полный конвейер расшифрования входящего сообщения:
          1. Извлечение 256-битного сессионного ключа belt через bign-keytrans-dec.
          2. Расшифрование шифротекста и проверка имитовставки belt-che-dec.
             (При искажении хотя бы 1 бита выбрасывается BeltIntegrityError).
          3. Верификация ЭЦП bign-verify открытым ключом отправителя.

        Возвращает:
          (decrypted_plaintext, is_signature_valid).
        """
        # 1. Извлечение сессионного ключа
        session_key = BignCrypto.extract_key(payload.encrypted_key, recipient_privkey)
        logger.info("HybridCrypto: сессионный ключ belt извлечен из bign-keytrans контейнера")

        # 2. Дешифрование и проверка целостности
        decrypted_bytes = BeltCrypto.decrypt(
            ciphertext=payload.ciphertext,
            mac=payload.mac,
            key=session_key,
            iv=payload.nonce,
        )
        logger.info(f"HybridCrypto: дешифрование belt-che выполнено успешно, имитовставка MAC подтверждена")

        plaintext = decrypted_bytes.decode("utf-8", errors="replace")

        # 3. Проверка подлинности подписи
        is_sig_valid = BignCrypto.verify(decrypted_bytes, signature, sender_pubkey)
        logger.info(f"HybridCrypto: проверка ЭЦП bign-verify: {'ВЕРНА' if is_sig_valid else 'НЕВЕРНА'}")

        return plaintext, is_sig_valid
