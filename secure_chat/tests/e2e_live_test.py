import sys
import os
import time
import threading
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))
import uvicorn
from server.app import app
from client.network.api_client import ApiClient
from client.crypto.bign import BignCrypto
from client.crypto.hybrid import HybridCrypto
from common.integrity import SoftwareIntegrityManager

def run_e2e():
    config = uvicorn.Config(app, host="127.0.0.1", port=8999, log_level="warning")
    server = uvicorn.Server(config)
    server_thread = threading.Thread(target=server.run, daemon=True)
    server_thread.start()
    time.sleep(1.0)

    try:
        api_alice = ApiClient(base_url="http://127.0.0.1:8999")
        api_bob = ApiClient(base_url="http://127.0.0.1:8999")
        assert api_alice.check_health(), "Server health check failed"

        # Генерация ключей bign
        alice_keys = BignCrypto.generate_keypair()
        bob_keys = BignCrypto.generate_keypair()

        # Регистрация
        assert api_alice.register("alice_test", alice_keys.public_hex), "Alice register failed"
        assert api_bob.register("bob_test", bob_keys.public_hex), "Bob register failed"

        # Проверка пользователей
        users = api_alice.get_users()
        uids = [u["user_id"] for u in users]
        assert "alice_test" in uids and "bob_test" in uids, "Users not found in server registry"

        # Защищенная отправка E2EE (СТБ belt-che + bign)
        msg_text = "Привет, Боб! Это секретное сообщение по СТБ 34.101."
        payload, signature = HybridCrypto.encrypt_message(
            plaintext=msg_text,
            recipient_pubkey=bob_keys.public_key,
            sender_privkey=alice_keys.private_key,
        )
        sent = api_alice.send_message(
            from_id="alice_test",
            to_id="bob_test",
            encrypted_key=payload.encrypted_key.hex(),
            ciphertext=payload.ciphertext.hex(),
            mac=payload.mac.hex(),
            nonce=payload.nonce.hex(),
            signature=signature.hex(),
        )
        assert sent, "Message sending failed"

        # Получение сообщения Бобом
        inbox = api_bob.get_inbox("bob_test")
        assert len(inbox) == 1, f"Expected 1 message, got {len(inbox)}"
        item = inbox[0]

        from client.crypto.hybrid import HybridPayload
        rx_payload = HybridPayload(
            encrypted_key=bytes.fromhex(item["encrypted_key"]),
            ciphertext=bytes.fromhex(item["ciphertext"]),
            mac=bytes.fromhex(item["mac"]),
            nonce=bytes.fromhex(item["nonce"]),
        )
        decrypted, is_sig_valid = HybridCrypto.decrypt_message(
            payload=rx_payload,
            recipient_privkey=bob_keys.private_key,
            sender_pubkey=alice_keys.public_key,
            signature=bytes.fromhex(item["signature"]),
        )
        assert decrypted == msg_text, f"Decryption mismatch: {decrypted} != {msg_text}"
        assert is_sig_valid, "Digital signature verification failed!"

        # Проверка работы БД и аудита
        status = api_alice.get_db_status()
        assert status["enabled"] is True, "DB should be enabled by default"

        audit = api_alice.get_db_audit_logs(limit=50)
        assert len(audit) > 0, "Audit logs should contain events"
        print(f"E2E TEST PASSED: Decrypted message: '{decrypted}', Audit events count: {len(audit)}")
        return True
    finally:
        server.should_exit = True

if __name__ == "__main__":
    success = run_e2e()
    sys.exit(0 if success else 1)
