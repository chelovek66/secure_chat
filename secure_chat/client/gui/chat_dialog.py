"""
Окно защищенного диалога (ChatDialog) с фоновым неблокирующим опросом (QThread).
Реализует:
  * Неблокирующий опрос сервера входящих сообщений (QThread worker);
  * Шифрование и выработку ЭЦП исходящих сообщений (СТБ 34.101.31 / СТБ 34.101.45);
  * Расшифрование и верификацию входящих сообщений с индикацией подлинности [✔] / [⚠];
  * Защиту от XSS и HTML Injection при форматировании сообщений.
"""

import html
import time
import logging
from typing import Optional

logger = logging.getLogger("secure_chat.gui.chat")
from PyQt5.QtWidgets import (
    QDialog,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QTextEdit,
    QLineEdit,
    QPushButton,
    QMessageBox,
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal

from ..crypto.hybrid import HybridCrypto, HybridPayload
from ..crypto.belt import BeltIntegrityError
from ..crypto.bign import BignKeyPair
from ..network.api_client import ApiClient, ApiClientError


class InboxPollWorker(QThread):
    """
    Фоновый рабочий поток для регулярного опроса входящей очереди сообщений.
    Исключает зависание пользовательского интерфейса при сетевых задержках.
    """
    new_messages_received = pyqtSignal(list)
    poll_error = pyqtSignal(str)

    def __init__(self, api_client: ApiClient, interval_sec: float = 2.0):
        super().__init__()
        self.api = api_client
        self.interval = interval_sec
        self._running = True

    def run(self):
        while self._running:
            try:
                if self.api.user_id:
                    messages = self.api.get_inbox(self.api.user_id)
                    if messages:
                        self.new_messages_received.emit(messages)
            except Exception as exc:
                self.poll_error.emit(str(exc))

            # Спим короткими квантами для мгновенной остановки по запросу
            for _ in range(int(self.interval * 10)):
                if not self._running:
                    break
                time.sleep(0.1)

    def stop(self):
        self._running = False
        self.wait(1000)


class ChatDialog(QDialog):
    """
    Интерактивное окно защищенного чата между двумя абонентами.
    """

    def __init__(
        self,
        api_client: ApiClient,
        keypair: BignKeyPair,
        partner_id: str,
        partner_pubkey: bytes,
        parent=None,
    ):
        super().__init__(parent)
        self.api = api_client
        self.keypair = keypair
        self.partner_id = partner_id
        self.partner_pubkey = partner_pubkey

        self.setWindowTitle(f"Защищенный диалог: {self.api.user_id} ↔ {self.partner_id}")
        self.resize(760, 560)
        self.setMinimumSize(680, 480)
        self.init_ui()

        # Запуск фонового потока опроса
        self.poll_thread = InboxPollWorker(self.api, interval_sec=2.0)
        self.poll_thread.new_messages_received.connect(self.handle_incoming_messages)
        self.poll_thread.poll_error.connect(self._on_poll_error)
        self.poll_thread.start()

    def _on_poll_error(self, err_msg: str):
        if hasattr(self, "status_badge"):
            self.status_badge.setText("🔴 Связь с сервером потеряна")
            self.status_badge.setStyleSheet("color: #F87171; font-weight: bold; font-size: 11px;")

    def _restore_online_badge(self):
        if hasattr(self, "status_badge"):
            self.status_badge.setText("🟢 Защищенное соединение (E2EE)")
            self.status_badge.setStyleSheet("color: #34D399; font-weight: bold; font-size: 11px;")

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(10)

        # Верхняя панель
        header_layout = QHBoxLayout()
        title = QLabel(f"Собеседник: {self.partner_id}")
        title.setObjectName("titleLabel")
        header_layout.addWidget(title)
        header_layout.addStretch()

        self.status_badge = QLabel("🟢 Защищенное соединение (E2EE)")
        self.status_badge.setStyleSheet("color: #34D399; font-weight: bold; font-size: 11px;")
        header_layout.addWidget(self.status_badge)

        self.export_btn = QPushButton("💾 Экспорт", self)
        self.export_btn.setObjectName("secondaryButton")
        self.export_btn.clicked.connect(self.export_chat_history)
        header_layout.addWidget(self.export_btn)

        self.logs_btn = QPushButton("📋 Логи", self)
        self.logs_btn.setObjectName("secondaryButton")
        self.logs_btn.clicked.connect(self.open_logs_dialog)
        header_layout.addWidget(self.logs_btn)
        layout.addLayout(header_layout)

        # Область сообщений
        self.chat_history = QTextEdit(self)
        self.chat_history.setReadOnly(True)
        layout.addWidget(self.chat_history)

        # Поле ввода и кнопка отправки
        input_layout = QHBoxLayout()
        self.msg_input = QLineEdit(self)
        self.msg_input.setPlaceholderText("Введите сообщение (будет зашифровано и подписано ЭЦП)...")
        self.msg_input.returnPressed.connect(self.send_message)
        input_layout.addWidget(self.msg_input)

        self.send_btn = QPushButton("Отправить", self)
        self.send_btn.clicked.connect(self.send_message)
        input_layout.addWidget(self.send_btn)

        layout.addLayout(input_layout)

    def append_message_to_history(self, sender: str, text: str, is_me: bool, sig_valid: Optional[bool] = None, preview_cipher: str = ""):
        """Форматирует и выводит сообщение в область истории."""
        t_str = time.strftime("%H:%M:%S")
        safe_text = html.escape(text)

        if is_me:
            sender_html = f"<b style='color: #60A5FA;'>Вы ({self.api.user_id})</b>"
            sig_badge = "<span style='color: #94A3B8;'>[исходящее]</span>"
        else:
            sender_html = f"<b style='color: #34D399;'>{sender}</b>"
            if sig_valid is True:
                sig_badge = "<span style='color: #10B981; font-weight: bold;'>[✔ ЭЦП верна]</span>"
            elif sig_valid is False:
                sig_badge = "<span style='color: #EF4444; font-weight: bold;'>[⚠ ЭЦП неверна]</span>"
            else:
                sig_badge = ""

        cipher_meta = ""
        if preview_cipher:
            cipher_meta = f"<div style='color: #64748B; font-size: 10px; font-family: monospace;'>Шифротекст: {html.escape(preview_cipher[:28])}...</div>"

        msg_block = (
            f"<div style='margin-bottom: 8px;'>"
            f"<span style='color: #64748B; font-size: 11px;'>[{t_str}]</span> {sender_html} {sig_badge}:<br/>"
            f"<span style='font-size: 13px; color: #F1F5F9;'>{safe_text}</span>"
            f"{cipher_meta}"
            f"</div>"
        )
        self.chat_history.append(msg_block)

    def open_logs_dialog(self):
        """Открывает окно просмотра логов прямо из окна диалога."""
        from .logs_dialog import LogsDialog
        dlg = LogsDialog(api_client=self.api, parent=self)
        dlg.exec_()

    def send_message(self):
        text = self.msg_input.text().strip()
        if not text:
            return

        if not self.partner_pubkey or len(self.partner_pubkey) != 64:
            QMessageBox.critical(
                self,
                "Ошибка безопасности",
                f"Невозможно зашифровать сообщение: открытый ключ собеседника '{self.partner_id}' некорректен (длина {len(self.partner_pubkey) if self.partner_pubkey else 0} байт вместо 64 байт).",
            )
            return

        try:
            logger.info(f"Отправка сообщения пользователю '{self.partner_id}': шифрование E2EE...")
            # 1. Гибридное шифрование и подпись
            payload, signature = HybridCrypto.encrypt_message(
                plaintext=text,
                recipient_pubkey=self.partner_pubkey,
                sender_privkey=self.keypair.private_key,
            )

            # 2. Сетевая отправка через сервер
            dict_payload = payload.to_dict_b64()
            import base64
            sig_b64 = base64.b64encode(signature).decode("ascii")

            self.api.send_message(
                from_id=self.api.user_id,
                to_id=self.partner_id,
                ciphertext=dict_payload["ciphertext"],
                nonce=dict_payload["nonce"],
                mac=dict_payload["mac"],
                encrypted_key=dict_payload["encrypted_key"],
                signature=sig_b64,
            )
            logger.info(f"Сообщение для '{self.partner_id}' успешно зашифровано и отправлено на сервер.")

            # 3. Отображение в своем окне
            self.append_message_to_history(
                sender=self.api.user_id,
                text=text,
                is_me=True,
                preview_cipher=dict_payload["ciphertext"],
            )
            self.msg_input.clear()

        except ApiClientError as exc:
            QMessageBox.critical(self, "Ошибка доставки", f"Не удалось отправить сообщение: {exc}")
        except Exception as exc:
            QMessageBox.critical(self, "Криптографическая ошибка", f"Сбой при шифровании: {exc}")

    def export_chat_history(self):
        """Сохраняет текущую историю переписки в текстовый файл."""
        from PyQt5.QtWidgets import QFileDialog
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Экспорт истории диалога",
            f"chat_{self.partner_id}_{int(time.time())}.txt",
            "Текстовый документ (*.txt);;HTML (*.html)",
        )
        if not path:
            return
        try:
            content = self.chat_history.toPlainText() if path.endswith(".txt") else self.chat_history.toHtml()
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)
            QMessageBox.information(self, "Экспорт", f"История переписки сохранена в:\n{path}")
        except Exception as exc:
            QMessageBox.critical(self, "Ошибка экспорта", f"Не удалось сохранить историю: {exc}")

    def handle_incoming_messages(self, messages: list):
        """Обрабатывает и расшифровывает принятые от сервера сообщения."""
        self._restore_online_badge()
        import base64
        for msg in messages:
            # Обрабатываем сообщения, предназначенные для текущего диалога
            if msg.get("from_id") != self.partner_id:
                continue

            try:
                payload = HybridPayload(
                    encrypted_key=base64.b64decode(msg["encrypted_key"]),
                    nonce=base64.b64decode(msg["nonce"]),
                    ciphertext=base64.b64decode(msg["ciphertext"]),
                    mac=base64.b64decode(msg["mac"]),
                )
                sig_bytes = base64.b64decode(msg["signature"])

                # Расшифрование и проверка ЭЦП
                logger.info(f"Входящее сообщение от '{self.partner_id}'. Дешифрование конвейером СТБ 34.101...")
                decrypted_text, is_valid_sig = HybridCrypto.decrypt_message(
                    payload=payload,
                    recipient_privkey=self.keypair.private_key,
                    sender_pubkey=self.partner_pubkey,
                    signature=sig_bytes,
                )

                # Безопасный отказ (Fail-Closed): блокировка поддельных сообщений
                if not is_valid_sig:
                    logger.warning(f"Сообщение от '{self.partner_id}' заблокировано: недействительная цифровая подпись!")
                    self.chat_history.append(
                        f"<div style='color: #FCA5A5; background-color: #7F1D1D; padding: 6px 10px; border-radius: 4px; margin: 6px 0; border: 1px solid #DC2626;'>"
                        f"<b>[УГРОЗА БЕЗОПАСНОСТИ]</b> Сообщение от {self.partner_id} отвергнуто: "
                        f"ЭЦП не подтверждена! Содержимое заблокировано во избежание подделки.</div>"
                    )
                    continue

                logger.info(f"Сообщение от '{self.partner_id}' расшифровано. ЭЦП: [ПОДТВЕРЖДЕНА]")

                self.append_message_to_history(
                    sender=self.partner_id,
                    text=decrypted_text,
                    is_me=False,
                    sig_valid=is_valid_sig,
                    preview_cipher=msg["ciphertext"],
                )

            except BeltIntegrityError as exc:
                self.chat_history.append(
                    f"<div style='color: #EF4444;'><b>[ОШИБКА БЕЗОПАСНОСТИ]</b> Сообщение от {self.partner_id} "
                    f"было отброшено из-за нарушения целостности имитозащиты: {html.escape(str(exc))}</div>"
                )
            except Exception as exc:
                self.chat_history.append(
                    f"<div style='color: #EF4444;'>[Ошибка дешифрования]: {html.escape(str(exc))}</div>"
                )

    def closeEvent(self, event):
        """Останавливает рабочий поток опроса перед закрытием окна."""
        if hasattr(self, "poll_thread") and self.poll_thread.isRunning():
            self.poll_thread.stop()
        event.accept()
