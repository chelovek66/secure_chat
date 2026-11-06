"""
Тесты персонализации ключей bign и защиты от импорта чужих ключей.
Проверяют:
  * Именование файлов {username}_public.bkey и {username}_private.bkey при передаче username;
  * Обратную совместимость (public.bkey, private.bkey) без username;
  * Запись и чтение метаданных пользователя в контейнерах;
  * Блокировку загрузки ключей другого пользователя с KeyStoreError;
  * Поиск ключей пользователя методом find_user_keys с fallback на стандартные;
  * Проверку принадлежности ключей в KeyDialog._validate_key_ownership.
"""

import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from PyQt5.QtWidgets import QApplication

from client.crypto.bign import BignCrypto
from client.crypto.keystore import KeyStore, KeyStoreError
from client.gui.key_dialog import KeyDialog


@pytest.fixture(scope="session")
def qapp():
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


def test_keystore_save_with_username(tmp_path):
    """При передаче username файлы именуются {username}_public.bkey и {username}_private.bkey."""
    kp = BignCrypto.generate_keypair()
    pub_file, priv_file = KeyStore.save_keys(tmp_path, kp, password=None, username="alice")

    assert pub_file.name == "alice_public.bkey"
    assert priv_file.name == "alice_private.bkey"
    assert pub_file.is_file()
    assert priv_file.is_file()

    # Проверка наличия метаданных
    pub_data = pub_file.read_bytes()
    priv_data = priv_file.read_bytes()
    assert b"USER:alice" in pub_data
    assert b"USER:alice" in priv_data


def test_keystore_save_without_username_backward_compatible(tmp_path):
    """Без username файлы сохраняются как public.bkey и private.bkey (обратная совместимость)."""
    kp = BignCrypto.generate_keypair()
    pub_file, priv_file = KeyStore.save_keys(tmp_path, kp, password=None, username=None)

    assert pub_file.name == "public.bkey"
    assert priv_file.name == "private.bkey"
    assert pub_file.is_file()
    assert priv_file.is_file()

    loaded_kp = KeyStore.load_keys(tmp_path, password=None)
    assert loaded_kp.public_key == kp.public_key
    assert loaded_kp.private_key == kp.private_key


def test_keystore_save_with_username_and_password(tmp_path):
    """Сохранение ключей с username и паролем."""
    kp = BignCrypto.generate_keypair()
    password = "SecretPassword456!"
    pub_file, priv_file = KeyStore.save_keys(tmp_path, kp, password=password, username="bob")

    assert pub_file.name == "bob_public.bkey"
    assert priv_file.name == "bob_private.bkey"

    # Загрузка Бобом с паролем успешна
    loaded_priv = KeyStore.load_private_key(priv_file, password=password, expected_username="bob")
    assert loaded_priv == kp.private_key

    # Попытка загрузки Алисой вызывает KeyStoreError о принадлежности другому пользователю
    with pytest.raises(KeyStoreError) as exc_info:
        KeyStore.load_private_key(priv_file, password=password, expected_username="alice")
    assert "Ключ принадлежит другому пользователю или не соответствует логину 'alice'" in str(exc_info.value)


def test_load_public_key_username_validation(tmp_path):
    """load_public_key проверяет соответствие имени файла и метаданных expected_username."""
    kp = BignCrypto.generate_keypair()
    pub_file, _ = KeyStore.save_keys(tmp_path, kp, username="alice")

    # Корректный пользователь
    pk = KeyStore.load_public_key(pub_file, expected_username="alice")
    assert pk == kp.public_key

    # Некорректный пользователь
    with pytest.raises(KeyStoreError) as exc_info:
        KeyStore.load_public_key(pub_file, expected_username="bob")
    assert "Ключ принадлежит другому пользователю или не соответствует логину 'bob'" in str(exc_info.value)


def test_load_private_key_username_validation(tmp_path):
    """load_private_key проверяет соответствие expected_username при загрузке без пароля."""
    kp = BignCrypto.generate_keypair()
    _, priv_file = KeyStore.save_keys(tmp_path, kp, username="charlie")

    # Корректный пользователь
    priv = KeyStore.load_private_key(priv_file, expected_username="charlie")
    assert priv == kp.private_key

    # Некорректный пользователь
    with pytest.raises(KeyStoreError) as exc_info:
        KeyStore.load_private_key(priv_file, expected_username="alice")
    assert "Ключ принадлежит другому пользователю или не соответствует логину 'alice'" in str(exc_info.value)


def test_find_user_keys(tmp_path):
    """find_user_keys находит пользовательские ключи либо выполняет fallback на стандартные."""
    kp = BignCrypto.generate_keypair()

    # 1. Сначала в директории ничего нет
    pub, priv = KeyStore.find_user_keys(tmp_path, username="alice")
    assert pub.name == "alice_public.bkey"
    assert priv.name == "alice_private.bkey"
    assert not pub.is_file()

    # 2. Сохраняем ключи alice
    KeyStore.save_keys(tmp_path, kp, username="alice")
    pub, priv = KeyStore.find_user_keys(tmp_path, username="alice")
    assert pub.is_file() and pub.name == "alice_public.bkey"
    assert priv.is_file() and priv.name == "alice_private.bkey"

    # 3. Для другого каталога со стандартными ключами public.bkey проверяем fallback
    sub_dir = tmp_path / "legacy"
    KeyStore.save_keys(sub_dir, kp, username=None)
    fallback_pub, fallback_priv = KeyStore.find_user_keys(sub_dir, username="bob")
    assert fallback_pub.name == "public.bkey"
    assert fallback_priv.name == "private.bkey"


def test_load_keys_full_cycle_with_username(tmp_path):
    """load_keys успешно загружает и верифицирует пару с ожидаемым именем пользователя."""
    kp = BignCrypto.generate_keypair()
    KeyStore.save_keys(tmp_path, kp, password=None, username="alice")

    loaded_kp = KeyStore.load_keys(tmp_path, password=None, expected_username="alice")
    assert loaded_kp.public_key == kp.public_key
    assert loaded_kp.private_key == kp.private_key

    # Попытка загрузить под именем bob вызывает KeyStoreError
    with pytest.raises(KeyStoreError):
        KeyStore.load_keys(tmp_path, password=None, expected_username="bob")


def test_key_dialog_ownership_validation(qapp, tmp_path):
    """
    KeyDialog._validate_key_ownership блокирует импорт ключей,
    если имя файла или метаданные не совпадают с текущим пользователем.
    """
    kp = BignCrypto.generate_keypair()
    alice_pub, alice_priv = KeyStore.save_keys(tmp_path, kp, username="alice")

    # Создаем диалог для пользователя bob
    dlg = KeyDialog(parent=None, initial_dir=str(tmp_path), username="bob")

    with patch("client.gui.key_dialog.QMessageBox.warning") as mock_warning:
        # Попытка валидировать чужой ключ alice_private.bkey для пользователя bob
        is_valid = dlg._validate_key_ownership(alice_priv)
        assert is_valid is False
        mock_warning.assert_called_once()
        args, kwargs = mock_warning.call_args
        assert "Ошибка импорта ключа: данный ключ не принадлежит пользователю 'bob'! Импорт чужих ключей запрещен." in args[2]

    # Валидация своего ключа
    bob_pub, bob_priv = KeyStore.save_keys(tmp_path, kp, username="bob")
    assert dlg._validate_key_ownership(bob_priv) is True
    assert dlg._validate_key_ownership(bob_pub) is True


def test_metadata_tampering_protection(tmp_path):
    """
    Если файл переименован под другого пользователя (например alice_public -> bob_public),
    но метаданные внутри указывают на исходного пользователя, попытка загрузки пресекается.
    """
    kp = BignCrypto.generate_keypair()
    pub_file, _ = KeyStore.save_keys(tmp_path, kp, username="alice")

    # Злоумышленник переименовывает alice_public.bkey в bob_public.bkey
    fake_bob_pub = tmp_path / "bob_public.bkey"
    fake_bob_pub.write_bytes(pub_file.read_bytes())

    # Боб пытается загрузить этот файл
    with pytest.raises(KeyStoreError) as exc_info:
        KeyStore.load_public_key(fake_bob_pub, expected_username="bob")
    assert "Ключ принадлежит другому пользователю или не соответствует логину 'bob'" in str(exc_info.value)


def test_case_insensitive_username_match(tmp_path):
    """Сравнение имени пользователя выполняется регистронезависимо."""
    kp = BignCrypto.generate_keypair()
    pub_file, priv_file = KeyStore.save_keys(tmp_path, kp, username="AliceUser")

    pk = KeyStore.load_public_key(pub_file, expected_username="aliceuser")
    assert pk == kp.public_key

    sk = KeyStore.load_private_key(priv_file, expected_username="ALICEUSER")
    assert sk == kp.private_key
