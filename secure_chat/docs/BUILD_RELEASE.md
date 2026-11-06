# Руководство по сборке релиза и механизму безопасного обновления (ПЗ-4)

Данный документ описывает процесс сборки автономного исполняемого файла `.exe`, создания релизного пакета, генерации паспорта компонентов SBOM CycloneDX 1.5 и подписи манифеста цифровой подписью Ed25519 в программном комплексе **«Secure Chat»**.

---

## 1. Структура сборки и релизных артефактов

После выполнения скрипта сборки формируется следующая структура каталогов и файлов:

```
secure_chat/
├── dist/
│   └── SecureClient/                      # Каталог автономного приложения (--onedir)
│       ├── SecureClient.exe               # Исполняемый файл клиента
│       ├── bee2.dll                       # Библиотека национальной криптографии СТБ РБ
│       ├── config.json                    # Конфигурация клиента по умолчанию
│       ├── build_info.json                # Метаданные сборки и версии
│       ├── software_manifest.json         # Эталонный манифест контроля целостности ПО
│       └── _internal/                     # Python runtime, зависимости PyQt5, Qt dlls
├── release/
│   ├── SecureClient-2.1.0-win-x64.zip     # Релизный ZIP-пакет обновления
│   ├── manifest.json                      # Манифест релиза обновления (JSON)
│   ├── manifest.sig                       # Отсоединенная цифровая подпись манифеста (Base64)
│   ├── manifest.sig.bin                   # Сырая бинарная подпись манифеста (64 байта Ed25519)
│   └── sbom.json                          # Паспорт компонентов ПО в стандарте CycloneDX 1.5
├── release_keys/
│   ├── update_private.key                 # Закрытый ключ подписи релизов Ed25519 (PKCS#8 PEM)
│   └── update_public.key                  # Открытый ключ верификации обновлений (SubjectPublicKeyInfo PEM)
└── scripts/
    └── build_release.py                   # Автоматизированный скрипт сборки релиза
```

---

## 2. Порядок сборки релиза

Сборка полностью автоматизирована и может запускаться из корня репозитория:

```bash
# Запуск через скрипт в scripts/
python scripts/build_release.py

# Либо через корень проекта:
python build_release.py
```

### Автоматически выполняемые этапы:
1. **Генерация/загрузка ключей Ed25519**:
   - При отсутствии ключей в каталоге `release_keys/` автоматически создается новая ключевая пара `update_private.key` и `update_public.key`.
2. **Генерация паспорта компонентов (SBOM)**:
   - Создается файл `release/sbom.json` по стандарту **CycloneDX 1.5 JSON**.
   - Фиксируются точные версии: `cryptography`, `PyQt5`, `requests`, `fastapi`, `uvicorn`, `pydantic` и криптоядра `bee2.dll` (с вычислением SHA-256).
   - Вычисляется SHA-256 контрольная сумма самого `sbom.json`.
3. **Компиляция через PyInstaller**:
   - Параметры: `--onedir --windowed --name SecureClient client/main.py`.
   - Включаются ресурсы: `bee2.dll`, `config.json`, `build_info.json`, `software_manifest.json`.
4. **Проверка целостности каталога `dist/SecureClient`**:
   - Проверяется физическое присутствие `SecureClient.exe`, `bee2.dll` и конфигурационных файлов.
5. **Быстрый самодиагностический Smoke-тест**:
   - Бинарник запускается с параметром `SecureClient.exe --smoke-test`.
   - Проверяется корректная инициализация Qt5, загрузка C-библиотеки `bee2.dll` и чтение конфигурации без блокировки GUI.
6. **Упаковка пакета релиза**:
   - Создается ZIP-архив `release/SecureClient-2.1.0-win-x64.zip`.
   - Вычисляются точный размер в байтах и контрольная сумма SHA-256 архива.
7. **Формирование и подписание релизного манифеста**:
   - Создается `release/manifest.json` в формате ПЗ-4.
   - Манифест подписывается закрытым ключом Ed25519:
     - Поле `"signature"` содержит Base64-подпись канонизированных данных манифеста.
     - Файл `release/manifest.sig` содержит отсоединенную Base64-подпись файла манифеста.
8. **Комплексная криптографическая проверка**:
   - Автоматическая валидация подписей, контрольных сумм и размера пакета.

---

## 3. Спецификация манифеста обновления (`manifest.json`)

```json
{
  "version": "2.1.0",
  "min_supported": "1.0.0",
  "release_date": "2026-11-06T14:47:28.715041+00:00",
  "os": "windows",
  "arch": "x64",
  "package_url": "/updates/download/2.1.0",
  "package_size": 89270697,
  "package_sha256": "671908451d2cd57af5d58e0ccd89c22668d0e06dca673e1d34af697f7ea1d00f",
  "signature": "K9OOa845Xq3Si7yjWGq7Qmv1iZ8440U/C3wCNTsllJ/6yOUjb6SdU3jeUm/btjxa29ZZTv1+0QGaETMiDa5RCA==",
  "sbom": {
    "format": "CycloneDX-1.5",
    "url": "/updates/sbom/2.1.0.json",
    "sha256": "95b44c08d8e6b8192c723fe8b59f8b29a47964781ab6d13d585a8582af05c406"
  },
  "critical": false
}
```

---

## 4. Проверка и установка обновлений

### 4.1. Автоматическое обновление через клиент (Updater)

В коде клиента модуль `client.updater.Updater` поддерживает как Online-режим (через REST API `/updates/*`), так и Offline-режим (из локальной папки):

```python
from client.updater import Updater, FileSource
from common.update_crypto import load_public_key

# Загрузка доверенного ключа релиза
pub_key = load_public_key("release_keys/update_public.key")

# Инициализация Offline-обновления из манифеста
updater = Updater(
    source=FileSource("release/manifest.json"),
    public_key=pub_key,
    current_version="2.0.0",
    app_dir="C:/Program Files/SecureClient"
)

# Выполнение проверки, распаковки в staging, сверки SBOM и атомарной замены app -> backup
success = updater.run_update()
```

### 4.2. Ручная проверка подписи манифеста через Python

```python
import json
from pathlib import Path
from common.update_crypto import verify_manifest, load_public_key

manifest_data = json.loads(Path("release/manifest.json").read_text(encoding="utf-8"))
pub_key = load_public_key("release_keys/update_public.key")

is_valid = verify_manifest(manifest_data, pub_key)
print("Манифест подлинный:", is_valid)
```

---

## 5. Запуск тестов проверки сборки

Для автоматического тестирования релизного пакета и SBOM разработан набор тестов:

```bash
pytest tests/test_release_package.py -v
```

Все 5 тестов проверяют:
- Существование архива, ключей, SBOM и подписи;
- Корректность вложенных в ZIP файлов (`SecureClient.exe`, `bee2.dll`, `config.json`, `sbom.json`);
- Спецификацию CycloneDX 1.5;
- SHA-256 пакета и SBOM;
- Цифровую подпись Ed25519 (встроенную и отсоединенную).
