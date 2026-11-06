# Инструкция по сборке криптографической библиотеки Bee2 (НИИ ППМИ БГУ)

Библиотека **Bee2** представляет собой официальную открытую реализацию криптографических стандартов Республики Беларусь, разработанную в НИИ прикладных проблем математики и информатики Белорусского государственного университета (НИИ ППМИ БГУ).

Официальный репозиторий: [https://github.com/agievich/bee2](https://github.com/agievich/bee2)

Библиотека реализует стандарты:
* **СТБ 34.101.31-2011 (belt)** — симметричное шифрование, выработка имитовставки (MAC), режимы ECB, CBC, CFB, CTR, CHE, MAC, KWP, DWP.
* **СТБ 34.101.45-2013 (bign)** — электронная цифровая подпись (ЭЦП) и транспортирование ключей на эллиптических кривых.
* **СТБ 34.101.47-2017 (bash)** — криптографическое хеширование и губкообразные функции.
* **СТБ 34.101.78-2017 (bkey)** — форматы ключевых контейнеров и защищенное хранилище.

---

## 1. Системные требования

### Для Windows:
1. **CMake** версии 3.15 или новее ([https://cmake.org/download/](https://cmake.org/download/)).
2. Компилятор C/C++:
   * **Microsoft Visual C++ (MSVC)**: Visual Studio 2019/2022 (с установленным компонентом «Desktop development with C++») **ИЛИ**
   * **MinGW-w64** (GCC for Windows).
3. **Git** для клонирования исходного кода.

### Для Linux (Ubuntu / Debian / Astra Linux / Red Hat):
```bash
sudo apt-get update
sudo apt-get install -y build-essential cmake git
```

---

## 2. Сборка для Windows (bee2.dll)

### Способ А: Сборка с использованием MSVC (Рекомендуется)

1. Откройте командную строку разработчика (**Developer Command Prompt for VS** или **x64 Native Tools Command Prompt**).
2. Склонируйте репозиторий `bee2`:
   ```cmd
   git clone https://github.com/agievich/bee2.git
   cd bee2
   ```
3. Создайте каталог сборки и сконфигурируйте проект как разделяемую библиотеку (`BUILD_SHARED_LIBS=ON`):
   ```cmd
   mkdir build
   cd build
   cmake .. -G "Visual Studio 17 2022" -A x64 -DBUILD_SHARED_LIBS=ON -DCMAKE_BUILD_TYPE=Release
   ```
4. Соберите проект:
   ```cmd
   cmake --build . --config Release
   ```
5. Запустите встроенные криптографические тесты Bee2:
   ```cmd
   ctest -C Release --output-on-failure
   ```
6. Найдите скомпилированную библиотеку `bee2.dll` (обычно в папке `bin\Release\` или `lib\Release\`).

---

### Способ Б: Сборка с использованием MinGW-w64

1. Откройте терминал (PowerShell или Bash):
   ```cmd
   git clone https://github.com/agievich/bee2.git
   cd bee2
   mkdir build && cd build
   cmake .. -G "MinGW Makefiles" -DBUILD_SHARED_LIBS=ON -DCMAKE_BUILD_TYPE=Release
   mingw32-make
   ```
2. Библиотека `bee2.dll` будет создана в каталоге `build/bin/` или `build/`.

---

## 3. Сборка для Linux (libbee2.so)

1. Клонирование и конфигурация:
   ```bash
   git clone https://github.com/agievich/bee2.git
   cd bee2
   mkdir build && cd build
   cmake .. -DBUILD_SHARED_LIBS=ON -DCMAKE_BUILD_TYPE=Release
   ```
2. Компиляция и тестирование:
   ```bash
   make -j$(nproc)
   ctest --output-on-failure
   ```
3. Скомпилированная библиотека `libbee2.so` будет расположена в каталоге `build/`.

---

## 4. Размещение библиотеки в Secure Chat

Для того чтобы приложение `Secure Chat` автоматически загрузило нативную библиотеку Bee2:

1. Скопируйте собранный файл библиотеки:
   * Для Windows: `bee2.dll`
   * Для Linux: `libbee2.so`
2. Поместите его в один из следующих каталогов:
   * **Вариант 1 (Рекомендуемый для проекта):**
     `secure_chat/client/crypto/bee2.dll` (или `libbee2.so`)
   * **Вариант 2 (Корневой каталог приложения):**
     `secure_chat/bee2.dll`
   * **Вариант 3 (Системный PATH):**
     Для Windows: `C:\Windows\System32\` или каталог, входящий в системный `%PATH%`.
     Для Linux: `/usr/local/lib/` (с последующим запуском `sudo ldconfig`).

---

## 5. Проверка статуса загрузки нативного модуля

Вы можете проверить, загрузилась ли нативная библиотека Bee2, выполнив команду Python:

```bash
python -c "from client.crypto.bee2_wrapper import Bee2NativeWrapper; print('Native loaded:', Bee2NativeWrapper.is_native_loaded())"
```

* Если вывод: `Native loaded: True` — используется C-библиотека Bee2 НИИ ППМИ БГУ.
* Если вывод: `Native loaded: False` — активирован резервный режим (Fallback Engine), полностью совместимый по интерфейсу, криптографическим тестам и тестовым векторам СТБ.
