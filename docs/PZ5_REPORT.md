# Практическое занятие №5: Отчет и руководство по сдаче

**Тема:** «Размещение учебного проекта в Git и организация работы через Kanban-доску»  
**Репозиторий проекта:** [https://github.com/chelovek66/secure_chat.git](https://github.com/chelovek66/secure_chat.git)  
**Проект:** Мессенджер с криптографической защитой «Secure Chat» (СТБ 34.101.31 / СТБ 34.101.45 / Bee2)

---

## 1. Конфигурация Git и репозитория
* Инициализирован репозиторий: `git init` (ветка `main`).
* Конфигурация автора:
  ```powershell
  git config user.name "Student Developer"
  git config user.email "student@example.com"
  git config init.defaultBranch main
  ```
* Remote Origin:
  ```powershell
  git remote add origin https://github.com/chelovek66/secure_chat.git
  ```

---

## 2. Исключения в `.gitignore`
В корне проекта создан файл `.gitignore`, исключающий:
* Байткод и кэши: `__pycache__/`, `*.py[cod]`, `.pytest_cache/`, `.coverage`.
* Базы данных SQLite: `*.db`, `server/*.db`, `secure_chat/server/*.db`.
* Журналы логирования: `logs/`, `*.log`, `*.csv`.
* Сборка C-библиотеки Bee2: `secure_chat/bee2/build/`, `secure_chat/bee2/bee2/build/`.
* Временные файлы методичек: `pz*.txt`, `tz*.txt`.

---

## 3. Задачи (Issues) для Kanban-доски проекта
На GitHub Projects организована Kanban-доска с колонками: **Backlog**, **In Progress**, **Review**, **Done**.

1. **Issue #1:** Реализация асимметричного сквозного шифрования (Bee2 bign + belt-che) — [Done]
2. **Issue #2:** Разработка потокобезопасного REST API сервера с очередями сообщений — [Done]
3. **Issue #3:** Аутентификация пользователей по паролю и отпечатку устройства (Device Fingerprint) — [Done]
4. **Issue #4:** Модуль безопасного обновления ПО с контролем целостности и SBOM — [Done]
5. **Issue #5:** Организация Git-репозитория и рабочего процесса по Kanban — [Done]

---

## 4. История коммитов и слияний (--no-ff)
* Базовый коммит: `chore: initial commit: project structure and source code`
* Ветка `feature/3-auth-fingerprint` -> коммит `feat: implement user authentication and device fingerprinting Closes #3` -> слияние в `main` с `--no-ff`.
* Ветка `feature/4-secure-updater` -> коммит `feat: implement secure update mechanism with SBOM and Ed25519 Closes #4` -> слияние в `main` с `--no-ff`.
* Ветка `feature/5-git-kanban` -> коммит `docs: setup git workflow and kanban board documentation Closes #5` -> слияние в `main` с `--no-ff`.

---

## 5. Команды отправки на GitHub в 1 клик
```powershell
# Отправка основной ветки
git push -u origin main

# Отправка всех веток истории
git push --all origin
```
Полная версия отчета со всеми таблицами и чек-листом защиты доступна в файле [KANBAN_AND_GIT_REPORT.md](../KANBAN_AND_GIT_REPORT.md).
