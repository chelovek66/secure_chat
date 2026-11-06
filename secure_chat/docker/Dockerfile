# ==============================================================================
# Secure Chat Server - Production Multi-Stage Dockerfile
# Conforms to Belarusian Security & Production Best Practices
# Non-root user execution, lightweight final image, health check integration
# ==============================================================================

# ----------------- Stage 1: Build Dependencies -----------------
FROM python:3.11-slim AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    git \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

# Установка зависимостей в изолированный каталог
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ----------------- Stage 2: Production Runtime -----------------
FROM python:3.11-slim AS runtime

LABEL maintainer="Secure Chat Dev Team"
LABEL description="Secure Chat Backend Server with Belarusian Cryptography Support"

# Создание непривилегированного системного пользователя
RUN groupadd -r appgroup && useradd -r -g appgroup -d /app -s /sbin/nologin -c "Secure Chat Service User" appuser

WORKDIR /app

# Копирование предварительно собранных пакетов из builder стадии
COPY --from=builder /install /usr/local

# Копирование исходных файлов сервера
COPY server/ /app/server/
COPY client/crypto/ /app/client/crypto/
COPY client/__init__.py /app/client/

# Настройка прав доступа
RUN chown -R appuser:appgroup /app

# Переключение на непривилегированного пользователя
USER appuser

# Переменные окружения
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app \
    HOST=0.0.0.0 \
    PORT=8000

EXPOSE 8000

# Встроенная проверка работоспособности (Healthcheck)
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; sys_exit = 0 if urllib.request.urlopen('http://localhost:8000/api/health').getcode() == 200 else 1; exit(sys_exit)"

# Запуск ASGI сервера Uvicorn
CMD ["python", "-m", "uvicorn", "server.app:app", "--host", "0.0.0.0", "--port", "8000", "--log-level", "info"]
