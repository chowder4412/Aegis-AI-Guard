FROM mcr.microsoft.com/playwright/python:v1.52.0-jammy

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY backend/requirements.txt backend/requirements.txt

RUN pip install --upgrade pip \
    && pip install -r backend/requirements.txt

COPY backend ./backend
COPY firebase-applet-config.json ./firebase-applet-config.json

EXPOSE 8080

CMD ["sh", "-c", "python -m uvicorn backend.main:app --host 0.0.0.0 --port ${PORT:-8080}"]
