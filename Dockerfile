# mem-guard gateway image.
FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

RUN groupadd --gid 10002 memguard \
    && useradd --uid 10002 --gid memguard --create-home --shell /usr/sbin/nologin memguard

COPY pyproject.toml README.md LICENSE ./
COPY mem_guard ./mem_guard

RUN pip install ".[gateway]" \
    && mkdir -p /var/lib/mem-guard \
    && chown -R memguard:memguard /app /var/lib/mem-guard

USER memguard

ENV MEM_GUARD_ENVIRONMENT=production \
    MEM_GUARD_STATE_DIR=/var/lib/mem-guard \
    MEM_GUARD_ALLOW_DEFAULT_SCOPE=false

VOLUME ["/var/lib/mem-guard"]
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=3)"]

CMD ["python", "-m", "uvicorn", "mem_guard.server:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "1"]
