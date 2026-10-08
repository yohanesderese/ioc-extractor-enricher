FROM python:3.12-slim AS builder
WORKDIR /build
COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/
RUN python -m pip wheel --no-cache-dir --wheel-dir /wheels .

FROM python:3.12-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
COPY --from=builder /wheels /wheels
RUN python -m pip install --no-cache-dir --no-index --find-links=/wheels ioc-extractor-enricher \
    && rm -rf /wheels \
    && groupadd --gid 10001 iocdesk \
    && useradd --uid 10001 --gid iocdesk --no-create-home iocdesk \
    && mkdir /data \
    && chown iocdesk:iocdesk /data
WORKDIR /data
USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/openapi.json', timeout=3).close()"]
CMD ["uvicorn", "ioc_extractor_enricher.app:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", "--no-access-log"]
