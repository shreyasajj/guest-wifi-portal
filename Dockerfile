FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /srv

COPY requirements.txt .
RUN pip install -r requirements.txt \
 && groupadd --system --gid 10001 portal \
 && useradd --system --uid 10001 --gid 10001 --home /srv portal \
 && mkdir -p /data && chown portal:portal /data

COPY app ./app
COPY --chmod=755 docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
# Starts as root only to fix /data ownership (bind mounts), then drops to uid 10001.

EXPOSE 8080
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz').status == 200 else 1)"

ENTRYPOINT ["docker-entrypoint.sh"]
# One worker: the event bus and OPNsense write locks live in-process.
# --no-proxy-headers: the app resolves X-Forwarded-For itself, only from TRUSTED_PROXIES.
CMD ["uvicorn", "app.main:app_factory", "--factory", "--host", "0.0.0.0", "--port", "8080", \
     "--workers", "1", "--no-proxy-headers", "--no-server-header"]
