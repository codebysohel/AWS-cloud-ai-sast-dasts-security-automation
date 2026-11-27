# BASE_IMAGE is resolved to an immutable digest by pipeline.py.
ARG BASE_IMAGE=python:3.13-alpine
FROM ${BASE_IMAGE}
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    AWS_EC2_METADATA_DISABLED=true \
    PIP_DISABLE_PIP_VERSION_CHECK=1
RUN apk upgrade --no-cache \
    && addgroup -S -g 10001 app \
    && adduser -S -D -u 10001 -G app app
COPY requirements.lock ./requirements.lock
RUN python -m pip install --no-cache-dir --upgrade pip==26.3 \
    && python -m pip install --no-cache-dir -r requirements.lock \
    && python -m pip uninstall -y pip \
    && rm -rf /usr/local/lib/python3.13/ensurepip
COPY --chown=10001:10001 app.py aws_ops.py wsgi.py index.html styles.css app.js ./
USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=5s --start-period=15s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=3)"]
CMD ["gunicorn", "--bind=0.0.0.0:8000", "--workers=2", "--threads=2", "--timeout=120", "--worker-tmp-dir=/tmp", "--error-logfile=-", "wsgi:app"]
