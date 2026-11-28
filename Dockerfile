FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
WORKDIR /app
COPY pyproject.toml README.md ./
COPY app ./app
RUN pip install --no-cache-dir . \
    && useradd --create-home --uid 10001 zyrax \
    && mkdir -p /app/data \
    && chown -R zyrax:zyrax /app
USER zyrax
EXPOSE 8000
CMD ["python", "-m", "app"]
