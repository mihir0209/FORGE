FROM node:22-bookworm-slim AS frontend
WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM python:3.12-slim-bookworm AS runtime
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PYTHONHASHSEED=0
RUN apt-get update && apt-get install -y --no-install-recommends ffmpeg curl \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
COPY configs ./configs
COPY vendor ./vendor
COPY --from=frontend /app/frontend/dist ./frontend/dist
RUN pip install --no-cache-dir .
RUN useradd --system --uid 10001 forge && mkdir -p /data && chown -R forge:forge /app /data
USER forge
EXPOSE 8000
CMD ["uvicorn", "forge.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
