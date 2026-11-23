FROM python:3.12-slim AS builder

WORKDIR /app
COPY requirements.lock requirements-dev.lock ./
# Build tooling is locked too. Runtime image below contains only runtime dependencies.
RUN pip install --no-cache-dir --require-hashes -r requirements-dev.lock
COPY pyproject.toml README.md LICENSE ./
COPY relayvault ./relayvault
RUN pip wheel --no-deps --no-build-isolation --wheel-dir /wheels .

FROM python:3.12-slim
WORKDIR /app
COPY requirements.lock ./
RUN pip install --no-cache-dir --require-hashes -r requirements.lock \
    && groupadd --gid 10001 relayvault \
    && useradd --uid 10001 --gid 10001 --create-home relayvault \
    && install -d -m 0700 -o relayvault -g relayvault /data
COPY --from=builder /wheels /wheels
RUN pip install --no-cache-dir --no-deps /wheels/*.whl
USER relayvault
ENV RELAYVAULT_HOME=/data
VOLUME ["/data"]
EXPOSE 8000
CMD ["relayvault", "serve-api", "--host", "0.0.0.0", "--port", "8000"]
