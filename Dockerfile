FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml README.md ./
COPY relayvault ./relayvault

RUN pip install --no-cache-dir .

ENV RELAYVAULT_HOME=/data
VOLUME ["/data"]

EXPOSE 8000 8090

CMD ["relayvault", "serve-api", "--host", "0.0.0.0", "--port", "8000"]