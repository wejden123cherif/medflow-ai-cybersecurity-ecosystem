FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    HF_HOME=/app/.cache/huggingface \
    SENTENCE_TRANSFORMERS_HOME=/app/.cache/huggingface/sentence-transformers

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./requirements.txt

# Use the CPU-only torch wheel. The default PyPI torch build pulls a large CUDA stack,
# which makes the container build unnecessarily heavy and extremely slow on a fresh VM.
RUN python -m pip install --upgrade pip setuptools wheel && \
    python -m pip install --index-url https://download.pytorch.org/whl/cpu \
        torch==2.6.0+cpu && \
    python -m pip install -r requirements.txt

COPY . .

RUN chmod +x /app/docker/init-medflow.sh

EXPOSE 8000

CMD ["/bin/bash", "/app/docker/init-medflow.sh"]
