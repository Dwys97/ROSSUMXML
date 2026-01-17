FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    git \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app.py .

# Create cache directory for model and set permissions
RUN mkdir -p /app/models && chmod 755 /app/models

# Create non-root user
RUN useradd -m -u 1000 qwen && chown -R qwen:qwen /app
USER qwen

# Environment for HuggingFace cache
ENV HF_HOME=/app/models
ENV TRANSFORMERS_CACHE=/app/models
ENV HF_HUB_ENABLE_HF_TRANSFER=1

# CPU-only settings
ENV CUDA_VISIBLE_DEVICES=""
ENV TORCH_DEVICE="cpu"

EXPOSE 5005

# Model downloads on first request (~14GB for Qwen2.5-VL-7B)
HEALTHCHECK --interval=30s --timeout=15s --start-period=600s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5005/health')"

CMD ["gunicorn", "--bind", "0.0.0.0:5005", "--workers", "1", "--timeout", "600", "--worker-class", "sync", "app:app"]
