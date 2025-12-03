FROM python:3.10-slim

WORKDIR /app

# Install system dependencies for llama.cpp
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    libgomp1 \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN CMAKE_ARGS="-DLLAMA_BLAS=ON -DLLAMA_BLAS_VENDOR=OpenBLAS" \
    pip install --no-cache-dir -r requirements.txt

# Create models directory
RUN mkdir -p /app/models

# Download Qwen2.5-0.5B-Instruct GGUF model (Q4_0 quantized, ~300MB)
RUN wget -O /app/models/qwen2.5-0.5b-instruct-q4_0.gguf \
    https://huggingface.co/Qwen/Qwen2.5-0.5B-Instruct-GGUF/resolve/main/qwen2.5-0.5b-instruct-q4_0.gguf

# Copy application code
COPY app.py .

# Create non-root user
RUN useradd -m -u 1000 qwen && chown -R qwen:qwen /app
USER qwen

EXPOSE 5005

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=120s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5005/health')"

CMD ["gunicorn", "--bind", "0.0.0.0:5005", "--workers", "1", "--timeout", "180", "app:app"]
