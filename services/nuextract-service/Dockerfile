FROM python:3.10-slim

WORKDIR /app

# Install system dependencies for llama-cpp-python
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Create model directory (model will be downloaded on first run)
RUN mkdir -p /app/models && chmod 777 /app/models

# Copy application code
COPY app.py .

# Create non-root user
RUN useradd -m -u 1000 nuextract && chown -R nuextract:nuextract /app
USER nuextract

EXPOSE 5005

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=180s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5005/health')"

CMD ["gunicorn", "--bind", "0.0.0.0:5005", "--workers", "1", "--timeout", "300", "--worker-class", "sync", "app:app"]
