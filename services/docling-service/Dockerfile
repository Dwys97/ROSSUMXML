FROM python:3.10-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    libgomp1 \
    libglib2.0-0 \
    libsm6 \
    libxext6 \
    libxrender-dev \
    libgl1 \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Create non-root user
RUN useradd -m -u 1000 docling

# Make RapidOCR models directory writable for non-root user
# RapidOCR hardcodes the model path, so we need to make it writable
RUN mkdir -p /usr/local/lib/python3.10/site-packages/rapidocr/models && \
    chmod -R 777 /usr/local/lib/python3.10/site-packages/rapidocr/models

# Copy application code
COPY app.py .
RUN chown -R docling:docling /app /home/docling

# Switch to non-root user
USER docling

# Pre-download RapidOCR models (will now succeed with writable directory)
RUN python -c "from rapidocr_onnxruntime import RapidOCR; RapidOCR()" 2>/dev/null || true

EXPOSE 5004

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=90s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5004/health')"

CMD ["gunicorn", "--bind", "0.0.0.0:5004", "--workers", "2", "--timeout", "120", "app:app"]
