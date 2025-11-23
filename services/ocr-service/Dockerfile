FROM python:3.10-slim-bookworm

WORKDIR /app

# Install system dependencies (minimal)
RUN apt-get update && apt-get install -y \
    libgomp1 \
    libglib2.0-0 \
    libsm6 \
    libxext6 \
    libxrender-dev \
    libgl1 \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Disable MKLDNN/oneDNN to prevent "could not create a primitive descriptor" error
ENV FLAGS_use_mkldnn=0
ENV FLAGS_enable_mkldnn=0
ENV CPU_NUM=1
ENV MKL_NUM_THREADS=1
ENV OMP_NUM_THREADS=1
ENV OPENBLAS_NUM_THREADS=1
ENV FLAGS_cpu_deterministic=true

# Copy application
COPY app.py .

# Expose port
EXPOSE 5002

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:5002/health')"

# Run application
CMD ["python", "app.py"]
