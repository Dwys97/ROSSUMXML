FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    make \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies (without AVX2 requirement)
RUN pip install --no-cache-dir \
    flask==3.0.0 \
    gunicorn==21.2.0 \
    huggingface-hub==0.20.2 \
    requests==2.31.0

# Install llama-cpp-python without AVX2 (compatible with older CPUs)
ENV CMAKE_ARGS="-DLLAMA_AVX=ON -DLLAMA_AVX2=OFF -DLLAMA_FMA=OFF -DLLAMA_F16C=OFF"
RUN pip install --no-cache-dir llama-cpp-python==0.2.27

COPY app.py .

# Create models directory
RUN mkdir -p /app/models

EXPOSE 5006

# Run with Gunicorn (4 workers for parallel requests)
CMD ["gunicorn", "--bind", "0.0.0.0:5006", "--workers", "2", "--timeout", "300", "--access-logfile", "-", "app:app"]
