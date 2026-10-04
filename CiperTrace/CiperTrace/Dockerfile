# PS 26237 — Production Dockerfile for Google Cloud Run & Container Platforms
FROM python:3.11-slim

# Ensure logs appear immediately in Cloud Logging
ENV PYTHONUNBUFFERED=1 \
    PORT=8080 \
    PS26237_HOME=/tmp/ps26237_workspace

WORKDIR /app

# Install minimal OS dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY . .

# Expose port (Cloud Run sets PORT env var dynamically)
EXPOSE 8080

# Start with Gunicorn WSGI server (timeout 300s for forensic geometric watermark searches)
CMD ["sh", "-c", "exec gunicorn --bind 0.0.0.0:${PORT:-8080} --workers 1 --threads 8 --timeout 300 wsgi:app"]
