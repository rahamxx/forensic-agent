# Use official slim Python 3.11 image
FROM python:3.11-slim-bookworm

# Metadata
LABEL maintainer="FORENSIC ENGINE Team"
LABEL description="AI-Powered Digital Forensics Investigation Agent"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=5000 \
    FLASK_ENV=production

# Install system dependencies (build-essential, OpenMP for scikit-learn/shap, whois, curl)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libgomp1 \
    whois \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy dependency specifications
COPY requirements.txt .

# Install Python packages
RUN pip install --no-cache-dir --upgrade pip setuptools wheel \
    && pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY . .

# Expose web service port
EXPOSE 5000

# Health check against Agent API
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:5000/api/agent/scenarios || exit 1

# Default startup command
CMD ["python", "app.py"]
