# ── Nigerian Fintech DevSecOps - App Dockerfile ────────────────
# Used by the CI/CD pipeline for Trivy container scanning

# Python 3.9 reached end-of-life in October 2025; 3.12 receives security patches
FROM python:3.12-slim

# Security: non-root user
RUN useradd -m -u 1001 appuser
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN mkdir -p reports && chown -R appuser:appuser /app

USER 1001

EXPOSE 8501

CMD ["streamlit", "run", "dashboard/app.py", "--server.port=8501", "--server.address=0.0.0.0"]
