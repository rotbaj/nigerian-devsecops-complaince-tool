# ── Nigerian Fintech DevSecOps - App Dockerfile ────────────────
# Used by the CI/CD pipeline for Trivy container scanning

# Python 3.9 reached end-of-life in October 2025; 3.12 receives security patches
FROM python:3.12-slim

# Apply Debian security updates at build time. The base image is rebuilt on
# its own schedule, so it lags behind fixes Debian has already published: the
# util-linux CVE-2026-53615 batch was patched in 2.41.5-0+deb13u1 while the
# base still shipped 2.41-5, failing the image scan. Upgrading here clears
# that whole class of finding instead of risk-accepting each one in turn.
RUN apt-get update \
    && apt-get upgrade -y \
    && rm -rf /var/lib/apt/lists/*

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
