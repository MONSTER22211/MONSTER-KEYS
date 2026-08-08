# =============================================================================
#  Dockerfile for Railway.app — Self-Hosted Xenos License Server
# =============================================================================
#  Railway detects Dockerfiles automatically.
#  To deploy: push this folder to GitHub, then in Railway:
#    1. New Project -> "Deploy from GitHub repo" -> pick your repo
#    2. Root Directory: set to the folder containing THIS Dockerfile (e.g. /server)
#    3. Add Environment Variables (Railway Dashboard -> Variables):
#         LICENSE_ADMIN_TOKEN      — long random string (keep it secret!)
#         LICENSE_HMAC_SECRET      — long random string (different from admin)
#       Optionally:
#         LICENSE_DEFAULT_TIER     — default tier name for new keys
#         LICENSE_DOWNLOAD_TOKEN_TTL_SEC — single-use token lifetime, default 180
#    4. Add Persistent Volumes (Railway Dashboard -> Settings -> Volumes):
#         Volume name: license-db       Mount path: /app/data
#         Volume name: license-payloads Mount path: /app/payloads
#    5. Deploy! Railway will set PORT automatically.
# =============================================================================

FROM python:3.11-slim

WORKDIR /app

# Install Python deps FIRST (cached Docker layer — unchanged requirements.txt => fast rebuild)
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy the current directory contents into the container at /app
COPY . .

# Create writable directories (volumes will be mounted here at Railway runtime)
RUN mkdir -p /app/payloads /app/data

# ---------------------------------------------------------------------------
# Default runtime configuration.
# ALWAYS override LICENSE_ADMIN_TOKEN + LICENSE_HMAC_SECRET via Railway
# Variables dashboard — do NOT rely on these defaults in production!
# ---------------------------------------------------------------------------
ENV LICENSE_ADMIN_TOKEN=CHANGE_ME_ADMIN_TOKEN_12345 \
    LICENSE_HMAC_SECRET=CHANGE_ME_HMAC_SECRET_98765_DEADBEEF \
    LICENSE_HOST=0.0.0.0 \
    LICENSE_PORT=5050 \
    LICENSE_DB_PATH=/app/data/licenses.db \
    LICENSE_DLL_DIR=/app/payloads \
    LICENSE_DEBUG=0

# Railway auto-injects $PORT at runtime. The Python app reads $PORT first
# (see app.py), so EXPOSE here is purely documentation + local testing.
EXPOSE 5050

# Health check — Railway/Services use this for zero-downtime deployments.
# Hits the public /api/app/health endpoint (no auth required).
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request,sys; port='${PORT:-5050}'; \
    urllib.request.urlopen(f'http://127.0.0.1:{port}/api/app/health', timeout=3); \
    sys.exit(0)" || exit 1

# Launch with unbuffered I/O so Railway logs show Flask output in real time.
# Use exec form so signals (SIGTERM from Railway deploys) are forwarded to Flask.
CMD ["python", "-u", "app.py"]
