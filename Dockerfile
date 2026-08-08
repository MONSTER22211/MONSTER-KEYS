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

# Launch with production-grade gunicorn WSGI server.
# Railway's reverse proxy handles HTTPS/TLS — gunicorn only needs plain HTTP.
# - bind 0.0.0.0:5050 so internal container binds to the port Railway expects
#   (target port 5050 = the one you entered in Networking -> Generate Service Domain)
# - 4 workers = good default for 1 vCPU; Railway scales worker count via env if you set WEB_CONCURRENCY
# - --access-logfile -   prints access logs to stdout (visible in Railway Deploy Logs)
# - --timeout 120         avoids gunicorn killing slow downloads of large DLLs
# - Forward SIGTERM cleanly for zero-downtime Railway redeploys
EXPOSE 5050
CMD ["gunicorn", \
     "--bind", "0.0.0.0:5050", \
     "--workers", "4", \
     "--threads", "2", \
     "--timeout", "120", \
     "--graceful-timeout", "30", \
     "--keep-alive", "5", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "--log-level", "info", \
     "app:app"]
