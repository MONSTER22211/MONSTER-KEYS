# =============================================================================
#  EPIC License Server — Production Dockerfile for Railway.app
# =============================================================================
#
#  USAGE (from repo root — you configured Railway Root Directory = "server"):
#    docker build -t epic-license-server:latest ./server
#    docker run --rm \
#      -e LICENSE_ADMIN_TOKEN='super-secret-admin-key' \
#      -e LICENSE_HMAC_SECRET='hmac-signing-key' \
#      -v "$(pwd)/data:/app/data" \
#      -v "$(pwd)/payloads:/app/payloads" \
#      -p 8080:8080 \
#      epic-license-server:latest
#
#  The server listens on 0.0.0.0:8080 by default. Railway.app Service Domain
#  Target Port in Networking -> Configure should be set to 8080.
# =============================================================================

FROM docker.io/library/python:3.11-slim@sha256:90744cff8f32887f075c47d747a173ff333e9e98801667af93c357fa9f5e28ff

# --- Labels / Metadata ---------------------------------------------------------
LABEL org.opencontainers.image.title="EPIC License Server"
LABEL org.opencontainers.image.description="Self-hosted Flask license server with tiered DLL payload delivery."
LABEL org.opencontainers.image.source="https://github.com/EPIC-NEW-LOOK"

# --- Upgrade system packages + install prod dependencies ----------------------
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      curl \
      ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && python3 -m pip install --no-cache-dir --upgrade pip setuptools wheel

# --- Create directories the app will write to ---------------------------------
RUN mkdir -p /app/data /app/payloads

# --- App workdir --------------------------------------------------------------
WORKDIR /app

# --- Install Python deps (cached layer — changes only when requirements.txt)
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# --- Copy application source --------------------------------------------------
COPY app.py keygen.py ./

# --- Provide safe defaults that work in both dev + Railway --------------------
# NOTE: Never put real secrets here. Override at run time via Railway Variables.
ENV LICENSE_ADMIN_TOKEN=CHANGE_ME_DEFAULT_ADMIN_TOKEN_DO_NOT_USE_PROD
ENV LICENSE_HMAC_SECRET=CHANGE_ME_DEFAULT_HMAC_SECRET_DO_NOT_USE_PROD

# -----------------------------------------------------------------------------
#  Railway.app note — DO NOT CHANGE the PORT default below.
#
#  Railway injects $PORT automatically (default: 8080) when the Service Domain
#  is created. The app in app.py reads $PORT first via:
#     PORT = int(os.environ.get("LICENSE_PORT", os.environ.get("PORT", "8080")))
#  So Flask + gunicorn always bind to the same port Railway routes to.
#
#  Railway Networking -> Service Domain -> Target Port: 8080
#  Railway Volumes:  /app/data     (SQLite DB, name: license-db)
#                    /app/payloads (DLL files,    name: license-payloads)
# -----------------------------------------------------------------------------
ENV LICENSE_PORT=8080
ENV LICENSE_HOST=0.0.0.0
ENV LICENSE_DEBUG=0
ENV LICENSE_DB_PATH=/app/data/licenses.db
ENV LICENSE_DLL_DIR=/app/payloads
ENV PYTHONUNBUFFERED=1

EXPOSE 8080

# --- Runtime volumes ----------------------------------------------------------
# (Declared here for documentation + Railway volume hinting.
#  You still need to attach real volumes via Railway.app UI / CLI.)
VOLUME ["/app/data", "/app/payloads"]

# --- Healthcheck --------------------------------------------------------------
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=6 \
  CMD curl -fsS "http://127.0.0.1:${LICENSE_PORT}/api/app/health" || exit 1

# -----------------------------------------------------------------------------
#  ENTRYPOINT (Railway DOES NOT override ENTRYPOINT — only CMD).
#  We use a shell ENTRYPOINT that always runs — this gunicorn CANNOT be
#  bypassed accidentally. If gunicorn is missing (pip install skipped it),
#  we fall back to Flask dev server AND print a clear warning.
# -----------------------------------------------------------------------------
ENTRYPOINT ["/bin/bash", "-c", "\
set -e; \
echo '============================================================'; \
echo ' EPIC LICENSE SERVER — RAILWAY ENTRYPOINT'; \
echo '============================================================'; \
echo \" Host bind: $LICENSE_HOST\"; \
echo \" Port:      $LICENSE_PORT\"; \
echo \" DB:        $LICENSE_DB_PATH\"; \
echo \" Payloads:  $LICENSE_DLL_DIR\"; \
echo '============================================================'; \
if command -v gunicorn >/dev/null 2>&1; then \
  echo '[INFO] gunicorn found — starting PRODUCTION workers (4 workers × 2 threads)...'; \
  exec gunicorn \
    --bind \"$LICENSE_HOST:$LICENSE_PORT\" \
    --workers 4 \
    --threads 2 \
    --timeout 120 \
    --graceful-timeout 30 \
    --keep-alive 5 \
    --access-logfile - \
    --error-logfile - \
    --log-level info \
    app:app; \
else \
  echo '[WARN] gunicorn NOT installed — falling back to Flask DEV server.'; \
  echo '[WARN] This is OK for testing but NOT for real production load.'; \
  echo '[WARN] Fix: make sure requirements.txt lists gunicorn>=21.2.0, then rebuild.'; \
  exec python -u app.py; \
fi"]
