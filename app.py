
from flask import Flask, jsonify, request, send_from_directory, abort, g
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path
import os
import uuid
import secrets
import hashlib
import hmac
import base64
import string
import random


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
APP_DIR = Path(__file__).resolve().parent

# Change these via environment variables in production.
ADMIN_TOKEN = os.environ.get("LICENSE_ADMIN_TOKEN", "CHANGE_ME_ADMIN_TOKEN_12345")
HMAC_SECRET = os.environ.get(
    "LICENSE_HMAC_SECRET",
    "CHANGE_ME_HMAC_SECRET_98765_DEADBEEF"
).encode("utf-8")
DOWNLOAD_TOKEN_TTL = int(os.environ.get("LICENSE_DOWNLOAD_TOKEN_TTL_SEC", "180"))
DEFAULT_TIER = os.environ.get("LICENSE_DEFAULT_TIER", "Standard")
DLL_DIR = Path(os.environ.get("LICENSE_DLL_DIR", APP_DIR / "payloads"))
DB_PATH = Path(os.environ.get("LICENSE_DB_PATH", APP_DIR / "licenses.db"))
HOST = os.environ.get("LICENSE_HOST", "0.0.0.0")
# --- RAILWAY PORT BINDING ---
# We ALWAYS bind the Flask app to port 5050 inside the container.
# Railway's public Service Domain forwards to internal port 5050
# (the target port you picked in Networking -> Generate Service Domain).
# Even if Railway sets $PORT to something else for healthchecking,
# the application itself listens on 5050 for the proxy traffic.
PORT = int(os.environ.get("LICENSE_PORT", "5050"))
DEBUG = os.environ.get("LICENSE_DEBUG", "0") == "1"

# Create required directories
DLL_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{DB_PATH}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)


# ---------------------------------------------------------------------------
# Database models
# ---------------------------------------------------------------------------
def _utcnow():
    return datetime.now(timezone.utc)


class Tier(db.Model):
    __tablename__ = "tiers"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True, nullable=False, index=True)
    # Relative filename inside DLL_DIR (e.g. "Standard.dll")
    dll_filename = db.Column(db.String(255), nullable=True)
    description = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=_utcnow)

    # One tier can have many keys
    keys = db.relationship("LicenseKey", back_populates="tier_rel", lazy=True)


class LicenseKey(db.Model):
    __tablename__ = "license_keys"
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(64), unique=True, nullable=False, index=True)
    tier_id = db.Column(db.Integer, db.ForeignKey("tiers.id"), nullable=False)
    hwid = db.Column(db.String(255), nullable=True, index=True)
    max_hwids = db.Column(db.Integer, default=1, nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    uses = db.Column(db.Integer, default=0, nullable=False)
    max_uses = db.Column(db.Integer, default=0, nullable=False)  # 0 = unlimited
    created_at = db.Column(db.DateTime, default=_utcnow, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=True)  # NULL = never expires
    last_used_at = db.Column(db.DateTime, nullable=True)
    last_used_ip = db.Column(db.String(64), nullable=True)
    note = db.Column(db.String(255), nullable=True)

    tier_rel = db.relationship("Tier", back_populates="keys")
    hwid_bindings = db.relationship(
        "HWIDBinding", back_populates="key_rel",
        cascade="all, delete-orphan", lazy=True
    )
    download_tokens = db.relationship(
        "DownloadToken", back_populates="key_rel",
        cascade="all, delete-orphan", lazy=True
    )


class HWIDBinding(db.Model):
    """Allows one key to be bound to up to LicenseKey.max_hwids devices."""
    __tablename__ = "hwid_bindings"
    id = db.Column(db.Integer, primary_key=True)
    key_id = db.Column(
        db.Integer, db.ForeignKey("license_keys.id", ondelete="CASCADE"),
        nullable=False, index=True
    )
    hwid = db.Column(db.String(255), nullable=False, index=True)
    bound_at = db.Column(db.DateTime, default=_utcnow, nullable=False)
    last_seen_at = db.Column(db.DateTime, default=_utcnow, nullable=False)
    last_seen_ip = db.Column(db.String(64), nullable=True)

    key_rel = db.relationship("LicenseKey", back_populates="hwid_bindings")


class DownloadToken(db.Model):
    """Single-use, short-lived download tokens returned by /validate."""
    __tablename__ = "download_tokens"
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(128), unique=True, nullable=False, index=True)
    key_id = db.Column(
        db.Integer, db.ForeignKey("license_keys.id", ondelete="CASCADE"),
        nullable=False, index=True
    )
    tier_id = db.Column(db.Integer, db.ForeignKey("tiers.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=_utcnow, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False, index=True)
    used = db.Column(db.Boolean, default=False, nullable=False)
    used_at = db.Column(db.DateTime, nullable=True)
    used_ip = db.Column(db.String(64), nullable=True)
    # Optional: remember the validation hwid so the download is tied to the
    # same device that validated the key.
    hwid = db.Column(db.String(255), nullable=True)

    key_rel = db.relationship("LicenseKey", back_populates="download_tokens")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _get_remote_ip():
    # If behind a reverse proxy like nginx, set X-Forwarded-For properly.
    if request.headers.get("X-Forwarded-For"):
        return request.headers["X-Forwarded-For"].split(",")[0].strip()
    return request.remote_addr or ""


def _sign(value: str) -> str:
    mac = hmac.new(HMAC_SECRET, value.encode("utf-8"), hashlib.sha256)
    return base64.urlsafe_b64encode(mac.digest()).decode("ascii").rstrip("=")


def _generate_human_key(segments: int = 4, seg_len: int = 4) -> str:
    alphabet = string.ascii_uppercase + string.digits
    while True:
        parts = [
            "".join(random.choices(alphabet, k=seg_len))
            for _ in range(segments)
        ]
        candidate = "-".join(parts)
        if not LicenseKey.query.filter_by(key=candidate).first():
            return candidate


def _fmt_dt(dt):
    if dt is None:
        return None
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _json_key(k: LicenseKey):
    return {
        "id": k.id,
        "key": k.key,
        "tier": k.tier_rel.name if k.tier_rel else None,
        "hwid": k.hwid,
        "max_hwids": k.max_hwids,
        "hwid_count": len(k.hwid_bindings),
        "is_active": bool(k.is_active),
        "uses": k.uses,
        "max_uses": k.max_uses,
        "created_at": _fmt_dt(k.created_at),
        "expires_at": _fmt_dt(k.expires_at),
        "last_used_at": _fmt_dt(k.last_used_at),
        "last_used_ip": k.last_used_ip,
        "note": k.note,
    }


# ---------------------------------------------------------------------------
# Admin authentication decorator
# ---------------------------------------------------------------------------
def require_admin(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        token = None
        auth_header = request.headers.get("Authorization", "")
        if auth_header.lower().startswith("bearer "):
            token = auth_header.split(" ", 1)[1].strip()
        if not token:
            token = request.args.get("admin_token") or (request.get_json(silent=True) or {}).get("admin_token")
        if not token or token != ADMIN_TOKEN:
            return jsonify({
                "valid": False,
                "error": "Unauthorized",
                "message": "Invalid or missing admin token. "
                           "Use header: Authorization: Bearer <LICENSE_ADMIN_TOKEN>"
            }), 401
        return f(*args, **kwargs)
    return wrapped


# ---------------------------------------------------------------------------
# Public license endpoints (same protocol the Xenos C++ client uses)
# ---------------------------------------------------------------------------
@app.route("/api/app/validate", methods=["POST"])
def validate_license():
    """
    Mirrors the Replit server protocol.
    Request JSON:  { "key": "...", "hwid": "..." }
    Response JSON:
      {
        "valid": true,
        "tier": "Premium",
        "downloadToken": "<single-use short-lived token>",
        "expiresAt": "2026-12-31T23:59:59Z",
        "message": "...",
        "signature": "<HMAC-SHA256 over tier|token|expiresAt|hwid>",
        "issuedAt": "<ISO timestamp>"
      }
    """
    body = request.get_json(silent=True) or {}
    raw_key = (body.get("key") or "").strip()
    raw_hwid = (body.get("hwid") or "").strip()

    if not raw_key:
        return jsonify({
            "valid": False,
            "message": "Missing license key"
        }), 200

    # Real-time lookup in the DB (every call is a server check)
    entry = LicenseKey.query.filter_by(key=raw_key).first()
    if not entry:
        return jsonify({
            "valid": False,
            "message": "Invalid license key"
        }), 200

    if not entry.is_active:
        return jsonify({
            "valid": False,
            "message": "This license key has been deactivated"
        }), 200

    if entry.expires_at and entry.expires_at <= _utcnow():
        return jsonify({
            "valid": False,
            "message": "This license key has expired"
        }), 200

    if entry.max_uses > 0 and entry.uses >= entry.max_uses:
        return jsonify({
            "valid": False,
            "message": f"This license key has reached its maximum usage limit ({entry.max_uses})"
        }), 200

    # HWID binding: enforce multi-HWID via HWIDBinding table for consistency.
    if raw_hwid:
        # Make sure there's a canonical HWID binding
        existing = next(
            (b for b in entry.hwid_bindings if str(b.hwid) == str(raw_hwid)),
            None
        )
        if existing:
            existing.last_seen_at = _utcnow()
            existing.last_seen_ip = _get_remote_ip()
        else:
            if len(entry.hwid_bindings) >= entry.max_hwids:
                return jsonify({
                    "valid": False,
                    "message": (
                        f"This key is already bound to {len(entry.hwid_bindings)} "
                        f"device(s) (max {entry.max_hwids})."
                    )
                }), 200
            binding = HWIDBinding(
                key_id=entry.id,
                hwid=str(raw_hwid),
                last_seen_ip=_get_remote_ip()
            )
            db.session.add(binding)
            # Legacy single-hwid field (kept in sync for backwards compat)
            if not entry.hwid:
                entry.hwid = str(raw_hwid)
    elif not entry.hwid_bindings and not entry.hwid:
        # No HWID provided on first validation — still allow the key to
        # validate, but the first valid HWID will bind on the next call.
        pass

    tier = entry.tier_rel
    if not tier:
        return jsonify({
            "valid": False,
            "message": "Server configuration error: key has no valid tier"
        }), 200

    # Increment usage counters *before* handing out a download token.
    entry.uses = (entry.uses or 0) + 1
    entry.last_used_at = _utcnow()
    entry.last_used_ip = _get_remote_ip()

    # Issue a single-use, short-lived download token
    now = _utcnow()
    exp = now + timedelta(seconds=DOWNLOAD_TOKEN_TTL)
    raw_dl_token = secrets.token_urlsafe(48)
    dl_token = DownloadToken(
        token=raw_dl_token,
        key_id=entry.id,
        tier_id=tier.id,
        expires_at=exp,
        hwid=raw_hwid or None,
    )
    db.session.add(dl_token)
    db.session.commit()

    issued_at = _fmt_dt(now)
    expires_at_str = _fmt_dt(entry.expires_at) or ""
    signature_payload = "|".join([
        tier.name,
        raw_dl_token,
        expires_at_str,
        raw_hwid or "",
        issued_at,
    ])
    signature = _sign(signature_payload)

    return jsonify({
        "valid": True,
        "tier": tier.name,
        "downloadToken": raw_dl_token,
        "expiresAt": expires_at_str,
        "issuedAt": issued_at,
        "signature": signature,
        "message": "License validated successfully",
        "hwidBound": bool(raw_hwid),
        "hwidCount": len(entry.hwid_bindings),
        "maxHwids": entry.max_hwids,
        "usesLeft": (
            "unlimited" if entry.max_uses == 0
            else max(entry.max_uses - entry.uses, 0)
        ),
    })


@app.route("/api/app/download/<path:tier_name>", methods=["GET"])
def download_payload(tier_name: str):
    """
    Protocol:  GET /api/app/download/<tier>?token=<downloadToken>
    Returns the DLL bytes (application/octet-stream) if:
      - tier exists in DB with a configured dll_filename
      - token exists, not used, not expired, and matches the tier
    """
    token = (request.args.get("token") or "").strip()
    if not token:
        return jsonify({
            "valid": False,
            "error": "Missing download token",
            "message": "Expected query parameter ?token=<downloadToken>"
        }), 400

    tier = Tier.query.filter_by(name=tier_name).first()
    if not tier or not tier.dll_filename:
        return jsonify({
            "valid": False,
            "error": "Invalid tier",
            "message": f"No payload configured for tier '{tier_name}'"
        }), 404

    dl = DownloadToken.query.filter_by(token=token).first()
    if not dl:
        return jsonify({
            "valid": False,
            "error": "Unknown token",
            "message": "Download token not found"
        }), 401

    now = _utcnow()
    if dl.used:
        return jsonify({
            "valid": False,
            "error": "Token already used",
            "message": "This download token has already been consumed"
        }), 409
    if dl.expires_at <= now:
        return jsonify({
            "valid": False,
            "error": "Token expired",
            "message": "This download token has expired. Re-validate the license key."
        }), 410
    if dl.tier_id != tier.id:
        return jsonify({
            "valid": False,
            "error": "Tier mismatch",
            "message": "Token was issued for a different tier"
        }), 403

    dll_path = DLL_DIR / tier.dll_filename
    if not dll_path.is_file():
        return jsonify({
            "valid": False,
            "error": "Payload missing",
            "message": "Server administrator has not yet uploaded the payload for this tier"
        }), 500

    # Mark the token as used (single-use) BEFORE sending the bytes so a
    # replay cannot generate multiple clean copies of the DLL.
    dl.used = True
    dl.used_at = now
    dl.used_ip = _get_remote_ip()
    db.session.commit()

    filename = tier.dll_filename
    return send_from_directory(
        directory=DLL_DIR,
        path=filename,
        as_attachment=True,
        download_name=filename,
        mimetype="application/octet-stream",
        max_age=0
    )


# ---------------------------------------------------------------------------
# Heartbeat / status
# ---------------------------------------------------------------------------
@app.route("/api/app/health", methods=["GET"])
def health():
    tiers = [
        {
            "name": t.name,
            "dll": t.dll_filename,
            "description": t.description,
            "dllPresent": bool(t.dll_filename and (DLL_DIR / t.dll_filename).is_file()),
        }
        for t in Tier.query.all()
    ]
    return jsonify({
        "ok": True,
        "server": "Xenos Self-Hosted License Server",
        "time": _fmt_dt(_utcnow()),
        "tiers": tiers,
        "keysTotal": db.session.query(func.count(LicenseKey.id)).scalar() or 0,
        "keysActive": db.session.query(func.count(LicenseKey.id)).filter_by(is_active=True).scalar() or 0,
    })


# ---------------------------------------------------------------------------
# Admin endpoints
# ---------------------------------------------------------------------------
@app.route("/api/admin/tier", methods=["POST"])
@require_admin
def admin_upsert_tier():
    """Create or update a tier. payload: {name, dll_filename?, description?}"""
    body = request.get_json(force=True, silent=True) or {}
    name = (body.get("name") or "").strip()
    if not name:
        return jsonify({"ok": False, "error": "name is required"}), 400
    tier = Tier.query.filter_by(name=name).first() or Tier(name=name)
    if "dll_filename" in body:
        tier.dll_filename = (body.get("dll_filename") or "").strip() or None
    if "description" in body:
        tier.description = (body.get("description") or "").strip() or None
    if tier.id is None:
        db.session.add(tier)
    db.session.commit()
    return jsonify({
        "ok": True,
        "tier": {
            "id": tier.id,
            "name": tier.name,
            "dll_filename": tier.dll_filename,
            "description": tier.description,
            "dllPresent": bool(tier.dll_filename and (DLL_DIR / tier.dll_filename).is_file()),
        }
    })


@app.route("/api/admin/tier/<name>", methods=["DELETE"])
@require_admin
def admin_delete_tier(name: str):
    tier = Tier.query.filter_by(name=name).first()
    if not tier:
        return jsonify({"ok": False, "error": "Tier not found"}), 404
    if tier.keys:
        return jsonify({
            "ok": False,
            "error": "Cannot delete tier: active keys are bound to it. "
                     "Revoke / delete the keys first."
        }), 409
    db.session.delete(tier)
    db.session.commit()
    return jsonify({"ok": True, "deleted": name})


@app.route("/api/admin/tiers", methods=["GET"])
@require_admin
def admin_list_tiers():
    tiers = []
    for t in Tier.query.order_by(Tier.name.asc()).all():
        tiers.append({
            "id": t.id,
            "name": t.name,
            "dll_filename": t.dll_filename,
            "description": t.description,
            "keys": len(t.keys),
            "dllPresent": bool(t.dll_filename and (DLL_DIR / t.dll_filename).is_file()),
        })
    return jsonify({"ok": True, "tiers": tiers})


@app.route("/api/admin/key", methods=["POST"])
@require_admin
def admin_create_key():
    """
    Create a new key. Optional fields:
      tier (str, default DEFAULT_TIER)
      format ("human" | "uuid", default human)
      segments, seg_len (for human format)
      validity_days (int, null=unlimited)
      max_uses (int, 0=unlimited)
      max_hwids (int, default 1)
      note (str)
      prebind_hwid (str)
    """
    body = request.get_json(force=True, silent=True) or {}
    tier_name = (body.get("tier") or DEFAULT_TIER).strip()
    tier = Tier.query.filter_by(name=tier_name).first()
    if not tier:
        # Auto-create the tier if it doesn't exist (convenience)
        tier = Tier(name=tier_name)
        db.session.add(tier)
        db.session.flush()

    key_format = (body.get("format") or "human").lower()
    if key_format == "uuid":
        new_key = str(uuid.uuid4()).upper()
    else:
        segments = int(body.get("segments") or 4)
        seg_len = int(body.get("seg_len") or 4)
        new_key = _generate_human_key(segments, seg_len)

    validity_days = body.get("validity_days")
    expires_at = None
    if validity_days:
        try:
            expires_at = _utcnow() + timedelta(days=float(validity_days))
        except (TypeError, ValueError):
            return jsonify({"ok": False, "error": "validity_days must be a number"}), 400

    max_uses = int(body.get("max_uses") or 0)
    max_hwids = int(body.get("max_hwids") or 1)
    note = (body.get("note") or "").strip() or None
    prebind_hwid = (body.get("prebind_hwid") or "").strip() or None

    entry = LicenseKey(
        key=new_key,
        tier_id=tier.id,
        expires_at=expires_at,
        max_uses=max_uses,
        max_hwids=max_hwids,
        note=note,
        hwid=prebind_hwid,
    )
    db.session.add(entry)

    if prebind_hwid:
        db.session.flush()
        db.session.add(HWIDBinding(
            key_id=entry.id,
            hwid=prebind_hwid,
        ))

    db.session.commit()
    return jsonify({
        "ok": True,
        "key": _json_key(entry),
        "download_endpoint": (
            f"/api/app/download/{tier.name}?token=<downloadToken>"
        ),
        "validate_endpoint": "/api/app/validate",
    })


@app.route("/api/admin/key/<path:key>", methods=["GET"])
@require_admin
def admin_get_key(key: str):
    entry = LicenseKey.query.filter_by(key=key).first()
    if not entry:
        return jsonify({"ok": False, "error": "Key not found"}), 404
    bindings = [
        {
            "hwid": b.hwid,
            "bound_at": _fmt_dt(b.bound_at),
            "last_seen_at": _fmt_dt(b.last_seen_at),
            "last_seen_ip": b.last_seen_ip,
        }
        for b in entry.hwid_bindings
    ]
    return jsonify({"ok": True, "key": _json_key(entry), "hwid_bindings": bindings})


@app.route("/api/admin/key/<path:key>", methods=["PATCH"])
@require_admin
def admin_update_key(key: str):
    """Toggle active, extend expiry, change tier/max_hwids/max_uses/note."""
    entry = LicenseKey.query.filter_by(key=key).first()
    if not entry:
        return jsonify({"ok": False, "error": "Key not found"}), 404
    body = request.get_json(force=True, silent=True) or {}
    if "is_active" in body:
        entry.is_active = bool(body["is_active"])
    if "tier" in body:
        tier = Tier.query.filter_by(name=str(body["tier"]).strip()).first()
        if not tier:
            return jsonify({"ok": False, "error": "Target tier does not exist"}), 404
        entry.tier_id = tier.id
    if "max_hwids" in body:
        try:
            entry.max_hwids = max(1, int(body["max_hwids"]))
        except (TypeError, ValueError):
            return jsonify({"ok": False, "error": "max_hwids must be int >= 1"}), 400
    if "max_uses" in body:
        try:
            entry.max_uses = max(0, int(body["max_uses"]))
        except (TypeError, ValueError):
            return jsonify({"ok": False, "error": "max_uses must be int >= 0"}), 400
    if "add_days" in body:
        try:
            add_days = float(body["add_days"])
            base = entry.expires_at or _utcnow()
            entry.expires_at = base + timedelta(days=add_days)
        except (TypeError, ValueError):
            return jsonify({"ok": False, "error": "add_days must be a number"}), 400
    if "validity_days" in body and body.get("validity_days") is not None:
        try:
            entry.expires_at = _utcnow() + timedelta(days=float(body["validity_days"]))
        except (TypeError, ValueError):
            return jsonify({"ok": False, "error": "validity_days must be a number"}), 400
    if "unlimited" in body and bool(body["unlimited"]):
        entry.expires_at = None
        entry.max_uses = 0
    if "note" in body:
        entry.note = (body.get("note") or "").strip() or None
    if "reset_hwids" in body and bool(body["reset_hwids"]):
        for b in entry.hwid_bindings:
            db.session.delete(b)
        entry.hwid = None
    db.session.commit()
    return jsonify({"ok": True, "key": _json_key(entry)})


@app.route("/api/admin/key/<path:key>", methods=["DELETE"])
@require_admin
def admin_delete_key(key: str):
    entry = LicenseKey.query.filter_by(key=key).first()
    if not entry:
        return jsonify({"ok": False, "error": "Key not found"}), 404
    db.session.delete(entry)
    db.session.commit()
    return jsonify({"ok": True, "deleted": key})


@app.route("/api/admin/keys", methods=["GET"])
@require_admin
def admin_list_keys():
    q = LicenseKey.query
    tier = (request.args.get("tier") or "").strip()
    if tier:
        t = Tier.query.filter_by(name=tier).first()
        if t:
            q = q.filter(LicenseKey.tier_id == t.id)
    only_active = request.args.get("active") == "1"
    if only_active:
        q = q.filter(LicenseKey.is_active == True)  # noqa: E712
    only_expired = request.args.get("expired") == "1"
    if only_expired:
        q = q.filter(LicenseKey.expires_at != None).filter(LicenseKey.expires_at <= _utcnow())  # noqa: E711
    search = (request.args.get("q") or "").strip()
    if search:
        like = f"%{search}%"
        q = q.filter(
            db.or_(
                LicenseKey.key.like(like),
                LicenseKey.hwid.like(like),
                LicenseKey.note.like(like),
            )
        )
    limit = min(int(request.args.get("limit") or 200), 2000)
    entries = q.order_by(LicenseKey.created_at.desc()).limit(limit).all()
    return jsonify({
        "ok": True,
        "count": len(entries),
        "keys": [_json_key(k) for k in entries],
    })


@app.route("/api/admin/stats", methods=["GET"])
@require_admin
def admin_stats():
    now = _utcnow()
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    week_ago = today_start - timedelta(days=7)
    return jsonify({
        "ok": True,
        "totals": {
            "tiers": db.session.query(func.count(Tier.id)).scalar() or 0,
            "keys": db.session.query(func.count(LicenseKey.id)).scalar() or 0,
            "keysActive": db.session.query(func.count(LicenseKey.id)).filter_by(is_active=True).scalar() or 0,
            "keysExpired": db.session.query(func.count(LicenseKey.id)).filter(
                LicenseKey.expires_at != None,  # noqa: E711
                LicenseKey.expires_at <= now
            ).scalar() or 0,
            "downloadTokensIssued": db.session.query(func.count(DownloadToken.id)).scalar() or 0,
            "downloadTokensUsed": db.session.query(func.count(DownloadToken.id)).filter_by(used=True).scalar() or 0,
        },
        "activity_last_7d": {
            "validations": db.session.query(func.count(LicenseKey.id)).filter(
                LicenseKey.last_used_at >= week_ago
            ).scalar() or 0,
            "downloads": db.session.query(func.count(DownloadToken.id)).filter(
                DownloadToken.used == True,  # noqa: E712
                DownloadToken.used_at >= week_ago
            ).scalar() or 0,
        }
    })


# ---------------------------------------------------------------------------
# Bootstrap: ensure default tier + DB tables exist
# ---------------------------------------------------------------------------
def _bootstrap():
    db.create_all()
    if not Tier.query.filter_by(name=DEFAULT_TIER).first():
        db.session.add(Tier(
            name=DEFAULT_TIER,
            description="Default tier — created on first server start",
            dll_filename=None,
        ))
        db.session.commit()


with app.app_context():
    _bootstrap()


if __name__ == "__main__":
    print("=" * 64)
    print(" SELF-HOSTED XENOS LICENSE SERVER")
    print("=" * 64)
    print(f" Listen         : http://{HOST}:{PORT}")
    print(f" Validate URL   : POST http://<host>:{PORT}/api/app/validate")
    print(f" Download URL   : GET  http://<host>:{PORT}/api/app/download/<tier>?token=...")
    print(f" Health URL     : GET  http://<host>:{PORT}/api/app/health")
    print(f" Admin endpoints: /api/admin/* (Authorization: Bearer <LICENSE_ADMIN_TOKEN>)")
    print(f" Payload dir    : {DLL_DIR}")
    print(f" Database       : {DB_PATH}")
    if ADMIN_TOKEN.startswith("CHANGE_ME"):
        print(" ⚠  WARNING: Set environment variable LICENSE_ADMIN_TOKEN before production use!")
    if HMAC_SECRET.startswith(b"CHANGE_ME"):
        print(" ⚠  WARNING: Set environment variable LICENSE_HMAC_SECRET before production use!")
    print("=" * 64)
    app.run(host=HOST, port=PORT, debug=DEBUG)
