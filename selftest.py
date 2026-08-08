
"""
Self-test for the self-hosted license server.

Uses Flask's test client so no network listener is required. Covers:
  1. Health endpoint
  2. Admin auth failure + success
  3. Tier management
  4. Key creation / update / list / delete
  5. Real-time validation flow (/api/app/validate -> download token -> download)
  6. Error cases: invalid key, expired key, revoked key, wrong HWID,
     reused / expired / tier-mismatched download token
"""
from __future__ import annotations
import os
import sys
import json
import tempfile
import shutil
import io
import zipfile
from pathlib import Path

SERVER_DIR = Path(__file__).resolve().parent
os.environ.setdefault("LICENSE_ADMIN_TOKEN", "SELFTEST_ADMIN_TOKEN")
os.environ.setdefault("LICENSE_HMAC_SECRET", "SELFTEST_HMAC_SECRET")
os.environ.setdefault("LICENSE_PORT", "5050")
# Redirect DB + DLL dir to a temp location
tmp = Path(tempfile.mkdtemp(prefix="lic_selftest_"))
os.environ["LICENSE_DB_PATH"] = str(tmp / "licenses.db")
os.environ["LICENSE_DLL_DIR"] = str(tmp / "payloads")
(tmp / "payloads").mkdir(parents=True, exist_ok=True)

# Force a fresh import
for mod_name in list(sys.modules.keys()):
    if mod_name == "app" or mod_name.startswith("app."):
        del sys.modules[mod_name]

sys.path.insert(0, str(SERVER_DIR))
import app as server_app  # noqa: E402

ADMIN = {"Authorization": "Bearer SELFTEST_ADMIN_TOKEN"}
BAD_ADMIN = {"Authorization": "Bearer WRONG"}
JSON = {"Content-Type": "application/json"}
failures = []


def run(tid: int):
    client = server_app.app.test_client()

    def check(label: str, cond: bool, detail: str = ""):
        if not cond:
            failures.append(f"[FAIL #{tid}] {label}: {detail}")
            print(f"  FAIL  {label}: {detail}")
        else:
            print(f"  ok    {label}")

    # --- 1. Health (unauthenticated, public) ---
    r = client.get("/api/app/health")
    check("health status 200", r.status_code == 200, f"got {r.status_code}")
    check("health ok:true", r.get_json(silent=True) and r.get_json().get("ok") is True, str(r.data[:200]))

    # --- 2. Admin auth failure ---
    r = client.get("/api/admin/stats", headers=BAD_ADMIN)
    check("bad admin -> 401", r.status_code == 401, f"got {r.status_code}")

    r = client.get("/api/admin/stats", headers=ADMIN)
    check("good admin stats -> 200", r.status_code == 200, f"got {r.status_code} {r.data[:160]}")

    # --- 3. Tier management ---
    r = client.post("/api/admin/tier", headers={**ADMIN, **JSON}, json={
        "name": "Standard",
        "dll_filename": "Standard.dll",
        "description": "Standard tier"
    })
    check("create Standard tier", r.status_code == 200 and r.get_json().get("ok"), str(r.data[:200]))

    r = client.post("/api/admin/tier", headers={**ADMIN, **JSON}, json={
        "name": "Premium",
        "dll_filename": "Premium.dll",
        "description": "Full features"
    })
    check("create Premium tier", r.status_code == 200 and r.get_json().get("ok"), str(r.data[:200]))

    r = client.get("/api/admin/tiers", headers=ADMIN)
    data = r.get_json()
    check("list tiers count >= 2", r.status_code == 200 and data and len(data.get("tiers", [])) >= 2, str(data))

    # --- 4. Fake a DLL file for the Standard tier so we can download it ---
    fake_dll = tmp / "payloads" / "Standard.dll"
    # Build a minimal but valid PE (MZ + PE headers, tiny)
    import struct
    mz = bytearray(b"MZ")
    mz += b"\x00" * 58
    mz += struct.pack("<I", 0x40)  # e_lfanew -> offset 0x40
    mz += b"\x00" * (0x40 - len(mz))
    assert len(mz) == 0x40
    mz += b"PE\x00\x00"  # Signature
    mz += struct.pack("<H", 0x8664)  # Machine = AMD64
    mz += struct.pack("<H", 2)       # NumberOfSections
    mz += struct.pack("<I", 0)       # TimeDateStamp
    mz += struct.pack("<I", 0)       # PointerToSymbolTable
    mz += struct.pack("<I", 0)       # NumberOfSymbols
    mz += struct.pack("<H", 0xF0)    # SizeOfOptionalHeader (plausible)
    mz += struct.pack("<H", 0x2022)  # Characteristics (DLL|IMAGE_FILE_LARGE_ADDRESS_AWARE)
    # Optional header minimal (we won't load it, just make LooksLikeValidPE pass)
    mz += b"\x00" * (0xF0 + 4096)   # Pad enough to be > minPeSize
    fake_dll.write_bytes(bytes(mz))
    check("fake Standard.dll created", fake_dll.is_file() and fake_dll.stat().st_size > 1024)

    # --- 5. Key creation ---
    r = client.post("/api/admin/key", headers={**ADMIN, **JSON}, json={
        "tier": "Standard",
        "format": "human",
        "validity_days": 30,
        "max_hwids": 2,
        "note": "selftest key",
    })
    check("create key", r.status_code == 200 and r.get_json().get("ok"), str(r.data[:200]))
    KEY = r.get_json()["key"]["key"]
    TIER = r.get_json()["key"]["tier"]
    check("key tier == Standard", TIER == "Standard", TIER)

    # Create an expired key for negative testing
    r = client.post("/api/admin/key", headers={**ADMIN, **JSON}, json={
        "tier": "Standard",
        "validity_days": -1,  # expired yesterday
    })
    check("create expired key", r.status_code == 200 and r.get_json().get("ok"))
    EXPIRED_KEY = r.get_json()["key"]["key"]

    # Create a revoked key
    r = client.post("/api/admin/key", headers={**ADMIN, **JSON}, json={
        "tier": "Standard", "unlimited": True,
    })
    REVOKED_KEY = r.get_json()["key"]["key"]
    r = client.patch(f"/api/admin/key/{REVOKED_KEY}", headers={**ADMIN, **JSON},
                     json={"is_active": False})
    check("revoke key", r.status_code == 200 and r.get_json()["ok"])

    # --- 6. Real-time validation flow ---
    def validate(key, hwid="HWID-FIRST-MACHINE"):
        return client.post("/api/app/validate", headers=JSON, json={"key": key, "hwid": hwid})

    r = validate("INVALID-NONSENSE-KEY")
    check("invalid key returns valid:false", r.status_code == 200 and r.get_json().get("valid") is False)

    r = validate(EXPIRED_KEY)
    check("expired key returns valid:false", r.status_code == 200 and r.get_json().get("valid") is False)

    r = validate(REVOKED_KEY)
    check("revoked key returns valid:false", r.status_code == 200 and r.get_json().get("valid") is False)

    r = validate(KEY, "HWID-A")
    check("first validation (HWID-A) -> valid:true", r.status_code == 200 and r.get_json().get("valid") is True, str(r.data[:300]))
    ok_data = r.get_json()
    TOKEN_A = ok_data.get("downloadToken")
    check("downloadToken returned", bool(TOKEN_A), str(ok_data.keys()))
    check("tier matches", ok_data.get("tier") == "Standard")
    check("expiresAt present", bool(ok_data.get("expiresAt")))
    check("signature present", bool(ok_data.get("signature")))

    # Re-validate from a different HWID (max_hwids=2, so allowed)
    r = validate(KEY, "HWID-B")
    check("second HWID (within max) -> valid:true", r.status_code == 200 and r.get_json().get("valid") is True)
    TOKEN_B = r.get_json()["downloadToken"]

    # Third HWID -> should be rejected
    r = validate(KEY, "HWID-C")
    check("third HWID (over max) -> valid:false", r.status_code == 200 and r.get_json().get("valid") is False,
          f"body={r.get_json()}")

    # Reset HWIDs via admin patch
    r = client.patch(f"/api/admin/key/{KEY}", headers={**ADMIN, **JSON},
                     json={"reset_hwids": True})
    check("admin reset_hwids", r.status_code == 200 and r.get_json()["ok"])
    r = validate(KEY, "HWID-C")
    check("after reset, new HWID binds", r.status_code == 200 and r.get_json().get("valid") is True)

    # --- 7. Download endpoint errors ---
    dl_url = f"/api/app/download/Standard?token={TOKEN_A}"

    # Missing token
    r = client.get("/api/app/download/Standard")
    check("download w/o token -> 400", r.status_code == 400)

    # Unknown token
    r = client.get("/api/app/download/Standard?token=does-not-exist")
    check("download unknown token -> 401", r.status_code == 401)

    # Tier mismatch: take TOKEN_A (issued for Standard) and request Premium
    r = client.get(f"/api/app/download/Premium?token={TOKEN_A}")
    check("download tier mismatch -> 403", r.status_code == 403)

    # Successful download
    r = client.get(dl_url)
    check(f"download success {r.status_code}", r.status_code == 200, f"body={r.data[:120]}")
    check("download bytes == fake DLL", r.data == fake_dll.read_bytes(),
          f"len(r.data)={len(r.data)} len(fake)={fake_dll.stat().st_size}")

    # Re-send the same token -> single-use enforced -> 409
    r2 = client.get(dl_url)
    check("reused download token -> 409", r2.status_code == 409, f"got {r2.status_code} {r2.data[:120]}")

    # --- 8. Admin: update key (add days + list + search) ---
    r = client.patch(f"/api/admin/key/{KEY}", headers={**ADMIN, **JSON}, json={"add_days": 60})
    check("patch add_days", r.status_code == 200 and r.get_json()["ok"])

    r = client.get("/api/admin/keys?q=selftest", headers=ADMIN)
    check("admin keys search", r.status_code == 200 and r.get_json()["count"] >= 1)

    r = client.get(f"/api/admin/key/{KEY}", headers=ADMIN)
    check("admin key detail w/ bindings", r.status_code == 200 and "hwid_bindings" in r.get_json())

    # --- 9. Admin delete key ---
    r = client.delete(f"/api/admin/key/{KEY}", headers=ADMIN)
    check("admin delete key", r.status_code == 200 and r.get_json()["ok"])
    r = validate(KEY)
    check("deleted key becomes invalid", r.status_code == 200 and r.get_json()["valid"] is False)

    # --- 10. Admin tier deletion blocked when keys present ---
    # Create a fresh Premium key, try to delete the tier
    r = client.post("/api/admin/key", headers={**ADMIN, **JSON}, json={"tier": "Premium", "unlimited": True})
    check("create Premium key", r.status_code == 200 and r.get_json()["ok"])
    r = client.delete("/api/admin/tier/Premium", headers=ADMIN)
    check("tier with keys cannot be deleted -> 409", r.status_code == 409)


# --------------------------------------------------------------
if __name__ == "__main__":
    print("=" * 64)
    print(" Self-hosted license server selftest (in-memory test client)")
    print(" Temp directory:", tmp)
    print("=" * 64)
    try:
        run(1)
    except Exception as e:
        import traceback
        traceback.print_exc()
        failures.append(f"Exception: {e}")
    finally:
        try:
            shutil.rmtree(tmp, ignore_errors=True)
        except Exception:
            pass

    print()
    print("=" * 64)
    if failures:
        print(f"FAILED: {len(failures)} assertion(s)")
        for line in failures:
            print("  -", line)
        sys.exit(1)
    print("PASSED: every assertion OK.")
    print("=" * 64)
