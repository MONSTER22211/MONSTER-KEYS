
"""
Command-line admin tool for the self-hosted Xenos license server.

Examples:

  # Point to your server + admin token
  set LICENSE_SERVER_URL=http://127.0.0.1:5050
  set LICENSE_ADMIN_TOKEN=CHANGE_ME_ADMIN_TOKEN_12345

  # Create a 30-day Standard key
  python keygen.py create --tier Standard --days 30 --note "Customer #123"

  # Create a Premium key valid forever, pre-bound to one HWID
  python keygen.py create --tier Premium --unlimited --prebind-hwid DESKTOP-ABCD123

  # Create 5 keys in batch
  python keygen.py create --tier Standard --days 7 --count 5

  # Revoke / extend / query
  python keygen.py get    ABCD-1234-WXYZ-9876
  python keygen.py update ABCD-1234-WXYZ-9876 --add-days 30
  python keygen.py update ABCD-1234-WXYZ-9876 --reset-hwids
  python keygen.py update ABCD-1234-WXYZ-9876 --deactivate
  python keygen.py delete ABCD-1234-WXYZ-9876

  # List keys (search, filter, ...)
  python keygen.py list --active --limit 50
  python keygen.py list --tier Premium
  python keygen.py list --q DESKTOP-

  # Tier management
  python keygen.py tier-create --name Premium --dll Premium.dll --desc "Full features"
  python keygen.py tier-list
  python keygen.py tier-delete Premium

  # General
  python keygen.py stats
  python keygen.py health
"""

from __future__ import annotations
import argparse
import os
import sys
import json
from typing import Optional
from urllib.parse import urlencode
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError


def _env(name: str, default: Optional[str] = None) -> Optional[str]:
    v = os.environ.get(name)
    if v is None or v == "":
        return default
    return v


SERVER_URL = _env("LICENSE_SERVER_URL", "http://127.0.0.1:5050").rstrip("/")
ADMIN_TOKEN = _env("LICENSE_ADMIN_TOKEN", "")


class _Encoder(json.JSONEncoder):
    def default(self, o):
        if hasattr(o, "isoformat"):
            return o.isoformat()
        return super().default(o)


def _headers(extra=None):
    h = {
        "Authorization": f"Bearer {ADMIN_TOKEN}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    if extra:
        h.update(extra)
    return h


def _method(method: str, path: str, payload=None, query=None):
    url = SERVER_URL + path
    if query:
        url += "?" + urlencode({k: v for k, v in query.items() if v is not None})
    data = None
    if payload is not None:
        data = json.dumps(payload, cls=_Encoder).encode("utf-8")
    req = Request(url, data=data, method=method, headers=_headers())
    try:
        with urlopen(req, timeout=30) as r:
            body = r.read().decode("utf-8", errors="replace")
            return r.status, json.loads(body) if body else {}
    except HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        try:
            return e.code, json.loads(body) if body else {"error": str(e)}
        except json.JSONDecodeError:
            return e.code, {"http_error": e.code, "raw": body[:500]}
    except URLError as e:
        return 0, {"error": f"Connection failed: {e.reason}"}
    except Exception as e:
        return 0, {"error": f"Request exception: {e}"}


def _print(blob, pretty=True):
    if pretty:
        print(json.dumps(blob, indent=2, sort_keys=False))
    else:
        print(json.dumps(blob))


# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------
def cmd_health(_args):
    code, data = _method("GET", "/api/app/health")
    _print({"http_status": code, **data})
    return 0 if code == 200 else 1


def cmd_stats(_args):
    code, data = _method("GET", "/api/admin/stats")
    _print({"http_status": code, **data})
    return 0 if code == 200 else 1


def cmd_create(args):
    payload = {
        "tier": args.tier or None,
        "format": args.format,
        "validity_days": None if args.unlimited else args.days,
        "max_uses": args.max_uses,
        "max_hwids": args.max_hwids,
        "note": args.note,
        "prebind_hwid": args.prebind_hwid,
        "segments": args.segments,
        "seg_len": args.seg_len,
    }
    count = max(1, args.count)
    keys_out = []
    last_status = 200
    last_resp = {}
    for i in range(count):
        code, data = _method("POST", "/api/admin/key", payload=payload)
        last_status, last_resp = code, data
        if code != 200 or not data.get("ok"):
            if count == 1:
                _print({"http_status": code, **data})
                return 1
            print(f"[!] Key #{i+1} creation failed: {data}")
            break
        k = data.get("key", {})
        keys_out.append(k.get("key"))
        if count == 1:
            _print({"http_status": code, **data})
        else:
            print(k.get("key"))
    if count > 1:
        print()
        print(f"Generated {len(keys_out)} key(s). Last response HTTP {last_status}.")
        if keys_out:
            with open("generated_keys.txt", "a", encoding="utf-8") as f:
                f.write("\n".join(keys_out) + "\n")
            print("Appended to generated_keys.txt")
    return 0 if (last_status == 200 and last_resp.get("ok")) else 1


def cmd_get(args):
    code, data = _method("GET", f"/api/admin/key/{args.key}")
    _print({"http_status": code, **data})
    return 0 if code == 200 and data.get("ok") else 1


def cmd_update(args):
    patch = {}
    if args.add_days is not None:
        patch["add_days"] = args.add_days
    if args.days is not None:
        patch["validity_days"] = args.days
    if args.unlimited:
        patch["unlimited"] = True
    if args.tier:
        patch["tier"] = args.tier
    if args.max_hwids is not None:
        patch["max_hwids"] = args.max_hwids
    if args.max_uses is not None:
        patch["max_uses"] = args.max_uses
    if args.activate:
        patch["is_active"] = True
    if args.deactivate:
        patch["is_active"] = False
    if args.reset_hwids:
        patch["reset_hwids"] = True
    if args.note is not None:
        patch["note"] = args.note
    if not patch:
        print("No update actions specified. See --help.", file=sys.stderr)
        return 2
    code, data = _method("PATCH", f"/api/admin/key/{args.key}", payload=patch)
    _print({"http_status": code, **data})
    return 0 if code == 200 and data.get("ok") else 1


def cmd_delete(args):
    if not args.yes:
        ans = input(f"Really delete key '{args.key}'? [y/N] ").strip().lower()
        if ans not in ("y", "yes"):
            print("Aborted.")
            return 3
    code, data = _method("DELETE", f"/api/admin/key/{args.key}")
    _print({"http_status": code, **data})
    return 0 if code == 200 and data.get("ok") else 1


def cmd_list(args):
    query = {
        "tier": args.tier,
        "q": args.q,
        "limit": args.limit,
        "active": "1" if args.active else None,
        "expired": "1" if args.expired else None,
    }
    code, data = _method("GET", "/api/admin/keys", query=query)
    if code == 200 and data.get("ok"):
        keys = data.get("keys", [])
        if args.brief:
            for k in keys:
                print(
                    f"{k['key']}\t{k['tier']}\t"
                    f"active={k['is_active']}\tuses={k['uses']}/{k['max_uses'] or '∞'}\t"
                    f"exp={k['expires_at'] or 'never'}\t"
                    f"hwids={k['hwid_count']}/{k['max_hwids']}\t"
                    f"note={(k.get('note') or '')}"
                )
        else:
            _print({"http_status": code, **data})
        return 0
    _print({"http_status": code, **data})
    return 1


def cmd_tier_create(args):
    payload = {
        "name": args.name,
        "dll_filename": args.dll,
        "description": args.desc,
    }
    code, data = _method("POST", "/api/admin/tier", payload=payload)
    _print({"http_status": code, **data})
    return 0 if code == 200 and data.get("ok") else 1


def cmd_tier_list(_args):
    code, data = _method("GET", "/api/admin/tiers")
    _print({"http_status": code, **data})
    return 0 if code == 200 and data.get("ok") else 1


def cmd_tier_delete(args):
    if not args.yes:
        ans = input(f"Really delete tier '{args.name}'? [y/N] ").strip().lower()
        if ans not in ("y", "yes"):
            print("Aborted.")
            return 3
    code, data = _method("DELETE", f"/api/admin/tier/{args.name}")
    _print({"http_status": code, **data})
    return 0 if code == 200 and data.get("ok") else 1


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="keygen",
        description="Admin CLI for the self-hosted Xenos license server.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--server", default=None, help="Override LICENSE_SERVER_URL")
    p.add_argument("--token", default=None, help="Override LICENSE_ADMIN_TOKEN")
    p.add_argument("--raw", action="store_true", help="Print JSON without pretty indent")

    sp = p.add_subparsers(dest="cmd", required=True)

    sp_health = sp.add_parser("health", help="Public server health / status")
    sp_health.set_defaults(func=cmd_health)

    sp_stats = sp.add_parser("stats", help="Admin stats summary")
    sp_stats.set_defaults(func=cmd_stats)

    # --------- create ---------
    sp_c = sp.add_parser("create", help="Create one or more new license keys")
    sp_c.add_argument("--tier", default=None, help="Tier name (e.g. Standard, Premium)")
    sp_c.add_argument("--format", choices=["human", "uuid"], default="human")
    sp_c.add_argument("--segments", type=int, default=4, help="Human-format segments")
    sp_c.add_argument("--seg-len", type=int, default=4, help="Human-format segment length")
    sp_c.add_argument("--days", type=float, default=None, help="Validity in days from now")
    sp_c.add_argument("--unlimited", action="store_true", help="Never expires, unlimited uses (overrides --days / --max-uses)")
    sp_c.add_argument("--max-uses", type=int, default=0, help="0 = unlimited")
    sp_c.add_argument("--max-hwids", type=int, default=1, help="Max HWID bindings per key")
    sp_c.add_argument("--note", default=None, help="Admin note (customer tag, email, etc.)")
    sp_c.add_argument("--prebind-hwid", default=None, help="Pre-bind this key to the given HWID")
    sp_c.add_argument("--count", type=int, default=1, help="Generate N keys (batch)")
    sp_c.set_defaults(func=cmd_create)

    # --------- get ---------
    sp_g = sp.add_parser("get", help="Look up a key + its HWID bindings")
    sp_g.add_argument("key")
    sp_g.set_defaults(func=cmd_get)

    # --------- update ---------
    sp_u = sp.add_parser("update", help="Extend / revoke / re-tier / reset HWIDs")
    sp_u.add_argument("key")
    sp_u.add_argument("--add-days", type=float, default=None, help="Add days to current expiry (or from now if never)")
    sp_u.add_argument("--days", type=float, default=None, help="Reset validity to N days from now")
    sp_u.add_argument("--unlimited", action="store_true", help="Mark never-expire + unlimited uses")
    sp_u.add_argument("--tier", default=None, help="Move key to a different tier")
    sp_u.add_argument("--max-hwids", type=int, default=None)
    sp_u.add_argument("--max-uses", type=int, default=None)
    sp_u.add_argument("--activate", action="store_true")
    sp_u.add_argument("--deactivate", action="store_true")
    sp_u.add_argument("--reset-hwids", action="store_true", help="Clear all HWID bindings on this key")
    sp_u.add_argument("--note", default=None, help="Set admin note (pass '' to clear)")
    sp_u.set_defaults(func=cmd_update)

    # --------- delete ---------
    sp_d = sp.add_parser("delete", help="Irreversibly delete a key")
    sp_d.add_argument("key")
    sp_d.add_argument("-y", "--yes", action="store_true", help="Skip confirmation")
    sp_d.set_defaults(func=cmd_delete)

    # --------- list ---------
    sp_l = sp.add_parser("list", help="List / search keys")
    sp_l.add_argument("--tier", default=None)
    sp_l.add_argument("--active", action="store_true", help="Only active")
    sp_l.add_argument("--expired", action="store_true", help="Only expired")
    sp_l.add_argument("--q", default=None, help="Search key/hwid/note substring")
    sp_l.add_argument("--limit", type=int, default=200)
    sp_l.add_argument("--brief", action="store_true", help="Tab-separated summary lines")
    sp_l.set_defaults(func=cmd_list)

    # --------- tiers ---------
    sp_tc = sp.add_parser("tier-create", help="Create or update a tier (assign DLL file)")
    sp_tc.add_argument("--name", required=True)
    sp_tc.add_argument("--dll", default=None, help="DLL filename inside the server payloads/ dir")
    sp_tc.add_argument("--desc", default=None, help="Tier description")
    sp_tc.set_defaults(func=cmd_tier_create)

    sp_tl = sp.add_parser("tier-list", help="List all tiers")
    sp_tl.set_defaults(func=cmd_tier_list)

    sp_td = sp.add_parser("tier-delete", help="Delete a tier (must have zero keys)")
    sp_td.add_argument("name")
    sp_td.add_argument("-y", "--yes", action="store_true")
    sp_td.set_defaults(func=cmd_tier_delete)

    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.server:
        global SERVER_URL
        SERVER_URL = args.server.rstrip("/")
    if args.token:
        global ADMIN_TOKEN
        ADMIN_TOKEN = args.token
    if getattr(args, "raw", False):
        # monkey-patch _print for this run
        import builtins as _b
        _orig = globals().get("_print")

        def _raw(blob, **_kw):
            print(json.dumps(blob))
        globals()["_print"] = _raw
    if not ADMIN_TOKEN and args.cmd not in ("health",):
        print(
            "ERROR: LICENSE_ADMIN_TOKEN env var (or --token) is required for admin commands.\n"
            "       Example: set LICENSE_ADMIN_TOKEN=CHANGE_ME_ADMIN_TOKEN_12345",
            file=sys.stderr,
        )
        return 2
    return args.func(args) or 0


if __name__ == "__main__":
    sys.exit(main())
