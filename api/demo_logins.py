"""
One-click demo sign-in buttons on the login page (for trying each role on your own computer).

The buttons list the accounts created by `python -m scripts.seed_demo_users`, read from demo_credentials.csv next
to the accounts database (git-ignored, never committed). Because they put passwords on the page, they are shown:

  DEMO_LOGINS=auto (default)  only when the browser connects from this same machine (loopback address, no proxy
                              forwarding headers), i.e. on localhost, never on a deployed site
  DEMO_LOGINS=on              always (e.g. a classroom demo server)
  DEMO_LOGINS=off             never

Only accounts that are still active, have not expired and still use the seeded password are listed, so an account
whose password was changed or that was disabled drops off by itself. The admin account is never listed.
"""
import csv
import ipaddress
import os
from typing import Dict, List

from fastapi import Request

from api import auth
from api.db import get_db

ROLE_ORDER = ["student", "faculty", "warden", "vendor", "guard"]


def credentials_file() -> str:
    path = get_db().path
    base = os.path.dirname(os.path.abspath(path)) if path != ":memory:" else os.getcwd()
    return os.path.join(base, "demo_credentials.csv")


def _is_local(request: Request) -> bool:
    if any(h in request.headers for h in ("x-forwarded-for", "x-real-ip", "forwarded")):
        return False                      # behind a proxy the peer address says nothing about the real client
    host = request.client.host if request.client else ""
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def enabled(request: Request) -> bool:
    mode = os.environ.get("DEMO_LOGINS", "auto").strip().lower()
    if mode == "off":
        return False
    return mode == "on" or _is_local(request)


def demo_accounts(request: Request) -> List[Dict[str, str]]:
    """Demo accounts to offer on the login page (empty unless enabled and the seed file exists)."""
    path = credentials_file()
    if not enabled(request) or not os.path.exists(path):
        return []
    out = []
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            if row.get("must_change", "").lower() != "no" or row.get("role") == "admin":
                continue                  # one-time passwords are for real hand-out, not one-click login
            user = auth.get_user_by_username(row["username"])
            if not user or not user["is_active"] or user["is_expired"]:
                continue
            with get_db().conn() as c:
                stored = c.execute("SELECT password_hash FROM users WHERE id = ?", (user["id"],)).fetchone()[0]
            if not auth.verify_password(row["password"], stored):
                continue                  # password changed since seeding
            out.append({"username": user["username"], "password": row["password"], "role": user["role"],
                        "role_label": user["role_label"], "name": user["full_name"] or user["username"],
                        "home_block": (user["home_block"] or "").replace("_", " ")})
    out.sort(key=lambda a: (ROLE_ORDER.index(a["role"]) if a["role"] in ROLE_ORDER else 99, a["username"]))
    return out
