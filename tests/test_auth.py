"""
Authentication, role-based access and the features built on them (home-block recommendations,
zone overrides, violation reports, vendor expiry, CSV import, camera ROI versioning).
"""
import re
import uuid

import pytest
from fastapi.testclient import TestClient

from api import auth
from api.db import get_db
from api.main import app
from tests.auth_helpers import ADMIN_PASSWORD, USER_PASSWORD, client_for_role, login_client, make_user

PUBLIC_API = {("GET", "/api/health"), ("POST", "/api/auth/login"), ("POST", "/api/auth/logout")}


def uid(prefix="u"):
    return f"{prefix}{uuid.uuid4().hex[:8]}"


@pytest.fixture(scope="module")
def admin():
    return login_client()


# ─────────────────────────── Secure by default ───────────────────────────

def _api_routes():
    # The OpenAPI schema lists every route, including those of included routers.
    for path, ops in app.openapi()["paths"].items():
        if path.startswith("/api/"):
            for m in ops:
                if m.upper() in ("GET", "POST", "PUT", "PATCH", "DELETE"):
                    yield m.upper(), path


def test_route_enumeration_sees_all_routers():
    paths = {p for _, p in _api_routes()}
    assert {"/api/recommendations", "/api/users", "/api/cameras", "/api/auth/login"} <= paths and len(paths) > 30


@pytest.mark.parametrize("method,path", sorted(set(_api_routes())))
def test_every_api_route_rejects_anonymous_callers(method, path):
    if (method, path) in PUBLIC_API:
        pytest.skip("public endpoint")
    url = re.sub(r"\{[^}]+\}", "1", path)
    body = {"zone_id": "ZONE_BLOCK1", "count": 1} if path == "/api/ingest" else None
    r = TestClient(app).request(method, url, json=body)
    assert r.status_code == 401, f"{method} {path} answered {r.status_code} without a session"


def test_health_stays_public():
    assert TestClient(app).get("/api/health").status_code == 200


# ─────────────────────────── Login, lockout, sessions ───────────────────────────

def test_bootstrap_admin_can_log_in_and_sees_permissions():
    c = login_client("admin", ADMIN_PASSWORD)
    me = c.get("/api/auth/me").json()
    assert me["role"] == "admin" and "manage_users" in me["permissions"] and me["landing_page"] == "/admin"


def test_wrong_password_and_unknown_user_get_the_same_message():
    name = uid("s")
    make_user(name, "student")
    c = TestClient(app)
    a = c.post("/api/auth/login", json={"username": name, "password": "nope-nope-1"})
    b = c.post("/api/auth/login", json={"username": uid("ghost"), "password": "nope-nope-1"})
    assert a.status_code == b.status_code == 401
    assert a.json()["detail"] == b.json()["detail"] == auth.GENERIC_LOGIN_ERROR


def test_lockout_after_repeated_failures_and_admin_unlock(admin):
    name = uid("s")
    user = make_user(name, "student")
    c = TestClient(app)
    for _ in range(auth.max_failed_logins() - 1):
        assert c.post("/api/auth/login", json={"username": name, "password": "bad-pass-123"}).status_code == 401
    assert c.post("/api/auth/login", json={"username": name, "password": "bad-pass-123"}).status_code == 423
    # even the right password is refused while locked
    assert c.post("/api/auth/login", json={"username": name, "password": USER_PASSWORD}).status_code == 423
    assert admin.post(f"/api/users/{user['id']}/unlock").status_code == 200
    assert c.post("/api/auth/login", json={"username": name, "password": USER_PASSWORD}).status_code == 200


def test_session_cookie_is_httponly_and_logout_revokes_it():
    name = uid("s")
    make_user(name, "student")
    c = TestClient(app)
    r = c.post("/api/auth/login", json={"username": name, "password": USER_PASSWORD})
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=lax" in cookie
    assert c.get("/api/auth/me").status_code == 200
    c.post("/api/auth/logout")
    assert c.get("/api/auth/me").status_code == 401


def test_database_stores_only_token_hashes():
    name = uid("s")
    make_user(name, "student")
    c = TestClient(app)
    c.post("/api/auth/login", json={"username": name, "password": USER_PASSWORD})
    token = c.cookies.get(auth.COOKIE_NAME)
    with get_db().conn() as db:
        stored = [r[0] for r in db.execute("SELECT token_hash FROM sessions").fetchall()]
    assert token not in stored and len(stored[0]) == 64


# ─────────────────────────── One-time passwords ───────────────────────────

def test_new_account_must_change_password_before_using_the_system(admin):
    name = uid("f")
    created = admin.post("/api/users", json={"username": name, "role": "faculty", "full_name": "Dr. Test",
                                              "home_block": "Block_1"}).json()
    temp = created["temporary_password"]
    assert re.fullmatch(r"[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}", temp)

    c = TestClient(app)
    r = c.post("/api/auth/login", json={"username": name, "password": temp})
    assert r.status_code == 200 and r.json()["redirect"] == "/account?first=1"
    assert c.get("/api/recommendations").json()["detail"] == "password_change_required"
    assert c.get("/").status_code == 200 and "Set your own password" in c.get("/").text  # redirected to /account

    weak = c.post("/api/auth/change-password", json={"current_password": temp, "new_password": "short1"})
    assert weak.status_code == 422
    ok = c.post("/api/auth/change-password", json={"current_password": temp, "new_password": "Brand-New-Pass-9"})
    assert ok.status_code == 200
    assert c.get("/api/recommendations").status_code == 200


def test_account_page_works_during_forced_password_change():
    """Regression: /api/blocks was refused for one-time-password accounts, so the account page failed to load
    its block list and the front end redirected to itself in an endless reload loop."""
    name = uid("f")
    _, temp = auth.create_user(name, "faculty")
    c = TestClient(app)
    assert c.post("/api/auth/login", json={"username": name, "password": temp}).status_code == 200
    assert c.get("/account").status_code == 200
    assert c.get("/api/blocks").status_code == 200 and len(c.get("/api/blocks").json()) > 5
    assert c.get("/api/auth/me").status_code == 200
    assert c.get("/api/recommendations").json()["detail"] == "password_change_required"   # everything else stays locked
    assert c.get("/api/zones").json()["detail"] == "password_change_required"


def test_demo_login_buttons_only_on_this_machine(tmp_path, monkeypatch):
    from api import demo_logins
    name, gone = uid("s"), uid("s")
    make_user(name, "student", home_block="Block_1")
    make_user(gone, "student")
    csv_path = tmp_path / "demo_credentials.csv"
    csv_path.write_text("username,role,full_name,home_block,password,must_change\n"
                        f"{name},student,Demo Student,Block_1,{USER_PASSWORD},no\n"
                        f"{gone},student,Changed,,Old-Pass-1234,no\n"          # password no longer matches
                        f"{uid('x')},faculty,Ghost,,Whatever-123,no\n", encoding="utf-8")   # account does not exist
    monkeypatch.setattr(demo_logins, "credentials_file", lambda: str(csv_path))

    monkeypatch.setenv("DEMO_LOGINS", "auto")       # TestClient's peer is "testclient", not a loopback address
    assert 'class="demo-login' not in TestClient(app).get("/login").text
    monkeypatch.setenv("DEMO_LOGINS", "on")
    html = TestClient(app).get("/login").text
    assert f'data-user="{name}"' in html and f'data-user="{gone}"' not in html and "Ghost" not in html
    monkeypatch.setenv("DEMO_LOGINS", "off")
    assert 'class="demo-login' not in TestClient(app).get("/login").text


def test_demo_logins_auto_mode_rules():
    from starlette.requests import Request
    from api import demo_logins
    req = lambda host, headers=(): Request({"type": "http", "client": (host, 1), "headers": list(headers)})
    assert demo_logins._is_local(req("127.0.0.1")) and demo_logins._is_local(req("::1"))
    assert not demo_logins._is_local(req("10.0.0.7"))
    assert not demo_logins._is_local(req("127.0.0.1", [(b"x-forwarded-for", b"203.0.113.9")]))   # behind a proxy


def test_password_policy():
    with pytest.raises(ValueError):
        auth.validate_password("abcdefgh", "x123", "student")         # no digit
    with pytest.raises(ValueError):
        auth.validate_password("12301234abc", "12301234", "student")  # contains the user ID
    with pytest.raises(ValueError):
        auth.validate_password("Admin-pw-1", "root", "admin")         # admins need 12+ characters
    auth.validate_password("Good-Pass-2026", "12301234", "student")


def test_reset_password_signs_the_user_out_everywhere(admin):
    name = uid("s")
    user = make_user(name, "student")
    c = login_client(name, USER_PASSWORD)
    temp = admin.post(f"/api/users/{user['id']}/reset-password").json()["temporary_password"]
    assert c.get("/api/auth/me").status_code == 401
    assert TestClient(app).post("/api/auth/login", json={"username": name, "password": temp}).status_code == 200


# ─────────────────────────── Role matrix ───────────────────────────

ROLE_MATRIX = [
    # (method, path, json, roles that may call it)
    ("GET", "/api/recommendations?destination=Block_1", None, {"admin", "warden", "faculty", "student", "vendor", "guard"}),
    ("GET", "/api/snapshot", None, {"admin", "warden", "faculty", "student", "vendor", "guard"}),
    ("GET", "/api/users", None, {"admin"}),
    ("GET", "/api/audit", None, {"admin"}),
    ("GET", "/api/cameras", None, {"admin"}),
    ("GET", "/api/metrics", None, {"admin"}),
    ("GET", "/api/reports", None, {"admin", "warden", "guard"}),
    ("POST", "/api/reports", {"zone_id": "ZONE_LAW", "category": "blocking"}, {"admin", "warden", "guard"}),
    ("PUT", "/api/zones/ZONE_SPORTS/override", {"status": "FULL", "minutes": 5}, {"admin", "warden"}),
]


@pytest.mark.parametrize("role", auth.ROLES)
def test_role_matrix(role):
    c = login_client() if role == "admin" else client_for_role(role, home_block="Block_1")
    for method, path, body, allowed in ROLE_MATRIX:
        r = c.request(method, path, json=body)
        if role in allowed:
            assert r.status_code not in (401, 403), f"{role} should be allowed {method} {path}: {r.status_code} {r.text}"
        else:
            assert r.status_code == 403, f"{role} should be denied {method} {path}: {r.status_code}"
    with get_db().conn() as db:
        db.execute("DELETE FROM zone_overrides")


@pytest.mark.parametrize("role,page,expected", [
    ("student", "/", 200), ("student", "/zones", 200), ("student", "/account", 200),
    ("student", "/admin", 403), ("student", "/vision", 403), ("student", "/users", 403), ("student", "/analytics", 403),
    ("guard", "/admin", 200), ("guard", "/vision", 403),
    ("warden", "/admin", 200), ("warden", "/users", 403),
    ("vendor", "/", 200), ("vendor", "/admin", 403),
])
def test_page_access_by_role(role, page, expected):
    c = client_for_role(role, home_block="Block_1")
    assert c.get(page).status_code == expected


def test_nav_only_lists_pages_the_role_can_open():
    html = client_for_role("student", home_block="Block_1").get("/").text
    assert 'href="/vision"' not in html and 'href="/users"' not in html and 'href="/zones"' in html
    admin_html = login_client().get("/admin").text
    assert 'href="/vision"' in admin_html and 'href="/users"' in admin_html


def test_anonymous_pages_redirect_to_login_with_next():
    r = TestClient(app).get("/admin?tab=1", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login?next=/admin%3Ftab%3D1"


def test_login_page_ignores_offsite_next():
    from api.main import safe_next
    assert safe_next("//evil.example") == "" and safe_next("https://evil.example") == "" and safe_next("/zones") == "/zones"


# ─────────────────────────── Nearest parking from the home block ───────────────────────────

def _dist(rec, zone_id):
    return next(z["walking_distance_meters"] for z in rec["recommended_zones"] if z["zone_id"] == zone_id)


def test_recommendations_default_to_home_block():
    c = client_for_role("faculty", username=uid("f"), home_block="Block_57_Agri")
    rec = c.get("/api/recommendations").json()
    assert rec["destination"] == "Block_57_Agri" and rec["destination_source"] == "home_block"
    assert rec["uses_adjacent_block"] is False
    assert _dist(rec, "ZONE_BLOCK57") == 30


def test_adjacent_block_uses_nearest_reference_block():
    c = client_for_role("student", username=uid("s"), home_block="Block_55_Mech")
    rec = c.get("/api/recommendations").json()
    assert rec["requested_block"] == "Block_55_Mech" and rec["destination"] == "Block_57_Agri"
    assert rec["uses_adjacent_block"] is True
    assert _dist(rec, "ZONE_BLOCK57") == 30   # distances come from the adjacent block 57
    nearest = min(rec["recommended_zones"], key=lambda z: z["walking_distance_meters"])
    assert nearest["zone_id"] == "ZONE_BLOCK57"


def test_explicit_destination_overrides_home_block():
    c = client_for_role("student", username=uid("s"), home_block="Block_55_Mech")
    rec = c.get("/api/recommendations?destination=Law_Block").json()
    assert rec["destination"] == "Law_Block" and rec["destination_source"] == "selected"


def test_no_home_block_and_no_destination_is_a_clear_error():
    c = client_for_role("vendor", username=uid("v"))
    r = c.get("/api/recommendations")
    assert r.status_code == 422 and "home block" in r.json()["detail"]


def test_user_can_set_own_home_block_but_not_an_unknown_one():
    c = client_for_role("student", username=uid("s"))
    assert c.patch("/api/auth/me", json={"home_block": "Nowhere"}).status_code == 422
    me = c.patch("/api/auth/me", json={"home_block": "management block"}).json()   # tolerant matching
    assert me["home_block"] == "Management_Block" and me["home_block_anchor"] == "Law_Block"


def test_every_configured_block_resolves_to_a_measured_anchor():
    from recommendation.campus_blocks import get_campus_blocks
    blocks = get_campus_blocks()
    for b in blocks.all():
        assert b["anchor"] in blocks.anchors


# ─────────────────────────── Ground overrides ───────────────────────────

def test_warden_override_removes_ground_from_recommendations():
    warden = client_for_role("warden", username=uid("w"))
    student = client_for_role("student", username=uid("s"), home_block="Block_57_Agri")
    try:
        r = warden.put("/api/zones/ZONE_BLOCK57/override", json={"status": "CLOSED", "reason": "Resurfacing", "minutes": 60})
        assert r.status_code == 200 and r.json()["expires_at"]
        zones = student.get("/api/recommendations").json()["recommended_zones"]
        assert zones[-1]["zone_id"] == "ZONE_BLOCK57" and zones[-1]["status"] == "CLOSED"
        assert zones[-1]["override_reason"] == "Resurfacing" and zones[0]["zone_id"] != "ZONE_BLOCK57"
        from api.limiter import limiter
        limiter.reset()   # all TestClients share one IP; other suites use up /navigate's 30/minute
        assert student.post("/api/navigate", json={"zone_id": "ZONE_BLOCK57"}).status_code == 409
        snap = student.get("/api/snapshot").json()
        z = next(z for z in snap["zones"] if z["zone_id"] == "ZONE_BLOCK57")
        assert z["status"] == "CLOSED" and z["available_spaces"] == 0
        assert any(a["type"] == "ZONE_CLOSED" for a in snap["alerts"])
    finally:
        assert warden.delete("/api/zones/ZONE_BLOCK57/override").json()["status"] == "cleared"
    assert student.get("/api/recommendations").json()["recommended_zones"][-1]["status"] not in ("CLOSED",)


def test_expired_override_is_ignored():
    from api.ops_routes import active_overrides
    with get_db().conn() as c:
        c.execute("INSERT OR REPLACE INTO zone_overrides (zone_id, status, set_by, set_at, expires_at)"
                  " VALUES ('ZONE_ARCH', 'FULL', 'x', '2020-01-01T00:00:00+00:00', '2020-01-01T01:00:00+00:00')")
    assert "ZONE_ARCH" not in active_overrides()


# ─────────────────────────── Violation reports ───────────────────────────

def test_guard_files_report_and_warden_resolves_it():
    guard = client_for_role("guard", username=uid("g"))
    warden = client_for_role("warden", username=uid("w"))
    r = guard.post("/api/reports", json={"zone_id": "ZONE_MAINGATE", "category": "blocking",
                                         "vehicle_number": "pb 08 ab 1234", "description": "Blocking gate 2"})
    assert r.status_code == 201
    rep = r.json()
    assert rep["vehicle_number"] == "PB 08 AB 1234" and rep["status"] == "open"
    assert guard.post(f"/api/reports/{rep['id']}/resolve", json={}).status_code == 403
    done = warden.post(f"/api/reports/{rep['id']}/resolve", json={"note": "Towed"}).json()
    assert done["status"] == "resolved" and done["resolved_by"].startswith("w")
    assert guard.post("/api/reports", json={"zone_id": "ZONE_LAW", "category": "rocket"}).status_code == 422
    assert guard.post("/api/reports", json={"zone_id": "ZONE_LAW", "category": "other",
                                            "vehicle_number": "<script>"}).status_code == 422


# ─────────────────────────── User management ───────────────────────────

def test_vendor_accounts_always_expire(admin):
    r = admin.post("/api/users", json={"username": uid("V-"), "role": "vendor", "full_name": "Chai Point"})
    assert r.status_code == 201 and r.json()["user"]["expires_at"]
    too_long = admin.post("/api/users", json={"username": uid("V-"), "role": "vendor", "expires_at": "2099-01-01"})
    assert too_long.status_code == 422


def test_expired_account_cannot_log_in_and_loses_its_session():
    name = uid("V-")
    user = make_user(name, "vendor", expires_at="2099-01-01T00:00:00+00:00")
    c = login_client(name, USER_PASSWORD)
    with get_db().conn() as db:
        db.execute("UPDATE users SET expires_at = '2020-01-01T00:00:00+00:00' WHERE id = ?", (user["id"],))
    assert c.get("/api/auth/me").status_code == 401
    r = TestClient(app).post("/api/auth/login", json={"username": name, "password": USER_PASSWORD})
    assert r.status_code == 401 and "expired" in r.json()["detail"]


def test_disabled_account_is_signed_out(admin):
    name = uid("s")
    user = make_user(name, "student")
    c = login_client(name, USER_PASSWORD)
    admin.patch(f"/api/users/{user['id']}", json={"is_active": False})
    assert c.get("/api/auth/me").status_code == 401
    r = TestClient(app).post("/api/auth/login", json={"username": name, "password": USER_PASSWORD})
    assert r.status_code == 401 and "disabled" in r.json()["detail"]


def test_admin_cannot_lock_themselves_out(admin):
    me = admin.get("/api/auth/me").json()
    assert admin.patch(f"/api/users/{me['id']}", json={"role": "student"}).status_code == 409
    assert admin.patch(f"/api/users/{me['id']}", json={"is_active": False}).status_code == 409
    assert admin.delete(f"/api/users/{me['id']}").status_code == 409


def test_duplicate_user_id_is_rejected(admin):
    name = uid("s")
    assert admin.post("/api/users", json={"username": name, "role": "student"}).status_code == 201
    assert admin.post("/api/users", json={"username": name.upper(), "role": "student"}).status_code == 409


def test_csv_import(admin):
    a, b, dup = uid("s"), uid("F"), uid("s")
    admin.post("/api/users", json={"username": dup, "role": "student"})
    csv_text = ("user_id,name,role,block,dept,expires_at\n"
                f"{a},Student A,student,Block_26_CSE,CSE,\n"
                f"{b},Faculty B,faculty,block 55 mech,Mech,\n"
                f"{dup},Dup,student,,,\n"
                f"{uid('x')},Bad Role,principal,,,\n"
                f"{uid('x')},Bad Block,student,Mars,,\n"
                "\n")
    r = admin.post("/api/users/import", files={"file": ("users.csv", csv_text.encode(), "text/csv")})
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["created_count"] == 2 and d["error_count"] == 3
    assert {c["username"] for c in d["created"]} == {a, b}
    assert all(c["temporary_password"] for c in d["created"])
    assert next(c for c in d["created"] if c["username"] == b)["home_block"] == "Block_55_Mech"
    assert {e["line"] for e in d["errors"]} == {4, 5, 6}


def test_audit_log_records_logins_and_changes(admin):
    name = uid("s")
    make_user(name, "student")
    TestClient(app).post("/api/auth/login", json={"username": name, "password": "wrong-pass-1"})
    entries = admin.get(f"/api/audit?actor={name}").json()["entries"]
    assert any(e["action"] == "login_failed" for e in entries)
    assert admin.get("/api/audit?action=user_created&limit=5").status_code == 200


# ─────────────────────────── Cameras and ROI ───────────────────────────

def test_roi_versions_and_rollback(admin):
    cam = "CAM_LAW_01"
    p1 = [[10, 10], [200, 10], [200, 150]]
    p2 = [[0, 0], [300, 0], [300, 200], [0, 200]]
    v1 = admin.put(f"/api/cameras/{cam}/roi", json={"polygon": p1, "image_width": 640, "image_height": 480, "note": "first"})
    v2 = admin.put(f"/api/cameras/{cam}/roi", json={"polygon": p2, "image_width": 640, "image_height": 480})
    assert v1.status_code == v2.status_code == 201 and v2.json()["version"] == v1.json()["version"] + 1
    assert admin.get(f"/api/cameras/{cam}/roi").json()["active"]["polygon"] == [[float(x), float(y)] for x, y in p2]
    back = admin.post(f"/api/cameras/{cam}/roi/{v1.json()['version']}/activate").json()
    assert back["version"] == v1.json()["version"] and back["is_active"]
    hist = admin.get(f"/api/cameras/{cam}/roi/history").json()["versions"]
    assert sum(v["is_active"] for v in hist) == 1
    assert admin.put(f"/api/cameras/{cam}/roi", json={"polygon": [[0, 0], [1, 1]]}).status_code == 422
    assert admin.put(f"/api/cameras/{cam}/roi", json={"polygon": [[0, 0], [900, 0], [0, 5]], "image_width": 640}).status_code == 422


def test_camera_source_validation(admin):
    cam = "CAM_ARCH_01"
    assert admin.patch(f"/api/cameras/{cam}", json={"source_type": "rtsp", "source_url": "http://x"}).status_code == 422
    ok = admin.patch(f"/api/cameras/{cam}", json={"source_type": "rtsp", "source_url": "rtsp://user:pw@10.0.0.5/s1", "enabled": False})
    assert ok.status_code == 200 and ok.json()["enabled"] is False
    entry = admin.get("/api/audit?action=camera_updated&limit=1").json()["entries"][0]
    assert "pw@" not in str(entry["detail"])   # stream credentials never reach the audit log
    admin.patch(f"/api/cameras/{cam}", json={"source_type": "none", "enabled": True})
