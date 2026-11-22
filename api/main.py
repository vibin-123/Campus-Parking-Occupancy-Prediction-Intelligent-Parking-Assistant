import os
from contextlib import asynccontextmanager
from urllib.parse import quote

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, FileResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from api import auth, calendar_store, demo_logins, model_monitor
from api.limiter import limiter
from api.routes import router, get_store
from api.auth_routes import router as auth_router
from api.ops_routes import router as ops_router
from api.forecast_routes import router as forecast_router
from features import calendar as feature_calendar
from models import live


def wire_forecasting(reload_counts: bool = False) -> None:
    """
    Connect the forecaster to the database-backed calendar and the prediction log. At startup also reload
    recent real counts from the observation store (so a restart does not forget the last hour).
    """
    feature_calendar.set_provider(calendar_store.list_entries)
    live.set_prediction_logger(model_monitor.log_predictions)
    if reload_counts:
        try:
            live.rehydrate(get_store())
        except Exception as e:     # a missing/locked observation DB must not stop the app starting
            import logging
            logging.getLogger(__name__).error("Could not reload recent counts: %s", e)


wire_forecasting()                 # also when the app is imported without running startup (tests, scripts)


@asynccontextmanager
async def lifespan(app: FastAPI):
    auth.ensure_bootstrap_admin()   # first run: create the initial admin account
    wire_forecasting(reload_counts=True)
    yield


app = FastAPI(
    title="LPU Campus Parking Intelligence System",
    description="End-to-End Parking Occupancy Prediction, Multi-Camera Vision, and Intelligent Recommendation Engine for Lovely Professional University.",
    version="2.1.0",
    lifespan=lifespan,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS Configuration for Decoupled Deployments (Render Static Site + Web Service)
_raw_origins = os.environ.get("ALLOWED_ORIGINS", "*")
_allowed_origins = [o.strip() for o in _raw_origins.split(",") if o.strip()]

if "*" in _allowed_origins or not _allowed_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )
else:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_allowed_origins,
        allow_origin_regex=r"https://.*\.onrender\.com",
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    if request.url.path.startswith("/api/") or response.headers.get("content-type", "").startswith("text/html"):
        response.headers.setdefault("Cache-Control", "no-store")
    return response


# Static files (CSS, JS, favicon, the ONNX YOLO models) live in public/static.
# Locally FastAPI serves them. On Vercel the platform serves public/ from its CDN (a function response is
# capped at ~4.5 MB, far below the 24 MB ONNX models), so the mount is skipped there.
IS_VERCEL = bool(os.environ.get("VERCEL"))
if not IS_VERCEL:
    app.mount("/static", StaticFiles(directory="public/static"), name="static")

# Configure Templates (HTML)
templates = Jinja2Templates(directory="frontend/templates")

# API routes (/api/...)
app.include_router(router)
app.include_router(auth_router)
app.include_router(ops_router)
app.include_router(forecast_router)

# Favicon — prevents 404 spam in logs
@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    path = "public/static/favicon.ico"
    if not os.path.exists(path):      # e.g. Vercel: public/ is not part of the function bundle
        return Response(status_code=204)
    return FileResponse(path)


# ---------------------------------------------------------------------------
# Pages. Every page except /login needs a session; each declares the permission it needs.
# The same checks guard the API, so hiding a link is only a convenience.
# ---------------------------------------------------------------------------

def safe_next(path: str) -> str:
    """Only same-site relative paths, to avoid open redirects."""
    if path and path.startswith("/") and not path.startswith("//") and "\\" not in path:
        return path
    return ""


def _render_page(request: Request, template: str, active_page: str, perm: str = None):
    user = auth.current_user(request)
    if user is None:
        nxt = request.url.path + (f"?{request.url.query}" if request.url.query else "")
        return RedirectResponse(f"/login?next={quote(nxt)}", status_code=303)
    if user["must_change_password"] and active_page != "account":
        return RedirectResponse("/account?first=1", status_code=303)
    ctx = {"active_page": active_page, "user": user, "perms": set(user["permissions"])}
    if perm and not auth.has_permission(user, perm):
        return templates.TemplateResponse(request=request, name="forbidden.html", status_code=403,
                                          context={**ctx, "active_page": ""})
    return templates.TemplateResponse(request=request, name=template, context=ctx)


@app.get("/login", response_class=HTMLResponse)
async def serve_login(request: Request, next: str = ""):
    user = auth.current_user(request)
    if user is not None:
        target = "/account?first=1" if user["must_change_password"] else (safe_next(next) or auth.landing_page(user["role"]))
        return RedirectResponse(target, status_code=303)
    return templates.TemplateResponse(request=request, name="login.html",
                                      context={"active_page": "login", "user": None, "next": safe_next(next),
                                               "demo_accounts": demo_logins.demo_accounts(request)})


@app.get("/", response_class=HTMLResponse)
async def serve_driver_view(request: Request):
    return _render_page(request, "driver.html", "driver", "recommend")

@app.get("/admin", response_class=HTMLResponse)
async def serve_admin_view(request: Request):
    return _render_page(request, "admin.html", "admin", "view_ops")

@app.get("/vision", response_class=HTMLResponse)
async def serve_vision_view(request: Request):
    return _render_page(request, "vision.html", "vision", "camera_control")

@app.get("/analytics", response_class=HTMLResponse)
async def serve_analytics_view(request: Request):
    return _render_page(request, "analytics.html", "analytics", "view_analytics")

@app.get("/zones", response_class=HTMLResponse)
async def serve_zones_view(request: Request):
    return _render_page(request, "zones.html", "zones", "view_occupancy")

@app.get("/users", response_class=HTMLResponse)
async def serve_users_view(request: Request):
    return _render_page(request, "users.html", "users", "manage_users")

@app.get("/calendar", response_class=HTMLResponse)
async def serve_calendar_view(request: Request):
    return _render_page(request, "calendar.html", "calendar", "manage_calendar")

@app.get("/model", response_class=HTMLResponse)
async def serve_model_view(request: Request):
    return _render_page(request, "model.html", "model", "view_model")

@app.get("/account", response_class=HTMLResponse)
async def serve_account_view(request: Request):
    return _render_page(request, "account.html", "account")


if __name__ == "__main__":
    uvicorn.run("api.main:app", host="0.0.0.0", port=8000, reload=True)
