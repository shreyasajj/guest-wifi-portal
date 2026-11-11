from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from .config import Settings, get_settings
from .db import init_engine
from .routes import admin, api, guest
from .services import Services, build_services
from .templating import set_site_name
from .workers import WorkerRunner

CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
       "font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")


def create_app(settings: Settings | None = None, services: Services | None = None) -> FastAPI:
    st = settings or get_settings()
    logging.basicConfig(level=st.log_level.upper(), format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    init_engine(st.database_url)
    set_site_name(st.site_name)
    owns_services = services is None
    svc = services or build_services(st)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        runner = WorkerRunner(svc)
        if st.workers_enabled:
            runner.start()
        try:
            yield
        finally:
            await runner.stop()
            if owns_services:
                await svc.aclose()

    app = FastAPI(title="Guest Wi-Fi Portal", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.services = svc

    if st.oidc_enabled:
        from authlib.integrations.starlette_client import OAuth

        oauth = OAuth()
        oauth.register(
            name="oidc",
            server_metadata_url=st.oidc_issuer.rstrip("/") + "/.well-known/openid-configuration",
            client_id=st.oidc_client_id,
            client_secret=st.oidc_client_secret,
            client_kwargs={"scope": st.oidc_scopes, "code_challenge_method": "S256"},
        )
        app.state.oauth = oauth

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        resp: Response = await call_next(request)
        resp.headers.setdefault("Content-Security-Policy", CSP)
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("Referrer-Policy", "same-origin")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        return resp

    app.add_middleware(SessionMiddleware, secret_key=st.secret_key, session_cookie="gw_session",
                       same_site="lax", https_only=st.session_cookie_secure, max_age=12 * 3600)

    @app.exception_handler(admin.NeedsLogin)
    async def _needs_login(request: Request, exc: admin.NeedsLogin):
        if request.headers.get("hx-request"):
            return Response(status_code=401, headers={"HX-Redirect": "/admin/login"})
        return RedirectResponse("/admin/login", status_code=303)

    app.mount("/static", StaticFiles(directory=str(Path(__file__).parent / "static")), name="static")
    app.include_router(admin.router)
    app.include_router(api.router)
    app.include_router(guest.router)

    @app.get("/healthz", include_in_schema=False)
    async def healthz():
        return {"ok": True}

    return app


def app_factory() -> FastAPI:  # used by uvicorn --factory
    return create_app()
