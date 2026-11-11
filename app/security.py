"""Client IP resolution (trusted proxies), CSRF, admin network restriction, auth helpers."""
from __future__ import annotations

import hmac
import ipaddress
import secrets

from fastapi import HTTPException, Request

_CSRF_KEY = "csrf"


def _in_any(ip: str, networks) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if getattr(addr, "ipv4_mapped", None):
        addr = addr.ipv4_mapped
    return any(addr in n for n in networks)


def resolve_client_ip(peer: str, xff: str | None, trusted) -> str:
    """Use X-Forwarded-For only when the direct peer is a trusted proxy.

    Walk the header right-to-left, skipping trusted proxies; the first untrusted hop is the
    client. A guest can prepend fake entries, but they sit left of the real one and are ignored.
    """
    if not peer or not _in_any(peer, trusted) or not xff:
        return peer
    hops = [h.strip() for h in xff.split(",") if h.strip()]
    for hop in reversed(hops):
        if not _in_any(hop, trusted):
            return hop
    return hops[0] if hops else peer


def client_ip(request: Request) -> str:
    st = request.app.state.services.settings
    peer = request.client.host if request.client else ""
    return resolve_client_ip(peer, request.headers.get("x-forwarded-for"), st.trusted_proxy_networks)


def ip_in_admin_networks(request: Request) -> bool:
    return _in_any(client_ip(request), request.app.state.services.settings.admin_networks)


# ---------------------------------------------------------------- CSRF
def csrf_token(request: Request) -> str:
    tok = request.session.get(_CSRF_KEY)
    if not tok:
        tok = secrets.token_urlsafe(32)
        request.session[_CSRF_KEY] = tok
    return tok


async def csrf_protect(request: Request) -> None:
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return
    expected = request.session.get(_CSRF_KEY)
    sent = request.headers.get("x-csrf-token")
    if not sent:
        form = await request.form()
        sent = form.get("csrf_token")
    if not expected or not sent or not hmac.compare_digest(str(sent), str(expected)):
        raise HTTPException(status_code=403, detail="CSRF check failed. Reload the page and try again.")


# ---------------------------------------------------------------- admin
def require_admin_network(request: Request) -> None:
    if not ip_in_admin_networks(request):
        raise HTTPException(status_code=404)


def current_admin(request: Request) -> dict | None:
    return request.session.get("admin")


def require_api_token(request: Request) -> str:
    require_admin_network(request)
    auth = request.headers.get("authorization", "")
    token = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
    tokens = request.app.state.services.settings.api_token_list
    if token and any(hmac.compare_digest(token, t) for t in tokens):
        return "home_assistant"
    raise HTTPException(status_code=401, detail="invalid token", headers={"WWW-Authenticate": "Bearer"})
