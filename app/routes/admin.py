"""Admin UI: login (password or OIDC), dashboard, people, devices, unidentified, audit."""
from __future__ import annotations

import hmac
import html
import logging

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from sqlmodel import Session, col, func, select

from ..approvals import AlreadyResolved, ContactChoiceRequired, NotFound
from ..carddav import CardDAVError
from ..db import get_session
from ..devices import DeviceBlocked, PersonBlocked, blocked_owner
from ..events import audit
from ..macs import normalize_mac
from ..matching import Contact
from ..models import ApprovalRequest, AuditLog, DecidedBy, Device, DeviceType, Event, Person
from ..opnsense import OPNsenseError
from ..security import client_ip, csrf_protect, current_admin, require_admin_network
from ..templating import templates
from ..views import approvals_view, people_view, sse_stream, status_view, unidentified_view

log = logging.getLogger(__name__)
router = APIRouter(prefix="/admin", dependencies=[Depends(require_admin_network)])
_ph = PasswordHasher()


class NeedsLogin(Exception):
    pass


def require_admin(request: Request) -> dict:
    admin = current_admin(request)
    if not admin:
        raise NeedsLogin()
    return admin


def _svc(request: Request):
    return request.app.state.services


def _page(request: Request, name: str, admin: dict, active: str, **ctx):
    return templates.TemplateResponse(request, name, {"admin": admin, "active": active, **ctx})


def _flash(kind: str, message: str, status: int = 200) -> HTMLResponse:
    """Flash message for htmx. Always HTTP 200: htmx doesn't swap error responses by default."""
    resp = HTMLResponse(f'<div class="flash {kind}" role="status">{html.escape(message)}</div>')
    resp.headers["X-Result-Status"] = str(status)
    resp.headers["HX-Trigger"] = "refresh"
    return resp


async def _contacts_for_picker(request: Request) -> list[Contact]:
    try:
        return sorted(await _svc(request).carddav.contacts(), key=lambda c: c.display_name.lower())
    except CardDAVError:
        return []


# ------------------------------------------------------------------ auth
@router.get("/login")
async def login_page(request: Request):
    st = _svc(request).settings
    return templates.TemplateResponse(request, "admin/login.html", {
        "oidc": st.oidc_enabled, "oidc_label": st.oidc_label, "password": bool(st.admin_password_hash),
        "error": request.query_params.get("error")})


@router.post("/login", dependencies=[Depends(csrf_protect)])
async def login_submit(request: Request, username: str = Form(""), password: str = Form(""),
                       session: Session = Depends(get_session)):
    svc = _svc(request)
    st = svc.settings
    key = "admin:" + client_ip(request)
    wait = svc.limiter.retry_after(session, key, None)
    if wait:
        return RedirectResponse(f"/admin/login?error=Too+many+attempts.+Try+again+in+{wait}s", status_code=303)
    ok = False
    if st.admin_password_hash and hmac.compare_digest(username.strip(), st.admin_username):
        try:
            ok = _ph.verify(st.admin_password_hash, password)
        except (VerificationError, InvalidHashError):
            ok = False
    svc.limiter.record(session, key, None, ok, "admin_login" if ok else "admin_login_failed")
    audit(session, "admin_login" if ok else "admin_login_failed", actor=username or "?", detail={"ip": client_ip(request), "via": "password"})
    if not ok:
        return RedirectResponse("/admin/login?error=Wrong+username+or+password", status_code=303)
    request.session.clear()
    request.session["admin"] = {"name": username, "via": "password"}
    return RedirectResponse("/admin", status_code=303)


@router.get("/oidc/login")
async def oidc_login(request: Request):
    oauth = getattr(request.app.state, "oauth", None)
    if not oauth:
        raise HTTPException(404)
    st = _svc(request).settings
    redirect_uri = (st.public_admin_url.rstrip("/") + "/admin/oidc/callback") if st.public_admin_url \
        else str(request.url_for("oidc_callback"))
    return await oauth.oidc.authorize_redirect(request, redirect_uri)


@router.get("/oidc/callback", name="oidc_callback")
async def oidc_callback(request: Request, session: Session = Depends(get_session)):
    oauth = getattr(request.app.state, "oauth", None)
    if not oauth:
        raise HTTPException(404)
    st = _svc(request).settings
    try:
        token = await oauth.oidc.authorize_access_token(request)
        claims = dict(token.get("userinfo") or {})
        try:
            claims.update(await oauth.oidc.userinfo(token=token))
        except Exception:  # noqa: BLE001 - userinfo is optional when the ID token has the claims
            pass
    except Exception as exc:  # noqa: BLE001
        log.warning("OIDC login failed: %s", exc)
        return RedirectResponse("/admin/login?error=Sign-in+failed", status_code=303)
    groups = claims.get("groups") or []
    if isinstance(groups, str):
        groups = [groups]
    allowed = st.oidc_group_list
    name = claims.get("preferred_username") or claims.get("name") or claims.get("email") or claims.get("sub")
    if allowed and not set(groups) & set(allowed):
        audit(session, "admin_login_failed", actor=name, detail={"via": "oidc", "reason": "group", "groups": groups})
        return RedirectResponse("/admin/login?error=Your+account+isn%27t+allowed+here", status_code=303)
    request.session.clear()
    request.session["admin"] = {"name": name, "via": "oidc", "sub": claims.get("sub")}
    audit(session, "admin_login", actor=name, detail={"via": "oidc", "ip": client_ip(request)})
    return RedirectResponse("/admin", status_code=303)


@router.post("/logout", dependencies=[Depends(csrf_protect)])
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/admin/login", status_code=303)


# ----------------------------------------------------------------- pages
@router.get("")
async def dashboard(request: Request, admin: dict = Depends(require_admin), session: Session = Depends(get_session)):
    return _page(request, "admin/dashboard.html", admin, "dashboard")


@router.get("/people")
async def people(request: Request, admin: dict = Depends(require_admin)):
    return _page(request, "admin/people.html", admin, "people")


@router.get("/devices")
async def devices(request: Request, admin: dict = Depends(require_admin)):
    return _page(request, "admin/devices.html", admin, "devices")


@router.get("/unidentified")
async def unidentified(request: Request, admin: dict = Depends(require_admin)):
    return _page(request, "admin/unidentified.html", admin, "unidentified")


@router.get("/audit")
async def audit_page(request: Request, page: int = 1, review: int = 0, admin: dict = Depends(require_admin),
                     session: Session = Depends(get_session)):
    per = 50
    q = select(AuditLog)
    if review:
        q = q.where(AuditLog.needs_review == True)  # noqa: E712
    total = session.exec(select(func.count()).select_from(q.subquery())).one()
    rows = session.exec(q.order_by(col(AuditLog.at).desc()).offset((page - 1) * per).limit(per)).all()
    return _page(request, "admin/audit.html", admin, "audit", rows=rows, page=page, pages=max(1, -(-total // per)),
                 review=review, total=total)


# -------------------------------------------------------------- partials
@router.get("/partials/{name}")
async def partial(name: str, request: Request, admin: dict = Depends(require_admin),
                  session: Session = Depends(get_session)):
    ctx: dict = {"admin": admin}
    if name == "pending":
        reqs = session.exec(select(ApprovalRequest).where(ApprovalRequest.status == "pending")
                            .order_by(col(ApprovalRequest.created_at))).all()
        ctx["requests"] = reqs
        ctx["names"] = await _contact_names(request, {u for r in reqs for u in r.contact_uids})
        recent = session.exec(select(ApprovalRequest).where(ApprovalRequest.status != "pending")
                              .order_by(col(ApprovalRequest.decided_at).desc()).limit(5)).all()
        ctx["recent"] = recent
    elif name == "badge":
        ctx["count"] = status_view(session)["pending_approvals"]
    elif name == "stats":
        ctx["s"] = status_view(session)
    elif name == "people":
        ctx["people"] = people_view(session)
    elif name == "devices":
        ctx["devices"] = session.exec(select(Device).order_by(col(Device.revoked), col(Device.online).desc(),
                                                              col(Device.last_seen).desc())).all()
        ctx["people"] = {p.contact_uid: p for p in session.exec(select(Person)).all()}
    elif name == "unidentified":
        ctx["rows"] = unidentified_view(session)
        ctx["contacts"] = await _contacts_for_picker(request)
    elif name == "feed":
        ctx["events"] = [e.as_dict() for e in session.exec(select(Event).order_by(col(Event.id).desc()).limit(25)).all()]
    else:
        raise HTTPException(404)
    return templates.TemplateResponse(request, f"admin/_{name}.html", ctx)


async def _contact_names(request: Request, uids: set[str]) -> dict[str, Contact]:
    out = {}
    try:
        for c in await _svc(request).carddav.contacts():
            if c.uid in uids:
                out[c.uid] = c
    except CardDAVError:
        pass
    return out


# --------------------------------------------------------------- actions
@router.post("/approvals/{req_id}/resolve", dependencies=[Depends(csrf_protect)])
async def resolve(req_id: str, request: Request, decision: str = Form(...), contact_uid: str = Form(""),
                  admin: dict = Depends(require_admin), session: Session = Depends(get_session)):
    try:
        res = await _svc(request).approvals.resolve(session, req_id, decision, by=DecidedBy.admin_ui,
                                                     contact_uid=contact_uid or None, actor=admin["name"])
    except ContactChoiceRequired:
        return _flash("warn", "Several contacts matched. Pick which one gets the birthday.", 200)
    except AlreadyResolved:
        session.expire_all()
        status = session.get(ApprovalRequest, req_id).status
        return _flash("warn", f"Already handled ({status.replace('_', ' ')}).")
    except NotFound:
        return _flash("bad", "That request no longer exists.")
    except ValueError:
        return _flash("bad", "That decision or contact isn't valid for this request.")
    if res.error:
        return _flash("warn", res.error)
    word = {"approved": "Approved and birthday saved", "approved_no_save": "Approved (birthday not saved)",
            "denied": "Denied"}[res.request.status]
    return _flash("ok", f"{word}: {res.request.contact_name}.")


@router.post("/devices/{device_id}/revoke", dependencies=[Depends(csrf_protect)])
async def revoke_device(device_id: int, request: Request, admin: dict = Depends(require_admin),
                        session: Session = Depends(get_session)):
    d = session.get(Device, device_id)
    if not d:
        return _flash("bad", "Device not found.", 404)
    try:
        await _svc(request).devices.revoke_device(session, d, actor=admin["name"])
    except OPNsenseError:
        log.exception("OPNsense request failed")
        return _flash("bad", "OPNsense request failed. Details are in the portal logs.", 502)
    return _flash("ok", f"Revoked {d.label} ({d.mac}).")


@router.post("/devices/{device_id}/edit", dependencies=[Depends(csrf_protect)])
async def edit_device(device_id: int, request: Request, device_type: str = Form(...), nickname: str = Form(""),
                      admin: dict = Depends(require_admin), session: Session = Depends(get_session)):
    d = session.get(Device, device_id)
    if not d:
        return _flash("bad", "Device not found.", 404)
    try:
        dtype = DeviceType(device_type)
    except ValueError:
        return _flash("bad", "Unknown device type.", 400)
    if dtype == DeviceType.phone and d.person_uid:
        for other in session.exec(select(Device).where(Device.person_uid == d.person_uid, Device.type == "phone",
                                                       Device.id != d.id)).all():
            other.type = DeviceType.other.value
            session.add(other)
            audit(session, "phone_demoted", actor=admin["name"], target=other.mac, commit=False)
    d.type = dtype.value
    d.nickname = nickname.strip()[:60] or None
    session.add(d)
    session.commit()
    audit(session, "device_edited", actor=admin["name"], target=d.mac, detail={"type": d.type, "nickname": d.nickname})
    _svc(request).bus.publish(session, "device_updated", {"device_id": d.id, "mac": d.mac, "type": d.type})
    return _flash("ok", f"Saved {d.label}.")


@router.post("/people/{uid}/revoke", dependencies=[Depends(csrf_protect)])
async def revoke_person(uid: str, request: Request, admin: dict = Depends(require_admin),
                        session: Session = Depends(get_session)):
    p = session.get(Person, uid)
    if not p:
        return _flash("bad", "Person not found.", 404)
    try:
        devs = await _svc(request).devices.revoke_person(session, p, actor=admin["name"])
    except OPNsenseError:
        log.exception("OPNsense request failed")
        return _flash("bad", "OPNsense request failed. Details are in the portal logs.", 502)
    return _flash("ok", f"Revoked {p.display_name} ({len(devs)} device{'s' if len(devs) != 1 else ''}) and blocked future logins.")


@router.post("/people/{uid}/unblock", dependencies=[Depends(csrf_protect)])
async def unblock_person(uid: str, request: Request, admin: dict = Depends(require_admin),
                         session: Session = Depends(get_session)):
    p = session.get(Person, uid)
    if not p:
        return _flash("bad", "Person not found.", 404)
    _svc(request).devices.unblock_person(session, p, actor=admin["name"])
    return _flash("ok", f"{p.display_name} can sign in again.")


@router.post("/unidentified/{mac}/adopt", dependencies=[Depends(csrf_protect)])
async def adopt(mac: str, request: Request, contact_uid: str = Form(...), device_type: str = Form("other"),
                nickname: str = Form(""), admin: dict = Depends(require_admin), session: Session = Depends(get_session)):
    svc = _svc(request)
    mac_n = normalize_mac(mac)
    if not mac_n:
        return _flash("bad", "Invalid MAC.", 400)
    try:
        contact = await svc.carddav.get_by_uid(contact_uid)
    except CardDAVError:
        log.exception("loading contacts failed")
        return _flash("bad", "Couldn't load contacts from Nextcloud. Details are in the portal logs.", 502)
    if not contact:
        return _flash("bad", "Contact not found.", 404)
    try:
        dtype = DeviceType(device_type)
    except ValueError:
        dtype = DeviceType.other
    try:
        await svc.devices.adopt(session, mac=mac_n, contact=contact, device_type=dtype, nickname=nickname,
                                actor=admin["name"])
    except DeviceBlocked:
        owner = blocked_owner(session, mac_n)
        name = owner.display_name if owner else "a blocked person"
        return _flash("bad", f"{mac_n} belongs to {name}, who is blocked. Unblock them first.", 409)
    except PersonBlocked:
        return _flash("bad", f"{contact.display_name} is blocked. Unblock them first.", 409)
    except OPNsenseError:
        log.exception("OPNsense request failed")
        return _flash("bad", "OPNsense request failed. Details are in the portal logs.", 502)
    return _flash("ok", f"Assigned {mac_n} to {contact.display_name}.")


@router.post("/unidentified/{mac}/remove", dependencies=[Depends(csrf_protect)])
async def remove_unidentified(mac: str, request: Request, admin: dict = Depends(require_admin),
                              session: Session = Depends(get_session)):
    mac_n = normalize_mac(mac)
    if not mac_n:
        return _flash("bad", "Invalid MAC.", 400)
    try:
        await _svc(request).devices.remove_unidentified(session, mac_n, actor=admin["name"])
    except OPNsenseError:
        log.exception("OPNsense request failed")
        return _flash("bad", "OPNsense request failed. Details are in the portal logs.", 502)
    return _flash("ok", f"Removed {mac_n}.")


# ---------------------------------------------------------------- events
@router.get("/events")
async def events(request: Request, admin: dict = Depends(require_admin)):
    return StreamingResponse(sse_stream(request, request.headers.get("last-event-id")),
                             media_type="text/event-stream",
                             headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})
