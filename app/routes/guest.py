"""Guest login flow: phone + birthday -> (approval) -> device type -> done."""
from __future__ import annotations

import logging
import time
from datetime import date

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import JSONResponse, RedirectResponse
from sqlmodel import Session, select

from ..approvals import Cooldown
from ..carddav import CardDAVError
from ..db import get_session
from ..devices import PersonBlocked, blocked_owner
from ..events import audit
from ..matching import Contact, Outcome, evaluate, normalize_phone
from ..models import ApprovalRequest, ApprovalStatus, Device, DeviceType, Person
from ..opnsense import OPNsenseError
from ..security import client_ip, csrf_protect
from ..templating import templates

log = logging.getLogger(__name__)
router = APIRouter()

VERIFIED = "verified"
APPROVAL = "approval_id"
VERIFY_TTL = 15 * 60

GENERIC_REJECT = "We couldn't verify those details. Check them and try again."
NO_MAC = "We couldn't identify your device. Make sure you're connected to the guest Wi‑Fi, then reload this page."
BACKEND = "Something went wrong on our side. Try again in a minute."


def _svc(request: Request):
    return request.app.state.services


def _mask(phone: str | None) -> str | None:
    return phone[:3] + "•" * max(0, len(phone) - 7) + phone[-4:] if phone and len(phone) > 7 else phone


async def _lookup_mac(request: Request, ip: str) -> str | None:
    svc = _svc(request)
    try:
        return await svc.opn.mac_for_ip(ip, svc.settings.guest_interface_list or None)
    except OPNsenseError as exc:
        log.error("ARP lookup failed: %s", exc)
        return None


def _render(request: Request, template: str, status: int = 200, **ctx):
    ctx.setdefault("today", date.today().isoformat())
    return templates.TemplateResponse(request, template, ctx, status_code=status)


def _login(request: Request, status: int = 200, **ctx):
    return _render(request, "guest/login.html", status, **ctx)


@router.get("/")
async def index(request: Request, session: Session = Depends(get_session)):
    ip = client_ip(request)
    mac = await _lookup_mac(request, ip)
    if mac:
        device = session.exec(select(Device).where(Device.mac == mac, Device.revoked == False)).first()  # noqa: E712
        if device:
            person = session.get(Person, device.person_uid) if device.person_uid else None
            if not (person and person.blocked):
                return _render(request, "guest/done.html", already=True, device=device,
                               name=person.display_name.split(" ")[0] if person else None)
    return _login(request)


@router.get("/captive-portal")
async def captive_portal_api(request: Request, session: Session = Depends(get_session)):
    """RFC 8908 Captive Portal API. Point DHCP option 114 here so phones offer 'Sign in to network'."""
    mac = await _lookup_mac(request, client_ip(request))
    known = bool(mac and session.exec(select(Device).where(Device.mac == mac, Device.revoked == False)).first())  # noqa: E712
    portal = _svc(request).settings.public_guest_url.rstrip("/") or str(request.base_url).rstrip("/")
    return JSONResponse({"captive": not known, "user-portal-url": portal + "/"},
                        media_type="application/captive+json", headers={"Cache-Control": "no-store"})


@router.post("/login", dependencies=[Depends(csrf_protect)])
async def login(request: Request, phone: str = Form(""), birthday: str = Form(""),
                session: Session = Depends(get_session)):
    svc = _svc(request)
    ip = client_ip(request)
    ua = request.headers.get("user-agent")
    form = {"phone": phone, "birthday": birthday}
    mac = await _lookup_mac(request, ip)

    def log_attempt(success: bool, reason: str, **detail):
        svc.limiter.record(session, ip, mac, success, reason)
        audit(session, "login_success" if success else "login_attempt", actor="guest", target=mac or ip,
              detail={"ip": ip, "mac": mac, "reason": reason, "phone": _mask(normalize_phone(phone, svc.settings.phone_default_region)), **detail})

    if not mac:
        log_attempt(False, "no_mac")
        return _login(request, 400, error=NO_MAC, **form)

    retry = svc.limiter.retry_after(session, ip, mac)
    if retry:
        log_attempt(False, "rate_limited", retry_after=retry)
        return _login(request, 429, locked=retry, **form)

    owner = blocked_owner(session, mac)
    if owner is not None:
        # Same generic message as a wrong birthday, and no approval request, so you aren't notified.
        log_attempt(False, "blocked_device", owner=owner.contact_uid)
        return _login(request, 401, error=GENERIC_REJECT, **form)

    try:
        entered = date.fromisoformat(birthday.strip())
    except ValueError:
        log_attempt(False, "invalid_input")
        return _login(request, 400, error="Enter your birth date.", **form)
    e164 = normalize_phone(phone, svc.settings.phone_default_region)
    if not e164:
        log_attempt(False, "invalid_input")
        return _login(request, 400, error="Enter a valid phone number.", **form)

    try:
        contacts = await svc.carddav.contacts()
        result = evaluate(contacts, e164, entered)
        if result.outcome == Outcome.reject_no_phone:
            fresh = await svc.carddav.refresh_if_allowed()
            if fresh is not None:
                result = evaluate(fresh, e164, entered)
    except Exception as exc:  # noqa: BLE001 - any backend failure is generic for the guest
        log.exception("contact lookup failed")
        log_attempt(False, "backend_error", error=str(exc))
        return _login(request, 503, error=BACKEND, **form)

    # Blocked people get the same generic rejection.
    uids = [c.uid for c in result.candidates]
    blocked = {p.contact_uid for p in session.exec(select(Person).where(Person.contact_uid.in_(uids), Person.blocked == True)).all()} if uids else set()  # noqa: E712

    if result.outcome == Outcome.success and result.matched.uid not in blocked:
        log_attempt(True, "success", contact=result.matched.uid)
        request.session[VERIFIED] = {"uid": result.matched.uid, "mac": mac, "at": time.time()}
        request.session.pop(APPROVAL, None)
        return RedirectResponse("/device", status_code=303)

    if result.outcome == Outcome.needs_approval and not blocked:
        try:
            req, created = svc.approvals.request(session, contacts=result.candidates, entered_birthday=entered,
                                                 ip=ip, mac=mac, user_agent=ua)
        except Cooldown as cd:
            log_attempt(False, "approval_cooldown", retry_after=cd.retry_after)
            return _login(request, 429, cooldown=cd.retry_after, **form)
        log_attempt(False, "approval_requested" if created else "approval_reused", request=req.id)
        request.session[APPROVAL] = req.id
        return RedirectResponse("/waiting", status_code=303)

    log_attempt(False, "blocked" if blocked else result.outcome.value)
    return _login(request, 401, error=GENERIC_REJECT, **form)


@router.get("/waiting")
async def waiting(request: Request):
    if not request.session.get(APPROVAL):
        return RedirectResponse("/", status_code=303)
    return _render(request, "guest/waiting.html")


@router.get("/waiting/status")
async def waiting_status(request: Request, session: Session = Depends(get_session)):
    svc = _svc(request)
    req_id = request.session.get(APPROVAL)
    req = session.get(ApprovalRequest, req_id) if req_id else None
    if not req:
        return JSONResponse({"state": "failed", "next": "/failed"})
    if req.status == ApprovalStatus.pending.value:
        svc.approvals.expire_due(session)
        session.refresh(req)
    if req.status == ApprovalStatus.pending.value:
        return JSONResponse({"state": "pending"}, headers={"Cache-Control": "no-store"})
    request.session.pop(APPROVAL, None)
    if req.status in (ApprovalStatus.approved.value, ApprovalStatus.approved_no_save.value):
        request.session[VERIFIED] = {"uid": req.chosen_contact_uid or req.contact_uids[0], "mac": req.mac,
                                     "at": time.time(), "approval": req.id}
        return JSONResponse({"state": "approved", "next": "/device"})
    return JSONResponse({"state": "failed", "next": "/failed"})


@router.get("/failed")
async def failed(request: Request):
    return _render(request, "guest/message.html", heading="Sorry", message="Couldn't connect, try again later.")


def _verified(request: Request) -> dict | None:
    v = request.session.get(VERIFIED)
    if not v or time.time() - v.get("at", 0) > VERIFY_TTL:
        return None
    return v


async def _contact(request: Request, session: Session, uid: str) -> Contact | None:
    try:
        c = await _svc(request).carddav.get_by_uid(uid)
        if c:
            return c
    except CardDAVError:
        log.warning("CardDAV unavailable, falling back to stored person")
    p = session.get(Person, uid)
    if p:
        return Contact(uid=p.contact_uid, display_name=p.display_name, phones=p.phones,
                       emails=[p.email] if p.email else [])
    return None


@router.get("/device")
async def device_form(request: Request, session: Session = Depends(get_session)):
    v = _verified(request)
    if not v:
        return RedirectResponse("/", status_code=303)
    c = await _contact(request, session, v["uid"])
    first = (c.display_name.split(" ")[0] if c else "My")
    return _render(request, "guest/device.html", first_name=first)


@router.post("/device", dependencies=[Depends(csrf_protect)])
async def device_submit(request: Request, device_type: str = Form("other"), nickname: str = Form(""),
                        session: Session = Depends(get_session)):
    svc = _svc(request)
    v = _verified(request)
    if not v:
        return RedirectResponse("/", status_code=303)
    try:
        dtype = DeviceType(device_type)
    except ValueError:
        dtype = DeviceType.other
    ip = client_ip(request)
    mac = await _lookup_mac(request, ip)
    if mac != v["mac"]:
        request.session.pop(VERIFIED, None)
        return _render(request, "guest/message.html", 400, message="Your connection changed.",
                       detail="Please sign in again from this device.")
    contact = await _contact(request, session, v["uid"])
    if not contact:
        return _render(request, "guest/message.html", 503, message=BACKEND)
    try:
        result = await svc.devices.register(session, contact=contact, mac=mac, ip=ip, device_type=dtype,
                                            nickname=nickname, user_agent=request.headers.get("user-agent"),
                                            replace_phone=True)  # newest phone is the tracked one
    except PersonBlocked:
        request.session.pop(VERIFIED, None)
        return _render(request, "guest/message.html", 403, heading="Sorry", message="Couldn't connect, try again later.")
    except OPNsenseError:
        log.exception("granting access failed")
        return _render(request, "guest/device.html", 503, error=BACKEND, device_type=device_type, nickname=nickname,
                       first_name=contact.display_name.split(" ")[0])
    request.session.pop(VERIFIED, None)
    return _render(request, "guest/done.html", device=result.device, name=contact.display_name.split(" ")[0])
