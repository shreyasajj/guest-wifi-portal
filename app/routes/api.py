"""REST API for Home Assistant (bearer token) + SSE event stream."""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlmodel import Session, col, select

from ..approvals import AlreadyResolved, ContactChoiceRequired, NotFound, request_payload
from ..db import get_session
from ..devices import device_payload
from ..macs import normalize_mac
from ..models import ApprovalRequest, AuditLog, DecidedBy, Device, Person, iso
from ..opnsense import OPNsenseError
from ..security import require_api_token
from ..views import approvals_view, devices_view, people_view, sse_stream, status_view, unidentified_view

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api", dependencies=[Depends(require_api_token)])


def _svc(request: Request):
    return request.app.state.services


class ApproveBody(BaseModel):
    save_birthday: bool = True
    contact_uid: str | None = None


def _decided_by(actor: str) -> DecidedBy:
    return DecidedBy.home_assistant if actor == "home_assistant" else DecidedBy.admin_ui


@router.get("/status")
def status(session: Session = Depends(get_session)):
    return status_view(session)


@router.get("/people")
def people(session: Session = Depends(get_session)):
    return people_view(session)


@router.get("/devices")
def devices(include_revoked: bool = False, session: Session = Depends(get_session)):
    return devices_view(session, include_revoked)


@router.get("/unidentified")
def unidentified(session: Session = Depends(get_session)):
    return unidentified_view(session)


@router.get("/approvals")
def approvals(status: str | None = "pending", session: Session = Depends(get_session)):
    return approvals_view(session, status or None)


@router.get("/snapshot")
def snapshot(session: Session = Depends(get_session)):
    """Everything Home Assistant needs in one call (used by the polling fallback)."""
    return {"status": status_view(session), "people": people_view(session),
            "devices": devices_view(session, include_revoked=False), "unidentified": unidentified_view(session),
            "approvals": approvals_view(session, "pending")}


async def _resolve(request, session, req_id, decision, actor, contact_uid=None):
    try:
        res = await _svc(request).approvals.resolve(session, req_id, decision, by=_decided_by(actor),
                                                     contact_uid=contact_uid, actor=actor)
    except NotFound:
        raise HTTPException(404, "request not found")
    except AlreadyResolved:
        session.expire_all()
        raise HTTPException(409, f"already {session.get(ApprovalRequest, req_id).status}")
    except ContactChoiceRequired:
        raise HTTPException(422, "several contacts matched; pass contact_uid")
    except ValueError:
        raise HTTPException(422, "invalid decision or contact_uid for this request")
    return {**request_payload(res.request), "birthday_saved": res.birthday_saved, "error": res.error, "note": res.note}


@router.post("/approvals/{req_id}/approve")
async def approve(req_id: str, request: Request, body: ApproveBody | None = None,
                  actor: str = Depends(require_api_token), session: Session = Depends(get_session)):
    body = body or ApproveBody()
    return await _resolve(request, session, req_id, "approve" if body.save_birthday else "approve_no_save", actor,
                          body.contact_uid)


@router.post("/approvals/{req_id}/deny")
async def deny(req_id: str, request: Request, actor: str = Depends(require_api_token),
               session: Session = Depends(get_session)):
    return await _resolve(request, session, req_id, "deny", actor)


def _device(session: Session, ref: str) -> Device:
    d = session.get(Device, int(ref)) if ref.isdigit() else None
    if not d:
        mac = normalize_mac(ref)
        d = session.exec(select(Device).where(Device.mac == mac)).first() if mac else None
    if not d:
        raise HTTPException(404, "device not found")
    return d


@router.post("/devices/{ref}/revoke")
async def revoke_device(ref: str, request: Request, actor: str = Depends(require_api_token),
                        session: Session = Depends(get_session)):
    d = _device(session, ref)
    try:
        await _svc(request).devices.revoke_device(session, d, actor=actor)
    except OPNsenseError:
        log.exception("OPNsense request failed")
        raise HTTPException(502, "OPNsense request failed; see the portal logs")
    return device_payload(d)


@router.post("/people/{uid}/revoke")
async def revoke_person(uid: str, request: Request, actor: str = Depends(require_api_token),
                        session: Session = Depends(get_session)):
    p = session.get(Person, uid)
    if not p:
        raise HTTPException(404, "person not found")
    try:
        devs = await _svc(request).devices.revoke_person(session, p, actor=actor)
    except OPNsenseError:
        log.exception("OPNsense request failed")
        raise HTTPException(502, "OPNsense request failed; see the portal logs")
    return {"person_uid": uid, "revoked_devices": [d.mac for d in devs], "blocked": True}


@router.post("/people/{uid}/unblock")
async def unblock_person(uid: str, request: Request, actor: str = Depends(require_api_token),
                         session: Session = Depends(get_session)):
    p = session.get(Person, uid)
    if not p:
        raise HTTPException(404, "person not found")
    _svc(request).devices.unblock_person(session, p, actor=actor)
    return {"person_uid": uid, "blocked": False}


@router.get("/audit")
def audit_log(limit: int = 100, session: Session = Depends(get_session)):
    rows = session.exec(select(AuditLog).order_by(col(AuditLog.at).desc()).limit(min(limit, 1000))).all()
    return [{"at": iso(r.at), "actor": r.actor, "action": r.action, "target": r.target,
             "detail": r.detail, "needs_review": r.needs_review} for r in rows]


@router.get("/events")
async def events(request: Request, since: str | None = None):
    return StreamingResponse(sse_stream(request, request.headers.get("last-event-id") or since),
                             media_type="text/event-stream",
                             headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})
