"""Read models shared by the admin UI and the REST API."""
from __future__ import annotations

import asyncio
import json
from typing import AsyncIterator

from fastapi import Request
from sqlmodel import Session, col, select

from .approvals import request_payload
from .db import session_scope
from .devices import device_payload
from .models import ApprovalRequest, ApprovalStatus, Device, DeviceType, Event, Person, UnidentifiedDevice, iso


def people_view(session: Session) -> list[dict]:
    devices = session.exec(select(Device)).all()
    by_person: dict[str, list[Device]] = {}
    for d in devices:
        if d.person_uid:
            by_person.setdefault(d.person_uid, []).append(d)
    out = []
    for p in session.exec(select(Person).order_by(Person.display_name)).all():
        ds = by_person.get(p.contact_uid, [])
        phone = next((d for d in ds if d.type == DeviceType.phone.value and not d.revoked), None)
        out.append({
            "person_uid": p.contact_uid, "name": p.display_name, "phones": p.phones, "email": p.email,
            "blocked": p.blocked, "home": p.home,
            "home_changed_at": iso(p.home_changed_at) if p.home_changed_at else None,
            "tracked_device_mac": phone.mac if phone else None,
            "tracked_device_id": phone.id if phone else None,
            "devices": [device_payload(d, p) for d in sorted(ds, key=lambda d: (d.revoked, d.type != "phone", d.label))],
        })
    return out


def devices_view(session: Session, include_revoked: bool = True) -> list[dict]:
    people = {p.contact_uid: p for p in session.exec(select(Person)).all()}
    q = select(Device).order_by(col(Device.revoked), col(Device.last_seen).desc())
    if not include_revoked:
        q = q.where(Device.revoked == False)  # noqa: E712
    return [device_payload(d, people.get(d.person_uid)) for d in session.exec(q).all()]


def unidentified_view(session: Session) -> list[dict]:
    return [
        {"mac": u.mac, "ip": u.ip, "sources": u.sources.split(",") if u.sources else [], "session_id": u.session_id,
         "first_seen": iso(u.first_seen), "last_seen": iso(u.last_seen)}
        for u in session.exec(select(UnidentifiedDevice).order_by(col(UnidentifiedDevice.first_seen).desc())).all()
    ]


def approvals_view(session: Session, status: str | None = "pending") -> list[dict]:
    q = select(ApprovalRequest).order_by(col(ApprovalRequest.created_at).desc()).limit(200)
    if status:
        q = q.where(ApprovalRequest.status == status)
    return [request_payload(r) for r in session.exec(q).all()]


def status_view(session: Session) -> dict:
    people = session.exec(select(Person)).all()
    devices = session.exec(select(Device).where(Device.revoked == False)).all()  # noqa: E712
    return {
        "guests_home": sum(1 for p in people if p.home and not p.blocked),
        "guests_home_names": sorted(p.display_name for p in people if p.home and not p.blocked),
        "people": len(people),
        "devices": len(devices),
        "devices_online": sum(1 for d in devices if d.online),
        "unidentified": len(session.exec(select(UnidentifiedDevice)).all()),
        "pending_approvals": len(session.exec(select(ApprovalRequest).where(
            ApprovalRequest.status == ApprovalStatus.pending.value)).all()),
    }


def _frame(ev: dict) -> str:
    return f"id: {ev['id']}\nevent: {ev['type']}\ndata: {json.dumps(ev)}\n\n"


async def sse_stream(request: Request, last_event_id: str | None) -> AsyncIterator[str]:
    bus = request.app.state.services.bus
    q = bus.subscribe()
    try:
        yield "retry: 5000\n\n"
        last = int(last_event_id) if last_event_id and last_event_id.isdigit() else None
        if last is not None:
            with session_scope() as s:
                for e in s.exec(select(Event).where(Event.id > last).order_by(col(Event.id)).limit(500)).all():
                    last = e.id
                    yield _frame(e.as_dict())
        while True:
            if await request.is_disconnected():
                break
            try:
                ev = await asyncio.wait_for(q.get(), timeout=15)
            except asyncio.TimeoutError:
                yield ": ping\n\n"
                continue
            if last is not None and ev["id"] <= last:
                continue
            yield _frame(ev)
    finally:
        bus.unsubscribe(q)
