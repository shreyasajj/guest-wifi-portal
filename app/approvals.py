"""Approval-request state machine.

pending ──approve──────────▶ approved          (BDAY written to CardDAV)
        ├─approve_no_save──▶ approved_no_save  (CardDAV untouched)
        ├─deny─────────────▶ denied
        └─expires_at passed▶ expired

The first decision wins: transitions use `UPDATE ... WHERE status='pending'`.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import date, datetime, timedelta

from sqlalchemy import update
from sqlmodel import Session, col, select

from .carddav import CardDAVClient, CardDAVError
from .events import EventBus, audit
from .matching import Contact
from .models import ApprovalRequest, ApprovalStatus, DecidedBy, iso, utcnow

log = logging.getLogger(__name__)

DECISIONS = {
    "approve": ApprovalStatus.approved,
    "approve_no_save": ApprovalStatus.approved_no_save,
    "deny": ApprovalStatus.denied,
}


class Cooldown(Exception):
    def __init__(self, retry_after: int):
        super().__init__(f"retry in {retry_after}s")
        self.retry_after = retry_after


class AlreadyResolved(Exception):
    def __init__(self, status: str):
        super().__init__(f"request already {status}")
        self.status = status


class NotFound(Exception):
    pass


class ContactChoiceRequired(Exception):
    """Admin UI approve with several matched contacts must name one."""


@dataclass
class ResolveResult:
    request: ApprovalRequest
    birthday_saved: bool = False
    note: str | None = None
    error: str | None = None


def request_payload(req: ApprovalRequest) -> dict:
    return {
        "request_id": req.id,
        "status": req.status,
        "contact_name": req.contact_name,
        "contact_uids": req.contact_uids,
        "entered_birthday": req.entered_birthday,
        "mac": req.mac,
        "client_ip": req.client_ip,
        "user_agent": req.user_agent,
        "created_at": iso(req.created_at),
        "expires_at": iso(req.expires_at),
        "decided_by": req.decided_by,
        "chosen_contact_uid": req.chosen_contact_uid,
        "note": req.note,
        "error": req.error,
    }


class ApprovalService:
    def __init__(self, bus: EventBus, carddav: CardDAVClient | None, *, ttl_seconds: int = 600,
                 cooldown_seconds: int = 20):
        self.bus = bus
        self.carddav = carddav
        self.ttl = ttl_seconds
        self.cooldown = cooldown_seconds

    # ---------------------------------------------------------------- create
    def request(self, session: Session, *, contacts: list[Contact], entered_birthday: date, ip: str,
                mac: str, user_agent: str | None, now: datetime | None = None) -> tuple[ApprovalRequest, bool]:
        """Return (request, created). Reuses a pending request for the MAC; enforces the cooldown."""
        now = now or utcnow()
        self.expire_due(session, now=now)

        pending = session.exec(
            select(ApprovalRequest).where(ApprovalRequest.mac == mac,
                                          ApprovalRequest.status == ApprovalStatus.pending.value)
            .order_by(col(ApprovalRequest.created_at).desc())
        ).first()
        if pending:
            return pending, False

        last = session.exec(
            select(ApprovalRequest).where(ApprovalRequest.mac == mac)
            .order_by(col(ApprovalRequest.created_at).desc())
        ).first()
        if last:
            elapsed = (now - last.created_at).total_seconds()
            if elapsed < self.cooldown:
                raise Cooldown(int(self.cooldown - elapsed + 0.999))

        names = []
        for c in contacts:
            if c.display_name not in names:
                names.append(c.display_name)
        req = ApprovalRequest(
            contact_uids_json=json.dumps([c.uid for c in contacts]),
            contact_name=" / ".join(names),
            entered_birthday=entered_birthday.isoformat(),
            client_ip=ip, mac=mac, user_agent=(user_agent or "")[:300],
            created_at=now, expires_at=now + timedelta(seconds=self.ttl),
        )
        session.add(req)
        session.commit()
        session.refresh(req)
        audit(session, "approval_requested", target=req.id,
              detail={"contacts": req.contact_uids, "mac": mac, "ip": ip, "birthday": req.entered_birthday})
        self.bus.publish(session, "approval_requested", request_payload(req))
        return req, True

    # --------------------------------------------------------------- resolve
    def _transition(self, session: Session, req_id: str, status: ApprovalStatus, by: str,
                    contact_uid: str | None, now: datetime) -> bool:
        res = session.execute(
            update(ApprovalRequest)
            .where(col(ApprovalRequest.id) == req_id,
                   col(ApprovalRequest.status) == ApprovalStatus.pending.value)
            .values(status=status.value, decided_by=by, decided_at=now, chosen_contact_uid=contact_uid)
        )
        session.commit()
        return res.rowcount == 1

    async def resolve(self, session: Session, req_id: str, decision: str, *, by: DecidedBy,
                      contact_uid: str | None = None, actor: str | None = None,
                      now: datetime | None = None) -> ResolveResult:
        now = now or utcnow()
        if decision not in DECISIONS:
            raise ValueError(f"unknown decision {decision}")
        req = session.get(ApprovalRequest, req_id)
        if not req:
            raise NotFound(req_id)
        if req.status == ApprovalStatus.pending.value and req.expires_at <= now:
            self.expire_due(session, now=now)
            session.refresh(req)
        if req.status != ApprovalStatus.pending.value:
            raise AlreadyResolved(req.status)

        status = DECISIONS[decision]
        uids = req.contact_uids
        note = None
        if contact_uid and contact_uid not in uids:
            raise ValueError("contact_uid is not one of the matched contacts")
        if status != ApprovalStatus.denied and not contact_uid:
            if len(uids) == 1:
                contact_uid = uids[0]
            elif status == ApprovalStatus.approved and by == DecidedBy.admin_ui:
                raise ContactChoiceRequired()
            else:
                contact_uid = uids[0]
                if status == ApprovalStatus.approved:
                    note = (f"Several contacts matched ({len(uids)}); birthday written to the first one "
                            f"({contact_uid}). Verify which contact was updated.")

        if not self._transition(session, req_id, status, by.value, contact_uid, now):
            session.refresh(req)
            raise AlreadyResolved(req.status)

        session.refresh(req)
        result = ResolveResult(request=req, note=note)
        actor = actor or by.value

        if status == ApprovalStatus.approved:
            try:
                if not self.carddav:
                    raise CardDAVError("CardDAV not configured")
                await self.carddav.write_birthday(contact_uid, date.fromisoformat(req.entered_birthday))
                result.birthday_saved = True
                audit(session, "carddav_write", actor=actor, target=contact_uid,
                      detail={"request": req.id, "bday": req.entered_birthday}, needs_review=bool(note))
            except CardDAVError as exc:
                result.error = f"Access granted, but saving the birthday failed: {exc}"
                audit(session, "carddav_write_failed", actor=actor, target=contact_uid,
                      detail={"request": req.id, "error": str(exc)}, needs_review=True)

        if note or result.error:
            req.note = note
            req.error = result.error
            session.add(req)
            session.commit()
            session.refresh(req)

        audit(session, f"approval_{status.value}", actor=actor, target=req.id,
              detail={"contact_uid": contact_uid, "mac": req.mac, "decided_by": by.value, "note": note},
              needs_review=bool(note))
        self.bus.publish(session, "approval_resolved", request_payload(req))
        return result

    # ---------------------------------------------------------------- expiry
    def expire_due(self, session: Session, now: datetime | None = None) -> list[ApprovalRequest]:
        now = now or utcnow()
        due = session.exec(
            select(ApprovalRequest).where(ApprovalRequest.status == ApprovalStatus.pending.value,
                                          ApprovalRequest.expires_at <= now)
        ).all()
        expired = []
        for req in due:
            if self._transition(session, req.id, ApprovalStatus.expired, DecidedBy.system.value, None, now):
                session.refresh(req)
                expired.append(req)
                audit(session, "approval_expired", target=req.id, detail={"mac": req.mac})
                self.bus.publish(session, "approval_resolved", request_payload(req))
        return expired

    def pending(self, session: Session) -> list[ApprovalRequest]:
        return list(session.exec(
            select(ApprovalRequest).where(ApprovalRequest.status == ApprovalStatus.pending.value)
            .order_by(col(ApprovalRequest.created_at))
        ).all())
