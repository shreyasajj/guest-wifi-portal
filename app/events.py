"""Event log + in-process fan-out to SSE subscribers (admin UI and Home Assistant)."""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from sqlmodel import Session

from .models import AuditLog, Event

log = logging.getLogger(__name__)

EVENT_TYPES = {
    "person_home", "person_away", "device_online", "device_offline", "new_device",
    "device_revoked", "person_revoked", "person_unblocked", "person_removed", "unidentified_device",
    "approval_requested", "approval_resolved", "device_updated",
}


class EventBus:
    def __init__(self) -> None:
        self._subscribers: set[asyncio.Queue] = set()

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=500)
        self._subscribers.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self._subscribers.discard(q)

    def publish(self, session: Session, type_: str, payload: dict[str, Any]) -> Event:
        ev = Event(type=type_, payload_json=json.dumps(payload, default=str))
        session.add(ev)
        session.commit()
        session.refresh(ev)
        data = ev.as_dict()
        for q in list(self._subscribers):
            try:
                q.put_nowait(data)
            except asyncio.QueueFull:
                log.warning("dropping slow event subscriber")
                self._subscribers.discard(q)
        return ev


def audit(session: Session, action: str, *, actor: str = "system", target: str | None = None,
          detail: dict | None = None, needs_review: bool = False, commit: bool = True) -> AuditLog:
    entry = AuditLog(actor=actor, action=action, target=target,
                     detail_json=json.dumps(detail or {}, default=str), needs_review=needs_review)
    session.add(entry)
    if commit:
        session.commit()
    log.info("audit %s actor=%s target=%s %s", action, actor, target, detail or "")
    return entry
