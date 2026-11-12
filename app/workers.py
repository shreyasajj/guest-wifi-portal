"""Background workers: presence poller, reconciler, approval expiry, MAC expiry, event pruning."""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from sqlmodel import Session, delete, select

from .db import session_scope
from .devices import device_payload
from .events import audit
from .models import Device, DeviceType, Event, Person, UnidentifiedDevice, utcnow
from .opnsense import ArpEntry, CPSession, Lease

log = logging.getLogger(__name__)


# ============================================================== presence
@dataclass
class Sighting:
    ip: str | None
    source: str


def collect_sightings(arp: list[ArpEntry], leases: list[Lease], *, now_epoch: float, recent_seconds: int,
                      previous_lease_ends: dict[str, float | None]) -> dict[str, Sighting]:
    """MACs that count as present right now.

    ARP: any non-expired entry on the guest interface.
    DHCP: an active lease that was (re)acquired within `recent_seconds`. When the server
    doesn't report a start time, a change in the lease end time since the last poll means
    the client just renewed.
    """
    seen: dict[str, Sighting] = {}
    for e in arp:
        if not e.expired:
            seen[e.mac] = Sighting(e.ip, "arp")
    for lease in leases:
        if not lease.active:
            continue
        renewed = False
        if lease.starts is not None:
            renewed = now_epoch - lease.starts <= recent_seconds
        elif lease.mac in previous_lease_ends:
            renewed = previous_lease_ends[lease.mac] != lease.ends
        if renewed and lease.mac not in seen:
            seen[lease.mac] = Sighting(lease.ip, "dhcp")
    return seen


def apply_presence(session: Session, bus, seen: dict[str, Sighting], *, now: datetime, grace_seconds: int) -> list[str]:
    """Update device online state and person home/away. Returns the event types emitted."""
    emitted: list[str] = []
    devices = session.exec(select(Device).where(Device.revoked == False)).all()  # noqa: E712
    grace = timedelta(seconds=grace_seconds)
    for d in devices:
        s = seen.get(d.mac)
        if s:
            d.last_seen = now
            if s.ip:
                d.current_ip = s.ip
            if not d.online:
                d.online = True
                session.add(d)
                session.commit()
                bus.publish(session, "device_online", device_payload(d, session.get(Person, d.person_uid) if d.person_uid else None))
                emitted.append("device_online")
            session.add(d)
        elif d.online and (d.last_seen is None or now - d.last_seen >= grace):
            d.online = False
            session.add(d)
            session.commit()
            bus.publish(session, "device_offline", device_payload(d, session.get(Person, d.person_uid) if d.person_uid else None))
            emitted.append("device_offline")
    session.commit()

    for p in session.exec(select(Person)).all():
        phone = session.exec(select(Device).where(Device.person_uid == p.contact_uid,
                                                  Device.type == DeviceType.phone.value,
                                                  Device.revoked == False)).first()  # noqa: E712
        home = bool(phone and phone.online)
        if home != p.home:
            p.home = home
            p.home_changed_at = now
            session.add(p)
            session.commit()
            ev = "person_home" if home else "person_away"
            bus.publish(session, ev, {"person_uid": p.contact_uid, "name": p.display_name, "home": home,
                                      "device_mac": phone.mac if phone else None})
            emitted.append(ev)
    return emitted


# ============================================================ reconciler
@dataclass
class ReconcilePlan:
    readd: set[str] = field(default_factory=set)          # authorized in DB, missing in OPNsense (readd mode)
    revoke: set[str] = field(default_factory=set)         # authorized in DB, missing in OPNsense (revoke mode)
    held: set[str] = field(default_factory=set)           # missing, but not acted on (see plan_reconcile)
    remove: set[str] = field(default_factory=set)         # revoked in DB, still allowed
    disconnect: list[str] = field(default_factory=list)   # session ids of revoked devices
    unidentified: dict[str, dict] = field(default_factory=dict)  # mac -> {sources, ip, session_id}


def plan_reconcile(allowed: dict[str, set[str]], sessions: list[CPSession], devices: list[Device],
                   missing_action: str = "revoke") -> ReconcilePlan:
    plan = ReconcilePlan()
    active = {d.mac for d in devices if not d.revoked}
    revoked = {d.mac for d in devices if d.revoked}
    missing: set[str] = set()
    for source, macs in allowed.items():
        missing |= active - macs
        plan.remove |= macs & revoked
        for mac in macs - active - revoked:
            entry = plan.unidentified.setdefault(mac, {"sources": set(), "ip": None, "session_id": None})
            entry["sources"].add(source)
    for s in sessions:
        if not s.mac:
            continue
        if s.mac in revoked:
            plan.disconnect.append(s.session_id)
        elif s.mac not in active:
            entry = plan.unidentified.setdefault(s.mac, {"sources": set(), "ip": None, "session_id": None})
            entry["sources"].add("session")
            entry["ip"] = s.ip or entry["ip"]
            entry["session_id"] = s.session_id

    if missing_action == "readd":
        plan.readd = missing
    elif len(active) > 1 and missing == active:
        # Every device vanished at once: that's a reset or restored zone, not you removing guests.
        # Don't revoke everyone; leave it for a human to look at.
        plan.held = missing
    else:
        plan.revoke = missing
    return plan


async def run_reconcile(services) -> ReconcilePlan:
    access = services.access
    with session_scope() as session:
        # Read the DB before OPNsense. Registration writes to OPNsense first and the DB second,
        # so a device that is in this snapshot is already in the allowed list we read next.
        # The other order could revoke a guest who signed in between the two reads.
        devices = list(session.exec(select(Device)).all())
        allowed = await access.allowed()
        sessions = await access.sessions()
        plan = plan_reconcile(allowed, sessions, devices, services.settings.missing_mac_action)

        if plan.readd:
            await access.allow(*sorted(plan.readd))
            audit(session, "reconciler_readd", detail={"macs": sorted(plan.readd)})
        for mac in sorted(plan.revoke):
            d = session.exec(select(Device).where(Device.mac == mac)).first()
            if d:
                session.refresh(d)
            if d and not d.revoked:  # an admin may have revoked it meanwhile
                await services.devices.revoke_device(session, d, actor="system",
                                                     reason="removed from OPNsense allowed MACs")
        if plan.held:
            log.warning("every authorized MAC is missing from OPNsense (%d); not revoking, check the zone",
                        len(plan.held))
            audit(session, "reconciler_all_missing", detail={"macs": sorted(plan.held)}, needs_review=True)
        if plan.remove:
            if access.use_zone:
                await access.client.remove_allowed_macs(*plan.remove)
            if access.use_alias:
                await access.client.remove_alias_macs(*plan.remove)
            audit(session, "reconciler_remove_revoked", detail={"macs": sorted(plan.remove)})
        for sid in plan.disconnect:
            await access.client.disconnect_session(sid)
            audit(session, "reconciler_disconnect", target=sid)

        now = utcnow()
        existing = {u.mac: u for u in session.exec(select(UnidentifiedDevice)).all()}
        for mac, info in plan.unidentified.items():
            row = existing.pop(mac, None)
            sources = ",".join(sorted(info["sources"]))
            if row is None:
                row = UnidentifiedDevice(mac=mac, ip=info["ip"], sources=sources,
                                         session_id=info["session_id"], first_seen=now, last_seen=now)
                session.add(row)
                session.commit()
                audit(session, "unidentified_found", target=mac, detail={"sources": sources})
                services.bus.publish(session, "unidentified_device",
                                     {"mac": mac, "ip": info["ip"], "sources": sources})
            else:
                row.last_seen, row.sources = now, sources
                row.ip = info["ip"] or row.ip
                row.session_id = info["session_id"]
                session.add(row)
        for gone in existing.values():
            session.delete(gone)
        session.commit()
    return plan


# ============================================================ MAC expiry
async def run_mac_expiry(services, now: datetime | None = None) -> list[str]:
    if services.settings.mac_expiry_days <= 0:
        return []
    now = now or utcnow()
    cutoff = now - timedelta(days=services.settings.mac_expiry_days)
    expired = []
    with session_scope() as session:
        stale = session.exec(select(Device).where(Device.revoked == False)).all()  # noqa: E712
        for d in stale:
            last = d.last_seen or d.first_seen
            if last < cutoff:
                await services.devices.revoke_device(session, d, actor="system", reason="expired (not seen)")
                expired.append(d.mac)
    return expired


# ================================================================ runner
class WorkerRunner:
    def __init__(self, services):
        self.s = services
        self._tasks: list[asyncio.Task] = []
        self._lease_ends: dict[str, float | None] = {}

    async def presence_tick(self) -> None:
        st = self.s.settings
        ifaces = st.guest_interface_list or None
        arp = await self.s.opn.get_arp(ifaces)
        leases = []
        if st.dhcp_backend != "none":
            try:
                leases = await self.s.opn.get_leases(st.dhcp_backend, ifaces)
            except Exception as exc:  # noqa: BLE001 - leases are a secondary signal
                log.warning("lease fetch failed: %s", exc)
        import time
        seen = collect_sightings(arp, leases, now_epoch=time.time(), recent_seconds=st.dhcp_recent_seconds,
                                 previous_lease_ends=self._lease_ends)
        self._lease_ends = {l.mac: l.ends for l in leases}
        with session_scope() as session:
            apply_presence(session, self.s.bus, seen, now=utcnow(), grace_seconds=st.away_grace_seconds)

    async def expiry_tick(self) -> None:
        with session_scope() as session:
            self.s.approvals.expire_due(session)

    async def housekeeping_tick(self) -> None:
        await run_mac_expiry(self.s)
        cutoff = utcnow() - timedelta(days=self.s.settings.event_retention_days)
        with session_scope() as session:
            session.exec(delete(Event).where(Event.at < cutoff))
            session.commit()

    async def _loop(self, name: str, interval: int, fn) -> None:
        await asyncio.sleep(2)
        while True:
            try:
                await fn()
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001
                log.exception("worker %s failed", name)
            await asyncio.sleep(interval)

    def start(self) -> None:
        st = self.s.settings
        self._tasks = [
            asyncio.create_task(self._loop("presence", st.presence_poll_seconds, self.presence_tick)),
            asyncio.create_task(self._loop("reconciler", st.reconcile_seconds, lambda: run_reconcile(self.s))),
            asyncio.create_task(self._loop("approval-expiry", st.approval_expiry_check_seconds, self.expiry_tick)),
            asyncio.create_task(self._loop("housekeeping", 3600, self.housekeeping_tick)),
        ]

    async def stop(self) -> None:
        for t in self._tasks:
            t.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
