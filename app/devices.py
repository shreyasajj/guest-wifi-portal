"""Device registration, the one-phone-per-person rule, revocation and adoption."""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass

from sqlmodel import Session, select

from .events import EventBus, audit
from .matching import Contact
from .models import Device, DeviceType, Person, UnidentifiedDevice, iso, utcnow
from .opnsense import AccessController

log = logging.getLogger(__name__)


class PersonBlocked(Exception):
    pass


class DeviceBlocked(PersonBlocked):
    """The MAC belongs to a blocked person, so nobody may register it until they're unblocked."""

    def __init__(self, mac: str, owner: "Person"):
        super().__init__(owner.contact_uid)
        self.mac = mac
        self.owner = owner


def blocked_owner(session: Session, mac: str) -> Person | None:
    """The blocked person this MAC belongs to, if any. Blocking a person blocks all their devices:
    without this, their phone could get back on by signing in with someone else's details."""
    device = session.exec(select(Device).where(Device.mac == mac)).first()
    if device is None or not device.person_uid:
        return None
    owner = session.get(Person, device.person_uid)
    return owner if owner is not None and owner.blocked else None


@dataclass
class PhoneConflict:
    """The person already has a tracked phone; the guest must confirm replacement."""
    existing: Device


@dataclass
class Registered:
    device: Device
    demoted: Device | None = None


def device_payload(d: Device, person: Person | None = None) -> dict:
    return {
        "device_id": d.id, "mac": d.mac, "type": d.type, "nickname": d.nickname, "label": d.label,
        "person_uid": d.person_uid, "person_name": person.display_name if person else None,
        "online": d.online, "revoked": d.revoked, "current_ip": d.current_ip,
        "first_seen": iso(d.first_seen) if d.first_seen else None,
        "last_seen": iso(d.last_seen) if d.last_seen else None,
    }


def upsert_person(session: Session, contact: Contact) -> Person:
    p = session.get(Person, contact.uid)
    if not p:
        p = Person(contact_uid=contact.uid)
    p.display_name = contact.display_name
    p.phones_json = json.dumps(contact.phones)
    p.email = contact.emails[0] if contact.emails else None
    session.add(p)
    session.commit()
    session.refresh(p)
    return p


def tracked_phone(session: Session, person_uid: str) -> Device | None:
    return session.exec(
        select(Device).where(Device.person_uid == person_uid, Device.type == DeviceType.phone.value,
                             Device.revoked == False)  # noqa: E712
    ).first()


class DeviceService:
    def __init__(self, bus: EventBus, access: AccessController):
        self.bus = bus
        self.access = access

    async def register(self, session: Session, *, contact: Contact, mac: str, ip: str | None,
                       device_type: DeviceType, nickname: str | None, user_agent: str | None,
                       replace_phone: bool = False, actor: str = "guest") -> Registered | PhoneConflict:
        owner = blocked_owner(session, mac)
        if owner is not None:
            raise DeviceBlocked(mac, owner)
        person = upsert_person(session, contact)
        if person.blocked:
            raise PersonBlocked(person.contact_uid)

        demoted = None
        if device_type == DeviceType.phone:
            existing = tracked_phone(session, person.contact_uid)
            if existing and existing.mac != mac:
                if not replace_phone:
                    return PhoneConflict(existing)
                existing.type = DeviceType.other.value
                session.add(existing)
                demoted = existing
                audit(session, "phone_demoted", actor=actor, target=existing.mac,
                      detail={"person": person.contact_uid, "replaced_by": mac}, commit=False)

        # Grant access first: if OPNsense fails, nothing is half-saved.
        await self.access.allow(mac)

        now = utcnow()
        device = session.exec(select(Device).where(Device.mac == mac)).first()
        is_new = device is None
        if is_new:
            device = Device(mac=mac, first_seen=now)
        previous_owner = device.person_uid
        device.person_uid = person.contact_uid
        device.type = device_type.value
        device.nickname = (nickname or "").strip()[:60] or device.nickname
        device.user_agent = (user_agent or "")[:300] or device.user_agent
        device.current_ip = ip or device.current_ip
        device.last_seen = now
        device.revoked = False
        device.revoked_at = None
        device.revoke_reason = None
        session.add(device)
        unknown = session.get(UnidentifiedDevice, mac)
        if unknown:
            session.delete(unknown)
        session.commit()
        session.refresh(device)

        audit(session, "device_registered", actor=actor, target=mac,
              detail={"person": person.contact_uid, "type": device.type, "ip": ip,
                      "previous_owner": previous_owner, "new": is_new})
        self.bus.publish(session, "new_device", device_payload(device, person))
        if demoted:
            session.refresh(demoted)
            self.bus.publish(session, "device_updated", device_payload(demoted, person))
        return Registered(device, demoted)

    async def revoke_device(self, session: Session, device: Device, *, actor: str, reason: str = "revoked",
                            publish: bool = True, remove_orphan: bool = True) -> Device:
        """Revoke one device. If it was the owner's last active device, the owner is removed too
        (unless they are blocked: the block has to survive so they can't sign in again)."""
        await self.access.remove(device.mac)
        device.revoked = True
        device.revoked_at = utcnow()
        device.revoke_reason = reason
        device.online = False
        session.add(device)
        session.commit()
        session.refresh(device)
        audit(session, "device_revoked", actor=actor, target=device.mac, detail={"reason": reason})
        if publish:
            person = session.get(Person, device.person_uid) if device.person_uid else None
            self.bus.publish(session, "device_revoked", device_payload(device, person))
        if remove_orphan and device.person_uid:
            self.remove_person_if_orphaned(session, device.person_uid, actor=actor)
        return device

    def remove_person_if_orphaned(self, session: Session, person_uid: str, *, actor: str) -> bool:
        """Delete a person who has no active devices left, along with their revoked device rows.
        The audit log keeps the history. Signing in again recreates them from CardDAV."""
        person = session.get(Person, person_uid)
        if person is None or person.blocked:
            return False
        devices = session.exec(select(Device).where(Device.person_uid == person_uid)).all()
        if any(not d.revoked for d in devices):
            return False
        for d in devices:
            session.delete(d)
        session.delete(person)
        session.commit()
        audit(session, "person_removed", actor=actor, target=person_uid,
              detail={"name": person.display_name, "reason": "no devices left",
                      "devices": [d.mac for d in devices]})
        self.bus.publish(session, "person_removed", {"person_uid": person_uid, "name": person.display_name})
        return True

    async def revoke_person(self, session: Session, person: Person, *, actor: str) -> list[Device]:
        devices = session.exec(select(Device).where(Device.person_uid == person.contact_uid,
                                                    Device.revoked == False)).all()  # noqa: E712
        for d in devices:
            await self.revoke_device(session, d, actor=actor, reason="person revoked", remove_orphan=False)
        person.blocked = True
        person.blocked_at = utcnow()
        person.home = False
        session.add(person)
        session.commit()
        audit(session, "person_revoked", actor=actor, target=person.contact_uid,
              detail={"devices": [d.mac for d in devices]})
        self.bus.publish(session, "person_revoked", {"person_uid": person.contact_uid,
                                                     "name": person.display_name,
                                                     "devices": [d.mac for d in devices]})
        return list(devices)

    def unblock_person(self, session: Session, person: Person, *, actor: str) -> None:
        person.blocked = False
        person.blocked_at = None
        session.add(person)
        session.commit()
        audit(session, "person_unblocked", actor=actor, target=person.contact_uid)
        self.bus.publish(session, "person_unblocked", {"person_uid": person.contact_uid,
                                                       "name": person.display_name})

    async def adopt(self, session: Session, *, mac: str, contact: Contact, device_type: DeviceType,
                    nickname: str | None, actor: str) -> Registered:
        """Assign an unidentified MAC to a person. Admin action: a phone replaces the old one."""
        result = await self.register(session, contact=contact, mac=mac, ip=None, device_type=device_type,
                                     nickname=nickname, user_agent=None, replace_phone=True, actor=actor)
        assert isinstance(result, Registered)
        audit(session, "device_adopted", actor=actor, target=mac, detail={"person": contact.uid})
        return result

    async def remove_unidentified(self, session: Session, mac: str, *, actor: str) -> None:
        await self.access.remove(mac)
        row = session.get(UnidentifiedDevice, mac)
        if row:
            session.delete(row)
            session.commit()
        audit(session, "unidentified_removed", actor=actor, target=mac)
