import pytest
from sqlmodel import select

from app.devices import PersonBlocked, PhoneConflict, Registered
from app.matching import Contact
from app.models import Device, DeviceType, Event

MAYA = Contact("u1", "Maya Chen", ["+14155550142"], ["maya@example.com"])
OLD, NEW, LAPTOP = "aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02", "aa:bb:cc:00:00:03"


async def reg(services, session, mac, dtype=DeviceType.phone, replace=False, contact=MAYA):
    return await services.devices.register(session, contact=contact, mac=mac, ip="10.0.20.5", device_type=dtype,
                                           nickname=None, user_agent="UA", replace_phone=replace)


async def test_first_phone_is_tracked(services, session, opn):
    r = await reg(services, session, OLD)
    assert isinstance(r, Registered) and r.device.type == "phone"
    assert opn.allowed == [OLD]
    assert session.exec(select(Event).where(Event.type == "new_device")).first()


async def test_second_phone_asks_before_replacing(services, session, opn):
    await reg(services, session, OLD)
    r = await reg(services, session, NEW)
    assert isinstance(r, PhoneConflict) and r.existing.mac == OLD
    assert opn.allowed == [OLD]  # nothing granted yet
    assert session.exec(select(Device).where(Device.mac == NEW)).first() is None


async def test_replace_demotes_old_phone_but_keeps_access(services, session, opn):
    await reg(services, session, OLD)
    r = await reg(services, session, NEW, replace=True)
    assert isinstance(r, Registered) and r.demoted.mac == OLD
    old = session.exec(select(Device).where(Device.mac == OLD)).one()
    new = session.exec(select(Device).where(Device.mac == NEW)).one()
    assert old.type == "other" and not old.revoked
    assert new.type == "phone"
    assert sorted(opn.allowed) == [OLD, NEW]
    phones = session.exec(select(Device).where(Device.person_uid == "u1", Device.type == "phone")).all()
    assert len(phones) == 1


async def test_non_phone_devices_never_conflict(services, session):
    await reg(services, session, OLD)
    r = await reg(services, session, LAPTOP, DeviceType.other)
    assert isinstance(r, Registered)


async def test_same_mac_reregistering_as_phone_is_fine(services, session):
    await reg(services, session, OLD)
    assert isinstance(await reg(services, session, OLD), Registered)


async def test_revoke_device_removes_mac_and_session(services, session, opn):
    r = await reg(services, session, OLD)
    opn.sessions = [{"sessionId": "s1", "macAddress": OLD, "ipAddress": "10.0.20.5", "userName": ""}]
    await services.devices.revoke_device(session, r.device, actor="admin")
    assert opn.allowed == [] and opn.sessions == []
    assert r.device.revoked


async def test_revoke_person_blocks_future_logins(services, session, opn):
    await reg(services, session, OLD)
    await reg(services, session, LAPTOP, DeviceType.other)
    from app.models import Person

    p = session.get(Person, "u1")
    devs = await services.devices.revoke_person(session, p, actor="admin")
    assert {d.mac for d in devs} == {OLD, LAPTOP}
    assert opn.allowed == [] and p.blocked
    with pytest.raises(PersonBlocked):
        await reg(services, session, NEW)
    services.devices.unblock_person(session, p, actor="admin")
    assert isinstance(await reg(services, session, NEW), Registered)


async def test_adopt_phone_replaces_without_asking(services, session):
    await reg(services, session, OLD)
    r = await services.devices.adopt(session, mac=NEW, contact=MAYA, device_type=DeviceType.phone, nickname="Pixel",
                                     actor="admin")
    assert r.demoted.mac == OLD and r.device.nickname == "Pixel"


async def test_revoking_last_device_removes_person(services, session, opn):
    from app.models import Person

    await reg(services, session, OLD)
    r = await reg(services, session, LAPTOP, DeviceType.other)
    await services.devices.revoke_device(session, r.device, actor="admin")
    assert session.get(Person, "u1") is not None  # phone still active
    phone = session.exec(select(Device).where(Device.mac == OLD)).one()
    await services.devices.revoke_device(session, phone, actor="admin")
    session.expire_all()
    assert session.get(Person, "u1") is None
    assert session.exec(select(Device)).all() == []
    assert opn.allowed == []
    # signing in again brings them back
    assert isinstance(await reg(services, session, NEW), Registered)
    assert session.get(Person, "u1").display_name == "Maya Chen"


async def test_revoke_person_keeps_blocked_person(services, session):
    from app.models import Person

    await reg(services, session, OLD)
    p = session.get(Person, "u1")
    await services.devices.revoke_person(session, p, actor="admin")
    session.expire_all()
    assert session.get(Person, "u1").blocked
    assert session.exec(select(Device).where(Device.mac == OLD)).one().revoked
