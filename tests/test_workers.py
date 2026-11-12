from datetime import timedelta

from sqlmodel import select

from app.models import Device, Event, Person, UnidentifiedDevice, utcnow
from app.opnsense import ArpEntry, CPSession, Lease
from app.workers import apply_presence, collect_sightings, plan_reconcile, run_mac_expiry, run_reconcile

A, B, C, D = (f"aa:bb:cc:00:00:0{i}" for i in range(1, 5))


def dev(mac, revoked=False, **kw):
    return Device(mac=mac, revoked=revoked, **kw)


# ------------------------------------------------------------ reconciler
def test_plan_reconcile():
    devices = [dev(A), dev(B), dev(C, revoked=True)]
    allowed = {"zone": {A, C, D}}
    sessions = [CPSession("s-c", C, "10.0.20.3", "", {}), CPSession("s-x", "ee:ee:ee:ee:ee:ee", "10.0.20.9", "", {}),
                CPSession("s-a", A, "10.0.20.1", "", {})]
    plan = plan_reconcile(allowed, sessions, devices)
    assert plan.revoke == {B} and plan.readd == set()  # authorized but removed from OPNsense
    assert plan.remove == {C}  # revoked but still allowed
    assert plan.disconnect == ["s-c"]
    assert set(plan.unidentified) == {D, "ee:ee:ee:ee:ee:ee"}
    assert plan.unidentified[D]["sources"] == {"zone"}
    assert plan.unidentified["ee:ee:ee:ee:ee:ee"]["ip"] == "10.0.20.9"


def test_plan_reconcile_alias_and_zone():
    plan = plan_reconcile({"zone": {A, B}, "alias": {B, D}}, [], [dev(A), dev(B)])
    assert plan.revoke == {A}  # missing from alias
    assert plan.unidentified[D]["sources"] == {"alias"}


def test_plan_reconcile_readd_mode():
    plan = plan_reconcile({"zone": {A}}, [], [dev(A), dev(B)], missing_action="readd")
    assert plan.readd == {B} and plan.revoke == set()


def test_plan_reconcile_holds_when_every_mac_vanishes():
    plan = plan_reconcile({"zone": set()}, [], [dev(A), dev(B), dev(C, revoked=True)])
    assert plan.revoke == set() and plan.held == {A, B}
    # a single registered device can still be removed
    assert plan_reconcile({"zone": set()}, [], [dev(A)]).revoke == {A}


async def test_run_reconcile_readds_and_flags(services, session, opn):
    services.settings.missing_mac_action = "readd"
    session.add(dev(A))
    session.add(dev(B, revoked=True))
    session.commit()
    opn.allowed = [B, D]
    opn.sessions = [{"sessionId": "s-b", "macAddress": B, "ipAddress": "10.0.20.2", "userName": ""}]

    plan = await run_reconcile(services)
    assert plan.readd == {A} and plan.remove == {B}
    assert sorted(opn.allowed) == [A, D]
    assert opn.sessions == []
    rows = session.exec(select(UnidentifiedDevice)).all()
    assert [r.mac for r in rows] == [D]
    assert len(session.exec(select(Event).where(Event.type == "unidentified_device")).all()) == 1

    await run_reconcile(services)  # second run: no duplicate event
    assert len(session.exec(select(Event).where(Event.type == "unidentified_device")).all()) == 1

    opn.allowed = [A]  # unknown MAC disappeared
    await run_reconcile(services)
    session.expire_all()
    assert session.exec(select(UnidentifiedDevice)).all() == []


def person(session, uid="u1", name="Maya", **kw):
    """Add and commit a person first: devices reference it with a foreign key."""
    p = Person(contact_uid=uid, display_name=name, **kw)
    session.add(p)
    session.commit()
    return p


async def test_removed_mac_revokes_device_and_keeps_person_with_other_devices(services, session, opn):
    person(session)
    session.add(dev(A, person_uid="u1", type="phone"))
    session.add(dev(B, person_uid="u1"))
    session.commit()
    opn.allowed = [B]  # you deleted A in OPNsense

    plan = await run_reconcile(services)
    assert plan.revoke == {A} and plan.readd == set()
    assert opn.allowed == [B]  # not put back
    session.expire_all()
    a = session.exec(select(Device).where(Device.mac == A)).one()
    assert a.revoked and a.revoke_reason == "removed from OPNsense allowed MACs"
    assert session.get(Person, "u1") is not None  # still has B
    assert session.exec(select(Event).where(Event.type == "device_revoked")).first()


async def test_removing_last_mac_removes_person(services, session, opn):
    person(session)
    session.add(dev(A, person_uid="u1", type="phone"))
    session.add(dev(B, person_uid="u1", revoked=True))  # revoked earlier
    person(session, "u2", "Sam")
    session.add(dev(C, person_uid="u2"))
    session.commit()
    opn.allowed = [C]

    await run_reconcile(services)
    session.expire_all()
    assert session.get(Person, "u1") is None
    assert session.exec(select(Device).where(Device.person_uid == "u1")).all() == []
    assert session.get(Person, "u2") is not None
    removed = session.exec(select(Event).where(Event.type == "person_removed")).one()
    assert removed.as_dict()["data"] == {"person_uid": "u1", "name": "Maya"}
    from app.models import AuditLog
    assert session.exec(select(AuditLog).where(AuditLog.action == "person_removed")).one().target == "u1"
    # the device is gone from the DB, so the next run doesn't flag or re-add anything
    plan = await run_reconcile(services)
    assert plan.revoke == set() and plan.readd == set() and opn.allowed == [C]


async def test_blocked_person_is_never_removed(services, session, opn):
    person(session, blocked=True)
    session.add(dev(A, person_uid="u1"))
    person(session, "u2")
    session.add(dev(B, person_uid="u2"))
    session.commit()
    opn.allowed = [B]
    await run_reconcile(services)
    session.expire_all()
    assert session.get(Person, "u1").blocked
    assert session.exec(select(Device).where(Device.mac == A)).one().revoked


async def test_every_mac_vanishing_revokes_nothing(services, session, opn):
    person(session)
    session.add(dev(A, person_uid="u1"))
    session.add(dev(B, person_uid="u1"))
    session.commit()
    opn.allowed = []
    plan = await run_reconcile(services)
    assert plan.held == {A, B}
    session.expire_all()
    assert not any(d.revoked for d in session.exec(select(Device)).all())
    from app.models import AuditLog
    entry = session.exec(select(AuditLog).where(AuditLog.action == "reconciler_all_missing")).one()
    assert entry.needs_review


# -------------------------------------------------------------- presence
def test_collect_sightings_arp_and_recent_leases():
    now = 1_000_000.0
    arp = [ArpEntry(A, "10.0.20.1", "vlan0.20", False), ArpEntry(B, "10.0.20.2", "vlan0.20", True)]
    leases = [Lease(C, "10.0.20.3", "vlan0.20", True, now - 60, now + 3000),      # renewed a minute ago
              Lease(D, "10.0.20.4", "vlan0.20", True, now - 5000, now + 3000),    # stale lease
              Lease(B, "10.0.20.2", "vlan0.20", True, None, now + 100)]           # no start time
    seen = collect_sightings(arp, leases, now_epoch=now, recent_seconds=600, previous_lease_ends={B: now + 50})
    assert set(seen) == {A, B, C}
    assert seen[B].source == "dhcp"  # end time moved since last poll => renewed
    seen2 = collect_sightings([], leases, now_epoch=now, recent_seconds=600, previous_lease_ends={B: now + 100})
    assert set(seen2) == {C}


async def test_presence_grace_period_and_person_events(services, session):
    session.add(Person(contact_uid="u1", display_name="Maya"))
    session.commit()
    session.add(dev(A, person_uid="u1", type="phone"))
    session.commit()
    t0 = utcnow()
    bus = services.bus

    emitted = apply_presence(session, bus, {A: type("S", (), {"ip": "10.0.20.1", "source": "arp"})()}, now=t0,
                             grace_seconds=300)
    assert emitted == ["device_online", "person_home"]

    assert apply_presence(session, bus, {}, now=t0 + timedelta(seconds=299), grace_seconds=300) == []
    emitted = apply_presence(session, bus, {}, now=t0 + timedelta(seconds=300), grace_seconds=300)
    assert emitted == ["device_offline", "person_away"]
    assert not session.get(Person, "u1").home


async def test_mac_expiry_off_by_default(services, session, opn):
    assert services.settings.mac_expiry_days == 0
    old = utcnow() - timedelta(days=400)
    session.add(dev(A, first_seen=old, last_seen=old))
    session.commit()
    opn.allowed = [A]
    assert await run_mac_expiry(services) == []
    assert opn.allowed == [A]


async def test_mac_expiry_removes_stale(services, session, opn):
    services.settings.mac_expiry_days = 30
    old = utcnow() - timedelta(days=31)
    session.add(dev(A, first_seen=old, last_seen=old))
    session.add(dev(B, last_seen=utcnow()))
    session.commit()
    opn.allowed = [A, B]
    expired = await run_mac_expiry(services)
    assert expired == [A]
    assert opn.allowed == [B]
    session.expire_all()
    d = session.exec(select(Device).where(Device.mac == A)).one()
    assert d.revoked and d.revoke_reason.startswith("expired")


async def test_blocked_device_added_back_in_opnsense_is_removed_again(services, session, opn):
    person(session, blocked=True)
    session.add(dev(A, person_uid="u1", revoked=True))
    session.commit()
    opn.allowed = [A]  # someone re-added it by hand in OPNsense
    plan = await run_reconcile(services)
    assert plan.remove == {A} and opn.allowed == []
