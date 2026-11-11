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
    assert plan.readd == {B}  # authorized but missing in OPNsense
    assert plan.remove == {C}  # revoked but still allowed
    assert plan.disconnect == ["s-c"]
    assert set(plan.unidentified) == {D, "ee:ee:ee:ee:ee:ee"}
    assert plan.unidentified[D]["sources"] == {"zone"}
    assert plan.unidentified["ee:ee:ee:ee:ee:ee"]["ip"] == "10.0.20.9"


def test_plan_reconcile_alias_and_zone():
    plan = plan_reconcile({"zone": {A}, "alias": {D}}, [], [dev(A)])
    assert plan.readd == {A}  # missing from alias
    assert plan.unidentified[D]["sources"] == {"alias"}


async def test_run_reconcile_readds_and_flags(services, session, opn):
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
