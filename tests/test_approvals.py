import asyncio
import json
from datetime import date, timedelta

import pytest
from sqlmodel import select

from app.approvals import AlreadyResolved, ContactChoiceRequired, Cooldown
from app.matching import Contact
from app.models import ApprovalRequest, AuditLog, DecidedBy, Event, utcnow

MAC = "aa:bb:cc:00:00:01"
BDAY = date(1991, 4, 12)


@pytest.fixture
def contacts(dav):
    dav.add("u1", "Maya Chen", ["+14155550142"])
    dav.add("u2", "Maya C (work)", ["+14155550142"])
    return [Contact("u1", "Maya Chen", ["+14155550142"]), Contact("u2", "Maya C (work)", ["+14155550142"])]


def new(services, session, contacts, now=None, mac=MAC):
    return services.approvals.request(session, contacts=contacts, entered_birthday=BDAY, ip="10.0.20.50",
                                      mac=mac, user_agent="iPhone", now=now)


def events(session, type_):
    return session.exec(select(Event).where(Event.type == type_)).all()


async def test_create_publishes_event(services, session, contacts):
    req, created = new(services, session, contacts[:1])
    assert created and req.status == "pending"
    assert req.expires_at - req.created_at == timedelta(seconds=600)
    assert json.loads(events(session, "approval_requested")[0].payload_json)["request_id"] == req.id


async def test_pending_request_is_reused(services, session, contacts):
    t0 = utcnow()
    a, created_a = new(services, session, contacts, now=t0)
    b, created_b = new(services, session, contacts, now=t0 + timedelta(seconds=1))
    c, created_c = new(services, session, contacts, now=t0 + timedelta(seconds=60))
    assert created_a and not created_b and not created_c
    assert a.id == b.id == c.id
    assert len(events(session, "approval_requested")) == 1


async def test_cooldown_20s_after_denial_then_retry_allowed(services, session, contacts):
    t0 = utcnow()
    req, _ = new(services, session, contacts, now=t0)
    await services.approvals.resolve(session, req.id, "deny", by=DecidedBy.admin_ui, now=t0 + timedelta(seconds=2))
    with pytest.raises(Cooldown) as exc:
        new(services, session, contacts, now=t0 + timedelta(seconds=5))
    assert exc.value.retry_after == 15
    with pytest.raises(Cooldown):
        new(services, session, contacts, now=t0 + timedelta(seconds=19.5))
    again, created = new(services, session, contacts, now=t0 + timedelta(seconds=20))
    assert created and again.id != req.id  # no lockout after a denial


async def test_cooldown_is_per_mac(services, session, contacts):
    t0 = utcnow()
    req, _ = new(services, session, contacts, now=t0)
    await services.approvals.resolve(session, req.id, "deny", by=DecidedBy.admin_ui, now=t0)
    _, created = new(services, session, contacts, now=t0 + timedelta(seconds=1), mac="aa:bb:cc:00:00:02")
    assert created


async def test_expiry(services, session, contacts):
    t0 = utcnow()
    req, _ = new(services, session, contacts, now=t0)
    assert services.approvals.expire_due(session, now=t0 + timedelta(seconds=599)) == []
    expired = services.approvals.expire_due(session, now=t0 + timedelta(seconds=600))
    assert [r.id for r in expired] == [req.id]
    session.refresh(req)
    assert req.status == "expired" and req.decided_by == "system"
    assert json.loads(events(session, "approval_resolved")[-1].payload_json)["status"] == "expired"
    with pytest.raises(AlreadyResolved) as exc:
        await services.approvals.resolve(session, req.id, "approve", by=DecidedBy.admin_ui, contact_uid="u1")
    assert exc.value.status == "expired"


async def test_resolving_an_overdue_request_expires_it(services, session, contacts):
    t0 = utcnow() - timedelta(minutes=11)
    req, _ = new(services, session, contacts, now=t0)
    with pytest.raises(AlreadyResolved):
        await services.approvals.resolve(session, req.id, "approve_no_save", by=DecidedBy.home_assistant)


async def test_double_resolution_first_wins(services, session, contacts):
    req, _ = new(services, session, contacts[:1])
    await services.approvals.resolve(session, req.id, "approve_no_save", by=DecidedBy.home_assistant)
    with pytest.raises(AlreadyResolved) as exc:
        await services.approvals.resolve(session, req.id, "deny", by=DecidedBy.admin_ui)
    assert exc.value.status == "approved_no_save"
    session.refresh(req)
    assert req.decided_by == "home_assistant"


async def test_concurrent_resolution_exactly_one_wins(services, session, contacts, dav):
    req, _ = new(services, session, contacts[:1])
    results = await asyncio.gather(
        services.approvals.resolve(session, req.id, "approve", by=DecidedBy.admin_ui),
        services.approvals.resolve(session, req.id, "deny", by=DecidedBy.home_assistant),
        return_exceptions=True,
    )
    wins = [r for r in results if not isinstance(r, Exception)]
    losses = [r for r in results if isinstance(r, AlreadyResolved)]
    assert len(wins) == 1 and len(losses) == 1
    session.refresh(req)
    assert req.status == "approved"
    assert len(dav.puts) == 1


async def test_approve_writes_birthday(services, session, contacts, dav):
    req, _ = new(services, session, contacts[:1])
    res = await services.approvals.resolve(session, req.id, "approve", by=DecidedBy.admin_ui)
    assert res.birthday_saved and res.error is None
    assert "BDAY:1991-04-12" in dav.text("u1")
    assert session.exec(select(AuditLog).where(AuditLog.action == "carddav_write")).first()


async def test_approve_without_saving_leaves_carddav_alone(services, session, contacts, dav):
    req, _ = new(services, session, contacts[:1])
    res = await services.approvals.resolve(session, req.id, "approve_no_save", by=DecidedBy.admin_ui)
    assert not res.birthday_saved and dav.puts == []


async def test_admin_ui_must_pick_contact_when_several_match(services, session, contacts, dav):
    req, _ = new(services, session, contacts)
    with pytest.raises(ContactChoiceRequired):
        await services.approvals.resolve(session, req.id, "approve", by=DecidedBy.admin_ui)
    session.refresh(req)
    assert req.status == "pending"
    res = await services.approvals.resolve(session, req.id, "approve", by=DecidedBy.admin_ui, contact_uid="u2")
    assert res.request.chosen_contact_uid == "u2"
    assert "BDAY:1991-04-12" in dav.text("u2") and "BDAY" not in dav.text("u1")


async def test_home_assistant_multi_match_updates_first_and_flags_review(services, session, contacts, dav):
    req, _ = new(services, session, contacts)
    res = await services.approvals.resolve(session, req.id, "approve", by=DecidedBy.home_assistant)
    assert res.request.chosen_contact_uid == "u1"
    assert "Verify which contact was updated" in res.note
    assert "BDAY:1991-04-12" in dav.text("u1")
    flagged = session.exec(select(AuditLog).where(AuditLog.needs_review == True)).all()  # noqa: E712
    assert flagged


async def test_contact_uid_must_be_a_match(services, session, contacts):
    req, _ = new(services, session, contacts)
    with pytest.raises(ValueError):
        await services.approvals.resolve(session, req.id, "approve", by=DecidedBy.admin_ui, contact_uid="intruder")


async def test_etag_conflict_twice_grants_access_and_reports_error(services, session, contacts, dav):
    req, _ = new(services, session, contacts[:1])
    await services.carddav.contacts()
    dav.conflicts_left = 2
    res = await services.approvals.resolve(session, req.id, "approve", by=DecidedBy.admin_ui)
    assert res.request.status == "approved"
    assert not res.birthday_saved
    assert "saving the birthday to Nextcloud failed" in res.error
    assert "ETag" not in res.error  # no exception text in what the admin page shows
    assert session.get(ApprovalRequest, req.id).error == res.error
    fail = session.exec(select(AuditLog).where(AuditLog.action == "carddav_write_failed")).one()
    assert fail.needs_review and "ETag" in fail.detail["error"]  # full error kept in the audit log


def test_audit_keeps_personal_data_out_of_the_container_log(session, caplog):
    import logging

    from app.events import audit

    with caplog.at_level(logging.INFO, logger="app.events"):
        entry = audit(session, "approval_requested", target="aa:bb:cc:dd:ee:ff",
                      detail={"contacts": ["u1"], "mac": "aa:bb:cc:dd:ee:ff", "birthday": "1991-04-12",
                              "phone": "+1415***0142", "reason": "needs_approval", "error": "boom"})
    text = caplog.text
    assert "approval_requested" in text and "aa:bb:cc:dd:ee:ff" in text
    for secret in ("1991-04-12", "0142", "boom", "u1", "needs_approval"):
        assert secret not in text
    assert entry.detail["birthday"] == "1991-04-12"  # still in the audit log
