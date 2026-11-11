"""End-to-end HTTP flows through FastAPI with fake OPNsense and CardDAV."""
import ipaddress

from fastapi.testclient import TestClient
from sqlmodel import select

from app.models import ApprovalRequest, Device
from app.security import resolve_client_ip

from .conftest import ADMIN_IP, GUEST_IP, GUEST_MAC, PROXY_IP, csrf


def login(c, phone="(415) 555-0142", birthday="1991-04-12"):
    tok = csrf(c.get("/").text)
    return c.post("/login", data={"phone": phone, "birthday": birthday, "csrf_token": tok}, follow_redirects=False)


def test_success_flow_registers_phone(guest, dav, opn, session):
    dav.add("u1", "Maya Chen", ["+14155550142"], "1991-04-12")
    r = login(guest)
    assert r.status_code == 303 and r.headers["location"] == "/device"
    page = guest.get("/device")
    assert "What kind of device is this?" in page.text
    r = guest.post("/device", data={"device_type": "phone", "nickname": "Maya's iPhone", "csrf_token": csrf(page.text)})
    assert r.status_code == 200 and "All set!" in r.text
    assert opn.allowed == [GUEST_MAC]
    d = session.exec(select(Device)).one()
    assert d.type == "phone" and d.person_uid == "u1" and d.nickname == "Maya's iPhone"
    assert "Welcome back" in guest.get("/").text


def test_wrong_birthday_is_generic_and_never_creates_approval(guest, dav, session):
    dav.add("u1", "Maya", ["+14155550142"], "1991-04-12")
    dav.add("u2", "Maya old", ["+14155550142"])  # no BDAY: must not open the approval path
    r = login(guest, birthday="1990-01-01")
    assert r.status_code == 401 and "verify those details" in r.text
    assert session.exec(select(ApprovalRequest)).all() == []
    r2 = login(guest, phone="415 555 9999")
    assert r2.status_code == 401 and "verify those details" in r2.text


def test_unknown_mac_is_rejected(app, dav):
    with TestClient(app, client=("10.0.20.99", 1)) as c:
        r = login(c)
    assert r.status_code == 400 and "identify your device" in r.text


def test_csrf_required(guest):
    r = guest.post("/login", data={"phone": "1", "birthday": "1991-04-12"})
    assert r.status_code == 403


def test_rate_limit_kicks_in(guest, dav):
    dav.add("u1", "Maya", ["+14155550142"], "1991-04-12")
    for _ in range(5):
        assert login(guest, birthday="2000-01-01").status_code == 401
    r = login(guest)  # even correct details are refused while locked
    assert r.status_code == 429 and "Too many attempts" in r.text


def test_approval_flow_via_api(guest, ha, dav, opn):
    dav.add("u1", "Sam Rivera", ["+14155550142"])
    r = login(guest)
    assert r.headers["location"] == "/waiting"
    assert "Waiting for approval" in guest.get("/waiting").text
    assert guest.get("/waiting/status").json() == {"state": "pending"}

    pending = ha.get("/api/approvals").json()
    assert len(pending) == 1 and pending[0]["contact_name"] == "Sam Rivera"
    rid = pending[0]["request_id"]
    res = ha.post(f"/api/approvals/{rid}/approve", json={"save_birthday": True})
    assert res.status_code == 200 and res.json()["birthday_saved"] is True
    assert res.json()["decided_by"] == "home_assistant"
    assert "BDAY:1991-04-12" in dav.text("u1")
    assert ha.post(f"/api/approvals/{rid}/deny").status_code == 409  # first decision wins

    assert guest.get("/waiting/status").json() == {"state": "approved", "next": "/device"}
    page = guest.get("/device")
    r = guest.post("/device", data={"device_type": "other", "csrf_token": csrf(page.text)})
    assert "All set!" in r.text and opn.allowed == [GUEST_MAC]


def test_denied_then_cooldown_message(guest, ha, dav):
    dav.add("u1", "Sam", ["+14155550142"])
    login(guest)
    rid = ha.get("/api/approvals").json()[0]["request_id"]
    ha.post(f"/api/approvals/{rid}/deny")
    assert guest.get("/waiting/status").json()["state"] == "failed"
    assert "connect, try again later." in guest.get("/failed").text
    r = login(guest)
    assert r.status_code == 429 and "Please wait a few seconds and try again" in r.text
    assert 'data-countdown="' in r.text


def test_repeat_submission_reuses_pending_request(guest, ha, dav, session):
    dav.add("u1", "Sam", ["+14155550142"])
    login(guest)
    login(guest)
    assert len(session.exec(select(ApprovalRequest)).all()) == 1


def test_one_phone_rule_over_http(app, dav, opn, session):
    dav.add("u1", "Maya", ["+14155550142"], "1991-04-12")
    opn.add_arp("10.0.20.60", "aa:bb:cc:00:00:60")
    opn.add_arp("10.0.20.61", "aa:bb:cc:00:00:61")
    for ip in ("10.0.20.60", "10.0.20.61"):
        with TestClient(app, client=(ip, 1)) as c:
            login(c)
            page = c.get("/device")
            r = c.post("/device", data={"device_type": "phone", "csrf_token": csrf(page.text)})
            assert "All set!" in r.text  # no prompt: the newest phone takes over tracking
    types = {d.mac: d.type for d in session.exec(select(Device)).all()}
    assert types == {"aa:bb:cc:00:00:60": "other", "aa:bb:cc:00:00:61": "phone"}
    assert sorted(opn.allowed) == ["aa:bb:cc:00:00:60", "aa:bb:cc:00:00:61"]  # old phone keeps access


def test_device_page_offers_only_phone_or_other(guest, dav):
    dav.add("u1", "Maya", ["+14155550142"], "1991-04-12")
    login(guest)
    page = guest.get("/device").text
    assert 'value="phone"' in page and 'value="other"' in page
    assert 'value="computer"' not in page and 'value="tablet"' not in page


def test_api_auth_and_network_restriction(app):
    with TestClient(app, client=(ADMIN_IP, 1)) as c:
        assert c.get("/api/status").status_code == 401
        assert c.get("/api/status", headers={"Authorization": "Bearer nope"}).status_code == 401
    with TestClient(app, client=(GUEST_IP, 1)) as c:
        assert c.get("/api/status", headers={"Authorization": "Bearer test-token"}).status_code == 404
        assert c.get("/admin").status_code == 404


def test_admin_requires_login(app):
    with TestClient(app, client=(ADMIN_IP, 1)) as c:
        r = c.get("/admin", follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"] == "/admin/login"


def test_trusted_proxy_xff(app, opn, dav):
    trusted = [ipaddress.ip_network(PROXY_IP + "/32")]
    assert resolve_client_ip(PROXY_IP, "10.0.20.50", trusted) == "10.0.20.50"
    assert resolve_client_ip(PROXY_IP, "1.2.3.4, 10.0.20.50", trusted) == "10.0.20.50"  # spoofed left entry ignored
    assert resolve_client_ip("10.0.20.77", "192.168.1.10", trusted) == "10.0.20.77"  # untrusted peer: header ignored
    # A guest can't reach admin by spoofing X-Forwarded-For directly.
    with TestClient(app, client=(GUEST_IP, 1)) as c:
        assert c.get("/admin/login", headers={"X-Forwarded-For": ADMIN_IP}).status_code == 404
    # Through the proxy, the guest IP is used for the MAC lookup.
    dav.add("u1", "Maya", ["+14155550142"], "1991-04-12")
    opn.add_arp(GUEST_IP, GUEST_MAC)
    with TestClient(app, client=(PROXY_IP, 1), headers={"X-Forwarded-For": GUEST_IP}) as c:
        assert login(c).headers["location"] == "/device"


def test_sse_replays_events_after_last_event_id(guest, ha, dav):
    dav.add("u1", "Sam", ["+14155550142"])
    login(guest)
    with ha.stream("GET", "/api/events", headers={"Last-Event-ID": "0"}) as r:
        assert r.headers["content-type"].startswith("text/event-stream")
        buf = ""
        for chunk in r.iter_text():
            buf += chunk
            if "approval_requested" in buf:
                break
    assert "event: approval_requested" in buf


def test_captive_portal_api(guest, dav):
    r = guest.get("/captive-portal")
    assert r.headers["content-type"].startswith("application/captive+json")
    assert r.json()["captive"] is True and r.json()["user-portal-url"].endswith("/")
    dav.add("u1", "Maya", ["+14155550142"], "1991-04-12")
    login(guest)
    page = guest.get("/device")
    guest.post("/device", data={"device_type": "phone", "csrf_token": csrf(page.text)})
    assert guest.get("/captive-portal").json()["captive"] is False
