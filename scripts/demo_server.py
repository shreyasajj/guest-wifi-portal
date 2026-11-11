"""Run the portal against the test fakes (tests/fakes.py) with made-up demo data.

Used by scripts/screenshots.py; also handy for clicking around the UI locally:
    python scripts/demo_server.py /tmp/demo.db 8765   ->  http://127.0.0.1:8765/  and  /admin (admin / demo)
Nothing talks to a real OPNsense or Nextcloud. All names, numbers and addresses are invented.
"""
import asyncio
import os
import sys
from datetime import date, timedelta
from pathlib import Path

PORTAL = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PORTAL))
os.chdir(PORTAL)

import uvicorn  # noqa: E402
from argon2 import PasswordHasher  # noqa: E402
from sqlmodel import select  # noqa: E402

from app.config import Settings  # noqa: E402
from app.db import init_engine, session_scope  # noqa: E402
from app.events import audit  # noqa: E402
from app.main import create_app  # noqa: E402
from app.matching import Contact  # noqa: E402
from app.models import Device, DeviceType, Person, utcnow  # noqa: E402
from app.services import build_services  # noqa: E402
from app.workers import WorkerRunner, run_reconcile  # noqa: E402
from tests.fakes import BOOK, FakeCardDAV, FakeOPNsense  # noqa: E402

DB = sys.argv[1]
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8765
GUEST_MAC = "f2:6c:1a:9e:44:07"  # the browser's "device"

st = Settings(
    _env_file=None, site_name="HomeNet", secret_key="demo", database_url=f"sqlite:///{DB}",
    session_cookie_secure=False, workers_enabled=False,
    opnsense_url="https://opn.demo", opnsense_key="k", opnsense_secret="s", access_mode="both",
    guest_interfaces="vlan0.20", dhcp_backend="none",
    carddav_url=f"https://cloud.demo{BOOK}", carddav_user="me", carddav_password="pw",
    contact_min_refresh_seconds=0, phone_default_region="US",
    admin_allowed_networks="127.0.0.0/8", api_tokens="demo",
    admin_password_hash=PasswordHasher().hash("demo"), admin_username="admin",
)

opn, dav = FakeOPNsense(), FakeCardDAV()
people = {
    "maya": ("Maya Chen", ["+14155550134"], "1991-04-12", "maya@example.com"),
    "jordan": ("Jordan Patel", ["+14155550188"], "1988-11-02", "jordan@example.com"),
    "alex": ("Alex Kim", ["+14155550121"], "--0823", "alex@example.com"),
    "taylor": ("Taylor Brooks", ["+14155550162"], "1995-06-30", None),
    "priya": ("Priya Nair", ["+14155550199"], "1993-01-17", "priya@example.com"),
    "sam": ("Sam Rivera", ["+14155550147"], None, "sam@example.com"),
    "sam-work": ("Sam Rivera (work)", ["+14155550147"], None, "s.rivera@example.org"),
    "lena": ("Lena Okafor", ["+14155550175"], None, None),
}
for uid, (name, tels, bday, email) in people.items():
    dav.add(uid, name, tels, bday, email)


def contact(uid):
    name, tels, _, email = people[uid]
    return Contact(uid=uid, display_name=name, phones=tels, emails=[email] if email else [])


async def seed(svc):
    devices = [
        ("maya", "3a:1f:9c:22:7b:01", "10.0.20.41", DeviceType.phone, "Maya's iPhone", True),
        ("maya", "3a:1f:9c:22:7b:02", "10.0.20.42", DeviceType.computer, "Work laptop", True),
        ("jordan", "5e:88:04:c1:93:10", "10.0.20.57", DeviceType.phone, None, True),
        ("jordan", "5e:88:04:c1:93:11", "10.0.20.58", DeviceType.tablet, "iPad", False),
        ("alex", "be:12:7d:a0:66:31", "10.0.20.63", DeviceType.phone, "Pixel", False),
        ("priya", "c6:40:2e:91:0a:55", "10.0.20.70", DeviceType.phone, None, False),
    ]
    with session_scope() as s:
        for uid, mac, ip, dtype, nick, online in devices:
            await svc.devices.register(s, contact=contact(uid), mac=mac, ip=ip, device_type=dtype, nickname=nick,
                                       user_agent="Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X)")
            if online:
                opn.add_arp(ip, mac)
        await svc.devices.revoke_person(s, s.get(Person, "priya"), actor="admin")

    # Presence from the fake ARP table, then age the offline devices.
    runner = WorkerRunner(svc)
    await runner.presence_tick()
    now = utcnow()
    with session_scope() as s:
        for d in s.exec(select(Device)).all():
            d.first_seen = now - timedelta(days={"maya": 41, "jordan": 12, "alex": 63, "priya": 20}[d.person_uid])
            if not d.online:
                d.last_seen = now - timedelta(hours=26 if d.person_uid == "alex" else 3)
            s.add(d)
        s.commit()

    # Something allowed in OPNsense that the portal doesn't know about.
    opn.allowed.append("9a:0c:5f:e3:28:6d")
    opn.sessions.append({"sessionId": "SrQ1bz", "macAddress": "d4:3b:04:7e:19:a2", "ipAddress": "10.0.20.88",
                         "userName": "", "startTime": 1762800000})
    await run_reconcile(svc)

    # Pending approvals: one person in two contacts (picker), one in a single contact.
    with session_scope() as s:
        svc.approvals.request(s, contacts=[contact("sam"), contact("sam-work")], entered_birthday=date(1990, 2, 3),
                              ip="10.0.20.91", mac="7e:21:b0:5c:11:3f",
                              user_agent="Mozilla/5.0 (Linux; Android 16; Pixel 9)")
        for detail in ({"reason": "reject_birthday", "phone": "+14•••••0121"}, {"reason": "reject_no_phone", "phone": "+12•••••4410"}):
            audit(s, "login_attempt", actor="guest", target="aa:41:9d:02:6e:c8",
                  detail={"ip": "10.0.20.95", "mac": "aa:41:9d:02:6e:c8", **detail})
        s.commit()

    opn.add_arp("127.0.0.1", GUEST_MAC)


async def main():
    init_engine(st.database_url)
    svc = build_services(st, opn_transport=opn.transport(), carddav_transport=dav.transport())
    await seed(svc)
    app = create_app(st, svc)
    await uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=PORT, log_level="warning",
                                        proxy_headers=False)).serve()


asyncio.run(main())
