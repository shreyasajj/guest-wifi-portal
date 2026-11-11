from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.db import init_engine, session_scope
from app.main import create_app
from app.services import build_services

from .fakes import BOOK, FakeCardDAV, FakeOPNsense

GUEST_IP = "10.0.20.50"
GUEST_MAC = "aa:bb:cc:00:00:01"
ADMIN_IP = "192.168.1.10"
PROXY_IP = "10.0.0.2"
TOKEN = "test-token"


@pytest.fixture
def settings(tmp_path) -> Settings:
    return Settings(
        _env_file=None,
        secret_key="test",
        database_url=f"sqlite:///{tmp_path / 'test.db'}",
        session_cookie_secure=False,
        workers_enabled=False,
        opnsense_url="https://opn.test",
        opnsense_key="k",
        opnsense_secret="s",
        access_mode="zone",
        guest_interfaces="vlan0.20",
        carddav_url=f"https://cloud.test{BOOK}",
        carddav_user="me",
        carddav_password="pw",
        contact_min_refresh_seconds=0,
        phone_default_region="US",
        trusted_proxies=PROXY_IP + "/32",
        admin_allowed_networks="192.168.1.0/24",
        api_tokens=TOKEN,
        admin_password_hash="",
    )


@pytest.fixture
def opn() -> FakeOPNsense:
    return FakeOPNsense()


@pytest.fixture
def dav() -> FakeCardDAV:
    return FakeCardDAV()


@pytest.fixture
def services(settings, opn, dav):
    init_engine(settings.database_url)
    return build_services(settings, opn_transport=opn.transport(), carddav_transport=dav.transport())


@pytest.fixture
def session(services):
    with session_scope() as s:
        yield s


@pytest.fixture
def app(settings, services):
    return create_app(settings, services)


@pytest.fixture
def guest(app, opn):
    opn.add_arp(GUEST_IP, GUEST_MAC)
    with TestClient(app, client=(GUEST_IP, 50000)) as c:
        yield c


@pytest.fixture
def ha(app):
    with TestClient(app, client=(ADMIN_IP, 50001), headers={"Authorization": f"Bearer {TOKEN}"}) as c:
        yield c


def csrf(html: str) -> str:
    return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)
