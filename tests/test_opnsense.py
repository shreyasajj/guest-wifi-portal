import json
import time

import httpx
import pytest
import respx

from app.opnsense import AccessController, OPNsenseClient, OPNsenseError, _camel_action, parse_list_field

from .fakes import ALIAS_UUID, ZONE_UUID, FakeOPNsense

BASE = "https://opn.test/api"


def make(fake: FakeOPNsense | None = None, **kw) -> OPNsenseClient:
    return OPNsenseClient("https://opn.test", "key", "secret", zone_id=0,
                          transport=fake.transport() if fake else None, **kw)


def test_parse_list_field_variants():
    assert parse_list_field({"aa:bb": {"value": "aa:bb", "selected": 1}, "cc": {"value": "cc", "selected": 0}}) == ["aa:bb"]
    assert parse_list_field("a,b\nc") == ["a", "b", "c"]
    assert parse_list_field({"": {"value": "", "selected": 1}}) == []
    assert parse_list_field(None) == []


@respx.mock
async def test_add_allowed_mac_exact_calls():
    respx.get(f"{BASE}/captiveportal/settings/search_zones").respond(json={"rows": [{"uuid": ZONE_UUID, "zoneid": "0"}]})
    respx.get(f"{BASE}/captiveportal/settings/get_zone/{ZONE_UUID}").respond(
        json={"zone": {"allowedMACAddresses": {"11:22:33:44:55:66": {"value": "11:22:33:44:55:66", "selected": 1}}}})
    set_route = respx.post(f"{BASE}/captiveportal/settings/set_zone/{ZONE_UUID}").respond(json={"result": "saved"})
    reconf = respx.post(f"{BASE}/captiveportal/service/reconfigure").respond(json={"status": "ok"})

    client = make()
    assert await client.add_allowed_macs("AA-BB-CC-DD-EE-FF") is True
    sent = json.loads(set_route.calls.last.request.content)
    assert sent == {"zone": {"allowedMACAddresses": "11:22:33:44:55:66,aa:bb:cc:dd:ee:ff"}}
    assert reconf.called
    auth = set_route.calls.last.request.headers["authorization"]
    assert auth.startswith("Basic ")


@respx.mock
async def test_add_existing_mac_is_noop():
    respx.get(f"{BASE}/captiveportal/settings/search_zones").respond(json={"rows": [{"uuid": ZONE_UUID, "zoneid": "0"}]})
    respx.get(f"{BASE}/captiveportal/settings/get_zone/{ZONE_UUID}").respond(
        json={"zone": {"allowedMACAddresses": "aa:bb:cc:dd:ee:ff"}})
    set_route = respx.post(f"{BASE}/captiveportal/settings/set_zone/{ZONE_UUID}")
    assert await make().add_allowed_macs("aa:bb:cc:dd:ee:ff") is False
    assert not set_route.called


@respx.mock
async def test_zone_not_found():
    respx.get(f"{BASE}/captiveportal/settings/search_zones").respond(json={"rows": [{"uuid": "x", "zoneid": "3"}]})
    with pytest.raises(OPNsenseError, match="zone 0 not found"):
        await make().get_allowed_macs()


@respx.mock
async def test_http_error_and_failed_save_raise():
    respx.get(f"{BASE}/diagnostics/interface/get_arp").respond(500, text="err")
    with pytest.raises(OPNsenseError, match="HTTP 500"):
        await make().get_arp()

    respx.get(f"{BASE}/captiveportal/settings/search_zones").respond(json={"rows": [{"uuid": ZONE_UUID, "zoneid": "0"}]})
    respx.get(f"{BASE}/captiveportal/settings/get_zone/{ZONE_UUID}").respond(json={"zone": {"allowedMACAddresses": ""}})
    respx.post(f"{BASE}/captiveportal/settings/set_zone/{ZONE_UUID}").respond(
        json={"result": "failed", "validations": {"zone.allowedMACAddresses": "invalid"}})
    with pytest.raises(OPNsenseError, match="setZone failed"):
        await make().add_allowed_macs("aa:bb:cc:dd:ee:ff")


def test_camel_action_maps_to_pre_25_7_names():
    assert _camel_action("diagnostics/interface/get_arp") == "diagnostics/interface/getArp"
    assert _camel_action("captiveportal/settings/search_zones") == "captiveportal/settings/searchZones"
    assert _camel_action("firewall/alias/get_alias_uuid/GUEST") == "firewall/alias/getAliasUUID/GUEST"
    assert _camel_action("captiveportal/session/list/0") == "captiveportal/session/list/0"


ARP_ROW = {"mac": "aa:bb:cc:dd:ee:01", "ip": "10.0.20.5", "intf": "vlan0.20", "expired": False}


@respx.mock
async def test_snake_case_arp_works_on_current_opnsense():
    snake = respx.get(f"{BASE}/diagnostics/interface/get_arp").respond(json=[ARP_ROW])
    camel = respx.get(f"{BASE}/diagnostics/interface/getArp")
    assert [e.mac for e in await make().get_arp()] == ["aa:bb:cc:dd:ee:01"]
    assert snake.called and not camel.called


@respx.mock
async def test_403_retries_with_camel_case_for_older_opnsense():
    # Before 25.7 the ACL pattern was "getArp*", so the snake_case URL is refused.
    respx.get(f"{BASE}/diagnostics/interface/get_arp").respond(403, json={"status": 403, "message": "Forbidden"})
    camel = respx.get(f"{BASE}/diagnostics/interface/getArp").respond(json=[ARP_ROW])
    assert [e.mac for e in await make().get_arp()] == ["aa:bb:cc:dd:ee:01"]
    assert camel.called


@respx.mock
async def test_403_on_both_spellings_reports_original_path():
    respx.get(f"{BASE}/diagnostics/interface/get_arp").respond(403, json={"status": 403, "message": "Forbidden"})
    respx.get(f"{BASE}/diagnostics/interface/getArp").respond(403, json={"status": 403, "message": "Forbidden"})
    with pytest.raises(OPNsenseError, match="get_arp: HTTP 403"):
        await make().get_arp()


@respx.mock
async def test_connection_error_wrapped():
    respx.get(f"{BASE}/diagnostics/interface/get_arp").mock(side_effect=httpx.ConnectError("refused"))
    with pytest.raises(OPNsenseError):
        await make().get_arp()


async def test_remove_and_concurrent_adds_do_not_lose_updates():
    import asyncio

    fake = FakeOPNsense()
    fake.allowed = ["00:00:00:00:00:01"]
    c = make(fake)
    await asyncio.gather(*(c.add_allowed_macs(f"00:00:00:00:00:{i:02x}") for i in range(2, 8)))
    assert len(fake.allowed) == 7
    assert await c.remove_allowed_macs("00:00:00:00:00:01") is True
    assert "00:00:00:00:00:01" not in fake.allowed
    assert await c.remove_allowed_macs("00:00:00:00:00:01") is False


async def test_sessions_and_disconnect_by_mac():
    fake = FakeOPNsense()
    fake.sessions = [
        {"sessionId": "s1", "macAddress": "AA:BB:CC:DD:EE:FF", "ipAddress": "10.0.20.5", "userName": "x"},
        {"sessionId": "s2", "macAddress": "11:22:33:44:55:66", "ipAddress": "10.0.20.6", "userName": "y"},
    ]
    c = make(fake)
    sessions = await c.list_sessions()
    assert [s.mac for s in sessions] == ["aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"]
    assert await c.disconnect_mac("aa:bb:cc:dd:ee:ff") == 1
    assert ("POST", "captiveportal/session/disconnect/0", {"sessionId": "s1"}) in fake.calls
    assert [s["sessionId"] for s in fake.sessions] == ["s2"]


async def test_arp_filtering_and_mac_lookup():
    fake = FakeOPNsense()
    fake.add_arp("10.0.20.5", "AA:BB:CC:DD:EE:01")
    fake.add_arp("10.0.20.6", "aa:bb:cc:dd:ee:02", expired=True)
    fake.add_arp("192.168.1.5", "aa:bb:cc:dd:ee:03", intf="igb0")
    c = make(fake)
    entries = await c.get_arp(["vlan0.20"])
    assert {e.mac for e in entries} == {"aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"}
    assert await c.mac_for_ip("10.0.20.5", ["vlan0.20"]) == "aa:bb:cc:dd:ee:01"
    assert await c.mac_for_ip("10.0.20.6", ["vlan0.20"]) is None  # expired
    assert await c.mac_for_ip("192.168.1.5", ["vlan0.20"]) is None  # wrong interface


async def test_leases_all_backends():
    now = int(time.time())
    fake = FakeOPNsense()
    fake.leases["kea"] = [
        {"address": "10.0.20.5", "hwaddr": "aa:bb:cc:dd:ee:01", "valid_lifetime": 3600, "expire": now + 3500,
         "state": 0, "if": "vlan0.20", "if_name": "opt2", "hostname": "maya-iphone"},
        {"address": "10.0.20.9", "hwaddr": "aa:bb:cc:dd:ee:09", "valid_lifetime": 3600, "expire": now - 10,
         "state": 0, "if": "vlan0.20"},
    ]
    fake.leases["dnsmasq"] = [{"address": "10.0.20.6", "hwaddr": "aa:bb:cc:dd:ee:02", "expire": now + 100, "if": "vlan0.20"}]
    fake.leases["isc"] = [{"address": "10.0.20.7", "mac": "aa:bb:cc:dd:ee:03", "starts": "2024/05/01 12:00:00 UTC",
                           "ends": "2099/05/01 12:00:00 UTC", "state": "active", "if": "opt2"}]
    c = make(fake)
    kea = await c.get_leases("kea", ["vlan0.20"])
    assert kea[0].active and kea[0].starts == pytest.approx(now - 100, abs=2) and kea[0].hostname == "maya-iphone"
    assert kea[1].active is False  # already expired
    dns = await c.get_leases("dnsmasq")
    assert dns[0].mac == "aa:bb:cc:dd:ee:02" and dns[0].starts is None
    isc = await c.get_leases("isc", ["opt2"])
    assert isc[0].active and isc[0].starts is not None
    assert await c.get_leases("none") == []


async def test_alias_mode_add_remove():
    fake = FakeOPNsense()
    fake.alias = ["11:22:33:44:55:66"]
    c = make(fake)
    access = AccessController(c, use_zone=False, use_alias=True)
    await access.allow("aa:bb:cc:dd:ee:ff")
    assert fake.alias == ["11:22:33:44:55:66", "aa:bb:cc:dd:ee:ff"]
    assert ("POST", f"firewall/alias/set_item/{ALIAS_UUID}",
            {"alias": {"content": "11:22:33:44:55:66\naa:bb:cc:dd:ee:ff"}}) in fake.calls
    assert ("POST", "firewall/alias/reconfigure", {}) in fake.calls
    await access.remove("11:22:33:44:55:66")
    assert fake.alias == ["aa:bb:cc:dd:ee:ff"]
    assert not any(p.startswith("captiveportal") for _, p, _ in fake.calls)


async def test_alias_missing_raises():
    c = make(FakeOPNsense(), alias_name="NOPE")
    with pytest.raises(OPNsenseError, match="alias NOPE not found"):
        await c.get_alias_macs()


async def test_both_mode_writes_both():
    fake = FakeOPNsense()
    access = AccessController(make(fake), use_zone=True, use_alias=True)
    await access.allow("aa:bb:cc:dd:ee:ff")
    assert fake.allowed == ["aa:bb:cc:dd:ee:ff"] and fake.alias == ["aa:bb:cc:dd:ee:ff"]
    assert await access.allowed() == {"zone": {"aa:bb:cc:dd:ee:ff"}, "alias": {"aa:bb:cc:dd:ee:ff"}}
