"""Single wrapper around every OPNsense REST call the portal makes.

Endpoints were checked against opnsense/core (master) and opnsense/plugins (net/isc-dhcp):

  Captive portal
    GET  /api/captiveportal/settings/searchZones           list zones (uuid <-> zoneid)
    GET  /api/captiveportal/settings/getZone/{uuid}        read zone, incl. allowedMACAddresses
    POST /api/captiveportal/settings/setZone/{uuid}        write allowedMACAddresses (comma list)
    POST /api/captiveportal/service/reconfigure            apply zone changes
    GET  /api/captiveportal/session/list/{zoneid}          active sessions
    POST /api/captiveportal/session/disconnect/{zoneid}    body: sessionId
  Diagnostics
    GET  /api/diagnostics/interface/getArp                 ARP table
  DHCP leases (one of)
    GET  /api/kea/leases4/search                           Kea DHCPv4
    GET  /api/dnsmasq/leases/search                        Dnsmasq
    GET  /api/dhcpv4/leases/searchLease                    ISC DHCPv4 (os-isc-dhcp plugin)
  Firewall alias (ACCESS_MODE=alias|both)
    GET  /api/firewall/alias/getAliasUUID/{name}
    GET  /api/firewall/alias/getItem/{uuid}
    POST /api/firewall/alias/setItem/{uuid}                body: alias.content (newline list)
    POST /api/firewall/alias/reconfigure
"""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from typing import Any, Iterable

import httpx

from .macs import normalize_mac

log = logging.getLogger(__name__)


class OPNsenseError(Exception):
    pass


@dataclass
class ArpEntry:
    mac: str
    ip: str
    intf: str
    expired: bool
    hostname: str = ""
    manufacturer: str = ""


@dataclass
class Lease:
    mac: str
    ip: str
    interface: str
    active: bool
    starts: float | None  # epoch seconds, when known
    ends: float | None
    hostname: str = ""


@dataclass
class CPSession:
    session_id: str
    mac: str | None
    ip: str
    username: str
    raw: dict


def parse_list_field(value: Any) -> list[str]:
    """OPNsense returns AsList fields as {"v": {"value": "v", "selected": 1}} on get, but accept strings too."""
    if value is None:
        return []
    if isinstance(value, str):
        parts = value.replace("\n", ",").split(",")
    elif isinstance(value, dict):
        parts = [k for k, v in value.items() if not isinstance(v, dict) or v.get("selected", 1)]
    elif isinstance(value, list):
        parts = [str(v) for v in value]
    else:
        parts = []
    return [p.strip() for p in parts if p and p.strip()]


def _epoch(value: Any) -> float | None:
    if value in (None, "", 0, "0"):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    s = str(value).strip()
    if s.isdigit():
        return float(s)
    # ISC: "2024/05/01 12:00:00 UTC" style; Kea/dnsmasq give epoch ints
    for fmt in ("%Y/%m/%d %H:%M:%S UTC", "%Y/%m/%d %H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            import calendar

            return float(calendar.timegm(time.strptime(s, fmt)))
        except ValueError:
            continue
    return None


class OPNsenseClient:
    def __init__(
        self,
        base_url: str,
        key: str,
        secret: str,
        *,
        verify: bool | str = True,
        zone_id: int = 0,
        alias_name: str = "GUEST_AUTH_MACS",
        timeout: float = 10.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ):
        self.zone_id = zone_id
        self.alias_name = alias_name
        self._http = httpx.AsyncClient(
            base_url=base_url.rstrip("/") + "/api/",
            auth=(key, secret),
            verify=verify,
            timeout=timeout,
            transport=transport,
            headers={"Accept": "application/json"},
        )
        self._zone_uuid: str | None = None
        self._alias_uuid: str | None = None
        self._zone_lock = asyncio.Lock()
        self._alias_lock = asyncio.Lock()

    async def aclose(self) -> None:
        await self._http.aclose()

    # ------------------------------------------------------------------ http
    async def _request(self, method: str, path: str, **kw) -> Any:
        try:
            resp = await self._http.request(method, path.lstrip("/"), **kw)
        except httpx.HTTPError as exc:
            raise OPNsenseError(f"{method} {path}: {exc}") from exc
        if resp.status_code >= 400:
            raise OPNsenseError(f"{method} {path}: HTTP {resp.status_code} {resp.text[:200]}")
        try:
            return resp.json()
        except ValueError as exc:
            raise OPNsenseError(f"{method} {path}: invalid JSON") from exc

    async def _get(self, path: str, **params) -> Any:
        return await self._request("GET", path, params=params or None)

    async def _post(self, path: str, body: dict | None = None) -> Any:
        return await self._request("POST", path, json=body if body is not None else {})

    # --------------------------------------------------------- captive portal
    async def zone_uuid(self) -> str:
        if self._zone_uuid:
            return self._zone_uuid
        data = await self._get("captiveportal/settings/searchZones", rowCount=-1)
        for row in data.get("rows", []):
            if str(row.get("zoneid")) == str(self.zone_id):
                self._zone_uuid = row["uuid"]
                return self._zone_uuid
        raise OPNsenseError(f"captive portal zone {self.zone_id} not found")

    async def get_allowed_macs(self) -> set[str]:
        uuid = await self.zone_uuid()
        data = await self._get(f"captiveportal/settings/getZone/{uuid}")
        zone = data.get("zone", {})
        return {m for m in (normalize_mac(x) for x in parse_list_field(zone.get("allowedMACAddresses"))) if m}

    async def _write_allowed_macs(self, macs: Iterable[str]) -> None:
        uuid = await self.zone_uuid()
        body = {"zone": {"allowedMACAddresses": ",".join(sorted(macs))}}
        res = await self._post(f"captiveportal/settings/setZone/{uuid}", body)
        if res.get("result") != "saved":
            raise OPNsenseError(f"setZone failed: {res}")
        await self.reconfigure_captiveportal()

    async def add_allowed_macs(self, *macs: str) -> bool:
        wanted = {m for m in (normalize_mac(x) for x in macs) if m}
        async with self._zone_lock:
            current = await self.get_allowed_macs()
            if wanted <= current:
                return False
            await self._write_allowed_macs(current | wanted)
            return True

    async def remove_allowed_macs(self, *macs: str) -> bool:
        drop = {m for m in (normalize_mac(x) for x in macs) if m}
        async with self._zone_lock:
            current = await self.get_allowed_macs()
            if not (current & drop):
                return False
            await self._write_allowed_macs(current - drop)
            return True

    async def reconfigure_captiveportal(self) -> None:
        res = await self._post("captiveportal/service/reconfigure")
        if str(res.get("status", "")).lower() not in ("ok", ""):
            raise OPNsenseError(f"captiveportal reconfigure failed: {res}")

    async def list_sessions(self) -> list[CPSession]:
        data = await self._get(f"captiveportal/session/list/{self.zone_id}")
        rows = data if isinstance(data, list) else list((data or {}).values()) if isinstance(data, dict) else []
        out = []
        for r in rows:
            if not isinstance(r, dict) or not r.get("sessionId"):
                continue
            out.append(
                CPSession(
                    session_id=r["sessionId"],
                    mac=normalize_mac(r.get("macAddress")),
                    ip=r.get("ipAddress", ""),
                    username=r.get("userName", ""),
                    raw=r,
                )
            )
        return out

    async def disconnect_session(self, session_id: str) -> None:
        await self._post(f"captiveportal/session/disconnect/{self.zone_id}", {"sessionId": session_id})

    async def disconnect_mac(self, mac: str) -> int:
        mac = normalize_mac(mac)
        count = 0
        for s in await self.list_sessions():
            if s.mac == mac:
                await self.disconnect_session(s.session_id)
                count += 1
        return count

    # ------------------------------------------------------------------- ARP
    async def get_arp(self, interfaces: list[str] | None = None) -> list[ArpEntry]:
        data = await self._get("diagnostics/interface/getArp")
        rows = data if isinstance(data, list) else data.get("rows", []) if isinstance(data, dict) else []
        out = []
        for r in rows:
            mac = normalize_mac(r.get("mac"))
            if not mac or not r.get("ip"):
                continue
            intf = str(r.get("intf", ""))
            if interfaces and intf.lower() not in interfaces and str(r.get("intf_description", "")).lower() not in interfaces:
                continue
            out.append(
                ArpEntry(
                    mac=mac,
                    ip=r["ip"],
                    intf=intf,
                    expired=bool(r.get("expired")),
                    hostname=r.get("hostname") or "",
                    manufacturer=r.get("manufacturer") or "",
                )
            )
        return out

    async def mac_for_ip(self, ip: str, interfaces: list[str] | None = None) -> str | None:
        for e in await self.get_arp(interfaces):
            if e.ip == ip and not e.expired:
                return e.mac
        return None

    # ---------------------------------------------------------------- leases
    async def get_leases(self, backend: str, interfaces: list[str] | None = None) -> list[Lease]:
        if backend == "none":
            return []
        if backend == "kea":
            data = await self._get("kea/leases4/search", rowCount=-1, current=1)
        elif backend == "dnsmasq":
            data = await self._get("dnsmasq/leases/search", rowCount=-1, current=1)
        elif backend == "isc":
            data = await self._get("dhcpv4/leases/searchLease", rowCount=-1, current=1)
        else:
            raise ValueError(f"unknown DHCP backend {backend}")
        now = time.time()
        out = []
        for r in data.get("rows", []):
            mac = normalize_mac(r.get("hwaddr") or r.get("mac"))
            ip = r.get("address")
            if not mac or not ip:
                continue
            iface_names = {str(r.get(k, "")).lower() for k in ("if", "if_name", "if_descr", "interface")} - {""}
            if interfaces and not (iface_names & set(interfaces)):
                continue
            ends = _epoch(r.get("expire") or r.get("ends"))
            starts = _epoch(r.get("starts") or r.get("cltt"))
            if starts is None and ends is not None and r.get("valid_lifetime"):
                starts = ends - float(r["valid_lifetime"])
            if backend == "kea":
                active = str(r.get("state", "0")) == "0"
            elif backend == "isc":
                active = str(r.get("state", "")).lower() == "active"
            else:
                active = True
            if ends is not None and ends < now:
                active = False
            out.append(
                Lease(mac=mac, ip=ip, interface=next(iter(iface_names), ""), active=active,
                      starts=starts, ends=ends, hostname=r.get("hostname") or "")
            )
        return out

    # ----------------------------------------------------------------- alias
    async def alias_uuid(self) -> str:
        if self._alias_uuid:
            return self._alias_uuid
        data = await self._get(f"firewall/alias/getAliasUUID/{self.alias_name}")
        uuid = data.get("uuid") if isinstance(data, dict) else None
        if not uuid:
            raise OPNsenseError(f"alias {self.alias_name} not found")
        self._alias_uuid = uuid
        return uuid

    async def get_alias_macs(self) -> set[str]:
        uuid = await self.alias_uuid()
        data = await self._get(f"firewall/alias/getItem/{uuid}")
        content = data.get("alias", {}).get("content")
        return {m for m in (normalize_mac(x) for x in parse_list_field(content)) if m}

    async def _write_alias_macs(self, macs: Iterable[str]) -> None:
        uuid = await self.alias_uuid()
        res = await self._post(f"firewall/alias/setItem/{uuid}", {"alias": {"content": "\n".join(sorted(macs))}})
        if res.get("result") != "saved":
            raise OPNsenseError(f"alias setItem failed: {res}")
        await self._post("firewall/alias/reconfigure")

    async def add_alias_macs(self, *macs: str) -> bool:
        wanted = {m for m in (normalize_mac(x) for x in macs) if m}
        async with self._alias_lock:
            current = await self.get_alias_macs()
            if wanted <= current:
                return False
            await self._write_alias_macs(current | wanted)
            return True

    async def remove_alias_macs(self, *macs: str) -> bool:
        drop = {m for m in (normalize_mac(x) for x in macs) if m}
        async with self._alias_lock:
            current = await self.get_alias_macs()
            if not (current & drop):
                return False
            await self._write_alias_macs(current - drop)
            return True


class AccessController:
    """Grants or removes access according to ACCESS_MODE (zone, alias or both)."""

    def __init__(self, client: OPNsenseClient, *, use_zone: bool, use_alias: bool):
        self.client = client
        self.use_zone = use_zone
        self.use_alias = use_alias

    async def allow(self, *macs: str) -> None:
        if self.use_zone:
            await self.client.add_allowed_macs(*macs)
        if self.use_alias:
            await self.client.add_alias_macs(*macs)

    async def remove(self, *macs: str) -> None:
        if self.use_zone:
            await self.client.remove_allowed_macs(*macs)
        if self.use_alias:
            await self.client.remove_alias_macs(*macs)
        if self.use_zone:
            for mac in macs:
                await self.client.disconnect_mac(mac)

    async def allowed(self) -> dict[str, set[str]]:
        """MACs currently granted, keyed by source ('zone', 'alias')."""
        out: dict[str, set[str]] = {}
        if self.use_zone:
            out["zone"] = await self.client.get_allowed_macs()
        if self.use_alias:
            out["alias"] = await self.client.get_alias_macs()
        return out

    async def sessions(self) -> list[CPSession]:
        return await self.client.list_sessions() if self.use_zone else []
