"""Stateful fakes for OPNsense and Nextcloud CardDAV, served through httpx.MockTransport."""
from __future__ import annotations

import json
from urllib.parse import unquote, urlparse

import httpx

ZONE_UUID = "11111111-2222-3333-4444-555555555555"
ALIAS_UUID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


class FakeOPNsense:
    def __init__(self):
        self.allowed: list[str] = []
        self.alias: list[str] = []
        self.sessions: list[dict] = []
        self.arp: list[dict] = []
        self.leases: dict[str, list[dict]] = {"kea": [], "dnsmasq": [], "isc": []}
        self.calls: list[tuple[str, str, dict | None]] = []
        self.reconfigures = 0
        self.fail_next: int | None = None

    def add_arp(self, ip: str, mac: str, intf: str = "vlan0.20", expired: bool = False):
        self.arp.append({"mac": mac, "ip": ip, "intf": intf, "expired": expired, "expires": 1200,
                         "permanent": False, "type": "ethernet", "manufacturer": "", "hostname": ""})

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handle)

    def handle(self, request: httpx.Request) -> httpx.Response:
        path = urlparse(str(request.url)).path.removeprefix("/api/")
        body = json.loads(request.content) if request.content else None
        self.calls.append((request.method, path, body))
        if self.fail_next:
            code, self.fail_next = self.fail_next, None
            return httpx.Response(code, text="boom")

        if path == "captiveportal/settings/search_zones":
            return httpx.Response(200, json={"rows": [{"uuid": ZONE_UUID, "zoneid": "0", "enabled": "1",
                                                       "description": "Guest"}], "total": 1})
        if path == f"captiveportal/settings/get_zone/{ZONE_UUID}":
            return httpx.Response(200, json={"zone": {"enabled": "1", "allowedMACAddresses": {
                m: {"value": m, "selected": 1} for m in self.allowed} if self.allowed else {"": {"value": "", "selected": 1}}}})
        if path == f"captiveportal/settings/set_zone/{ZONE_UUID}":
            raw = body["zone"]["allowedMACAddresses"]
            self.allowed = [m for m in raw.split(",") if m]
            return httpx.Response(200, json={"result": "saved"})
        if path == "captiveportal/service/reconfigure":
            self.reconfigures += 1
            return httpx.Response(200, json={"status": "ok"})
        if path == "captiveportal/session/list/0":
            return httpx.Response(200, json=self.sessions)
        if path == "captiveportal/session/disconnect/0":
            sid = body["sessionId"]
            self.sessions = [s for s in self.sessions if s["sessionId"] != sid]
            return httpx.Response(200, json={"terminateCause": "Admin-Reset"})
        if path == "diagnostics/interface/get_arp":
            return httpx.Response(200, json=self.arp)
        if path == "kea/leases4/search":
            return httpx.Response(200, json={"rows": self.leases["kea"], "total": len(self.leases["kea"])})
        if path == "dnsmasq/leases/search":
            return httpx.Response(200, json={"rows": self.leases["dnsmasq"]})
        if path == "dhcpv4/leases/search_lease":
            return httpx.Response(200, json={"rows": self.leases["isc"]})
        if path.startswith("firewall/alias/get_alias_uuid/"):
            return httpx.Response(200, json={"uuid": ALIAS_UUID} if path.endswith("GUEST_AUTH_MACS") else [])
        if path == f"firewall/alias/get_item/{ALIAS_UUID}":
            return httpx.Response(200, json={"alias": {"name": "GUEST_AUTH_MACS", "type": {"mac": {"selected": 1}},
                                                       "content": {m: {"value": m, "selected": 1} for m in self.alias}}})
        if path == f"firewall/alias/set_item/{ALIAS_UUID}":
            self.alias = [m for m in body["alias"]["content"].split("\n") if m]
            return httpx.Response(200, json={"result": "saved"})
        if path == "firewall/alias/reconfigure":
            return httpx.Response(200, json={"status": "ok"})
        return httpx.Response(404, json={"errorMessage": "Endpoint not found"})


def vcard(uid: str, name: str, tels: list[str], bday: str | None = None, email: str | None = None) -> str:
    lines = ["BEGIN:VCARD", "VERSION:3.0", f"UID:{uid}", f"FN:{name}", f"N:{name.split()[-1]};{name.split()[0]};;;"]
    lines += [f"TEL;TYPE=cell:{t}" for t in tels]
    if email:
        lines.append(f"EMAIL;TYPE=home:{email}")
    if bday:
        lines.append(f"BDAY:{bday}")
    lines.append("NOTE:A long note that is folded across two physical lines so we can check it")
    lines.append(" survives a birthday write untouched.")
    lines.append("END:VCARD")
    return "\r\n".join(lines) + "\r\n"


BOOK = "/remote.php/dav/addressbooks/users/me/contacts/"


class FakeCardDAV:
    def __init__(self):
        self.cards: dict[str, dict] = {}  # href -> {"text", "etag"}
        self.reports = 0
        self.puts: list[dict] = []
        self.conflicts_left = 0  # concurrent edits simulated before the next PUTs
        self._rev = 0

    def add(self, uid: str, name: str, tels: list[str], bday: str | None = None, email: str | None = None) -> str:
        href = f"{BOOK}{uid}.vcf"
        self._rev += 1
        self.cards[href] = {"text": vcard(uid, name, tels, bday, email), "etag": f'"e{self._rev}"'}
        return href

    def text(self, uid: str) -> str:
        return self.cards[f"{BOOK}{uid}.vcf"]["text"]

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handle)

    def handle(self, request: httpx.Request) -> httpx.Response:
        path = unquote(urlparse(str(request.url)).path)
        if request.method == "REPORT" and path == BOOK:
            self.reports += 1
            parts = []
            for href, c in self.cards.items():
                text = c["text"].replace("&", "&amp;").replace("<", "&lt;")
                parts.append(f"<d:response><d:href>{href}</d:href><d:propstat><d:prop><d:getetag>{c['etag']}</d:getetag>"
                             f"<card:address-data>{text}</card:address-data></d:prop>"
                             f"<d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>")
            xml = ('<?xml version="1.0"?><d:multistatus xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav">'
                   + "".join(parts) + "</d:multistatus>")
            return httpx.Response(207, content=xml.encode(), headers={"Content-Type": "application/xml"})
        card = self.cards.get(path)
        if request.method == "GET":
            if not card:
                return httpx.Response(404)
            return httpx.Response(200, text=card["text"], headers={"ETag": card["etag"]})
        if request.method == "PUT":
            if not card:
                return httpx.Response(404)
            if self.conflicts_left > 0:
                # someone else edited the card in between
                self.conflicts_left -= 1
                self._rev += 1
                card["etag"] = f'"e{self._rev}"'
            if request.headers.get("If-Match") != card["etag"]:
                return httpx.Response(412)
            self._rev += 1
            card["text"] = request.content.decode()
            card["etag"] = f'"e{self._rev}"'
            self.puts.append({"href": path, "if_match": request.headers.get("If-Match")})
            return httpx.Response(204, headers={"ETag": card["etag"]})
        return httpx.Response(405)
