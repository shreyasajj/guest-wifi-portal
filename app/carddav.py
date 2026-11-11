"""Nextcloud CardDAV access: read the address book, cache it, and write BDAY back."""
from __future__ import annotations

import asyncio
import logging
import time
import xml.etree.ElementTree as ET
from datetime import date
from urllib.parse import urljoin

import httpx
import vobject

from .matching import Contact, normalize_phone

log = logging.getLogger(__name__)

NS = {"d": "DAV:", "card": "urn:ietf:params:xml:ns:carddav"}

REPORT_BODY = """<?xml version="1.0" encoding="utf-8"?>
<card:addressbook-query xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav">
  <d:prop><d:getetag/><card:address-data/></d:prop>
</card:addressbook-query>"""


class CardDAVError(Exception):
    pass


class ETagConflict(CardDAVError):
    pass


def parse_vcard(text: str, href: str, etag: str | None, region: str) -> Contact | None:
    try:
        card = vobject.readOne(text, ignoreUnreadable=True)
    except Exception:  # noqa: BLE001 - malformed cards are skipped, not fatal
        log.warning("skipping unparsable vCard %s", href)
        return None
    uid = str(card.uid.value) if hasattr(card, "uid") else href
    name = ""
    if hasattr(card, "fn"):
        name = str(card.fn.value)
    elif hasattr(card, "n"):
        name = str(card.n.value).strip()
    phones = []
    for tel in card.contents.get("tel", []):
        e164 = normalize_phone(str(tel.value), region)
        if e164 and e164 not in phones:
            phones.append(e164)
    emails = [str(e.value) for e in card.contents.get("email", [])]
    bday = None
    if "bday" in card.contents:
        raw = card.contents["bday"][0].value
        bday = raw.isoformat() if isinstance(raw, date) else str(raw).strip()
    return Contact(uid=uid, display_name=name or uid, phones=phones, emails=emails,
                   birthday_raw=bday or None, href=href, etag=etag)


def set_bday_in_vcard(text: str, bday: date) -> str:
    """Replace or insert BDAY, keeping every other line byte-for-byte (incl. folding)."""
    lines = text.replace("\r\n", "\n").split("\n")
    logical: list[list[str]] = []
    for line in lines:
        if line[:1] in (" ", "\t") and logical:
            logical[-1].append(line)
        else:
            logical.append([line])

    def prop_name(group: list[str]) -> str:
        head = group[0].split(":", 1)[0].split(";", 1)[0]
        return head.split(".", 1)[-1].upper()

    kept = [g for g in logical if prop_name(g) not in ("BDAY", "X-APPLE-OMIT-YEAR")]
    out: list[str] = []
    inserted = False
    for g in kept:
        if not inserted and g[0].strip().upper() == "END:VCARD":
            out.append(f"BDAY:{bday.isoformat()}")
            inserted = True
        out.extend(g)
    if not inserted:
        raise CardDAVError("vCard has no END:VCARD")
    while out and out[-1] == "":
        out.pop()
    return "\r\n".join(out) + "\r\n"


class CardDAVClient:
    def __init__(self, url: str, user: str, password: str, *, region: str = "US", verify: bool = True,
                 cache_seconds: int = 300, min_refresh_seconds: int = 15,
                 transport: httpx.AsyncBaseTransport | None = None):
        self.url = url if url.endswith("/") else url + "/"
        self.region = region
        self.cache_seconds = cache_seconds
        self.min_refresh_seconds = min_refresh_seconds
        self._http = httpx.AsyncClient(auth=(user, password), verify=verify, timeout=15.0, transport=transport)
        self._cache: list[Contact] | None = None
        self._fetched_at = 0.0
        self._lock = asyncio.Lock()

    async def aclose(self) -> None:
        await self._http.aclose()

    async def _request(self, method: str, url: str, **kw) -> httpx.Response:
        try:
            return await self._http.request(method, url, **kw)
        except httpx.HTTPError as exc:
            raise CardDAVError(f"{method} {url}: {exc}") from exc

    # ------------------------------------------------------------- reading
    async def fetch_all(self) -> list[Contact]:
        resp = await self._request(
            "REPORT", self.url, content=REPORT_BODY,
            headers={"Depth": "1", "Content-Type": "application/xml; charset=utf-8"},
        )
        if resp.status_code != 207:
            raise CardDAVError(f"REPORT {resp.status_code}")
        try:
            root = ET.fromstring(resp.content)
        except ET.ParseError as exc:
            raise CardDAVError(f"invalid REPORT response: {exc}") from exc
        contacts = []
        for r in root.findall("d:response", NS):
            href = (r.findtext("d:href", default="", namespaces=NS) or "").strip()
            for ps in r.findall("d:propstat", NS):
                if "200" not in (ps.findtext("d:status", default="", namespaces=NS) or ""):
                    continue
                prop = ps.find("d:prop", NS)
                data = prop.findtext("card:address-data", default=None, namespaces=NS) if prop is not None else None
                etag = prop.findtext("d:getetag", default=None, namespaces=NS) if prop is not None else None
                if data:
                    c = parse_vcard(data, href, etag, self.region)
                    if c:
                        contacts.append(c)
        return contacts

    def _fresh(self) -> bool:
        return self._cache is not None and time.monotonic() - self._fetched_at < self.cache_seconds

    async def contacts(self, *, force: bool = False) -> list[Contact]:
        async with self._lock:
            if force or not self._fresh():
                self._cache = await self.fetch_all()
                self._fetched_at = time.monotonic()
            return list(self._cache or [])

    async def refresh_if_allowed(self) -> list[Contact] | None:
        """Refresh after a cache miss, but not more often than min_refresh_seconds."""
        if self._cache is not None and time.monotonic() - self._fetched_at < self.min_refresh_seconds:
            return None
        return await self.contacts(force=True)

    def invalidate(self) -> None:
        self._fetched_at = 0.0
        self._cache = None

    def cached_by_uid(self, uid: str) -> Contact | None:
        return next((c for c in self._cache or [] if c.uid == uid), None)

    async def get_by_uid(self, uid: str) -> Contact | None:
        c = self.cached_by_uid(uid)
        if c:
            return c
        return next((c for c in await self.contacts() if c.uid == uid), None)

    # ------------------------------------------------------------- writing
    def _abs(self, href: str) -> str:
        return urljoin(self.url, href)

    async def _get_card(self, href: str) -> tuple[str, str | None]:
        resp = await self._request("GET", self._abs(href))
        if resp.status_code != 200:
            raise CardDAVError(f"GET {href}: {resp.status_code}")
        return resp.text, resp.headers.get("ETag")

    async def _put_card(self, href: str, text: str, etag: str | None) -> httpx.Response:
        headers = {"Content-Type": "text/vcard; charset=utf-8"}
        if etag:
            headers["If-Match"] = etag
        return await self._request("PUT", self._abs(href), content=text.encode(), headers=headers)

    async def write_birthday(self, uid: str, bday: date) -> None:
        """PUT BDAY with If-Match. On 412, refetch and retry once, then raise ETagConflict."""
        contact = await self.get_by_uid(uid)
        if not contact:
            raise CardDAVError(f"contact {uid} not found")
        try:
            text, etag = await self._get_card(contact.href)
            etag = etag or contact.etag
            for attempt in (1, 2):
                resp = await self._put_card(contact.href, set_bday_in_vcard(text, bday), etag)
                if resp.status_code in (200, 201, 204):
                    return
                if resp.status_code == 412 and attempt == 1:
                    log.info("ETag conflict writing %s, refetching", uid)
                    text, etag = await self._get_card(contact.href)
                    continue
                if resp.status_code == 412:
                    raise ETagConflict(f"contact {uid} changed concurrently (ETag mismatch twice)")
                raise CardDAVError(f"PUT {contact.href}: {resp.status_code}")
        finally:
            self.invalidate()
