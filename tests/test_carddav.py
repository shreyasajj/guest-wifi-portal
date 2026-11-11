from datetime import date

import pytest

from app.carddav import CardDAVClient, ETagConflict, parse_vcard, set_bday_in_vcard

from .fakes import BOOK, FakeCardDAV, vcard


def client(dav: FakeCardDAV, **kw) -> CardDAVClient:
    return CardDAVClient(f"https://cloud.test{BOOK}", "me", "pw", region="US", transport=dav.transport(), **kw)


async def test_fetch_parses_all_contacts():
    dav = FakeCardDAV()
    dav.add("u1", "Maya Chen", ["(415) 555-0142", "+1 415 555 0199"], "1991-04-12", "maya@example.com")
    dav.add("u2", "Jordan Lee", ["+44 20 7946 0958"], "--0704")
    dav.add("u3", "No Bday", ["415-555-0100"])
    contacts = await client(dav).fetch_all()
    by = {c.uid: c for c in contacts}
    assert by["u1"].phones == ["+14155550142", "+14155550199"]
    assert by["u1"].emails == ["maya@example.com"]
    assert by["u1"].birthday_raw == "1991-04-12"
    assert by["u1"].etag.startswith('"e')
    assert by["u2"].phones == ["+442079460958"]
    assert by["u2"].birthday.year is None
    assert by["u3"].birthday_raw is None


def test_parse_vcard4_bday_formats():
    text = "BEGIN:VCARD\r\nVERSION:4.0\r\nUID:x\r\nFN:X\r\nTEL;VALUE=uri:tel:+1-415-555-0142\r\nBDAY:--0412\r\nEND:VCARD\r\n"
    c = parse_vcard(text, "/x.vcf", None, "US")
    assert c.phones == ["+14155550142"]
    assert c.birthday.month == 4 and c.birthday.day == 12 and c.birthday.year is None


def test_set_bday_inserts_and_preserves_other_lines():
    text = vcard("u", "Maya Chen", ["+14155550142"])
    out = set_bday_in_vcard(text, date(1991, 4, 12))
    assert "BDAY:1991-04-12\r\nEND:VCARD\r\n" in out
    assert "NOTE:A long note that is folded across two physical lines so we can check it\r\n survives" in out


def test_set_bday_replaces_existing():
    text = vcard("u", "Maya Chen", ["+14155550142"], bday="--0101").replace("BDAY:--0101", "item1.BDAY;VALUE=date:--0101")
    out = set_bday_in_vcard(text, date(1991, 4, 12))
    assert out.count("BDAY") == 1 and "BDAY:1991-04-12" in out


async def test_cache_and_refresh_rules():
    dav = FakeCardDAV()
    dav.add("u1", "A", ["+14155550142"])
    cd = client(dav, cache_seconds=300, min_refresh_seconds=60)
    await cd.contacts()
    await cd.contacts()
    assert dav.reports == 1  # served from cache
    assert await cd.refresh_if_allowed() is None  # too soon after the last fetch
    assert dav.reports == 1
    await cd.contacts(force=True)
    assert dav.reports == 2


async def test_cache_miss_refresh_allowed_after_interval():
    dav = FakeCardDAV()
    cd = client(dav, cache_seconds=300, min_refresh_seconds=0)
    assert await cd.contacts() == []
    dav.add("u1", "A", ["+14155550142"])
    fresh = await cd.refresh_if_allowed()
    assert [c.uid for c in fresh] == ["u1"]


async def test_write_birthday_uses_if_match():
    dav = FakeCardDAV()
    href = dav.add("u1", "A", ["+14155550142"])
    etag = dav.cards[href]["etag"]
    cd = client(dav)
    await cd.write_birthday("u1", date(1991, 4, 12))
    assert dav.puts == [{"href": href, "if_match": etag}]
    assert "BDAY:1991-04-12" in dav.text("u1")
    assert cd._cache is None  # invalidated after write


async def test_write_birthday_etag_conflict_refetches_and_retries_once():
    dav = FakeCardDAV()
    dav.add("u1", "A", ["+14155550142"])
    cd = client(dav)
    await cd.contacts()
    dav.conflicts_left = 1  # one concurrent edit
    await cd.write_birthday("u1", date(1991, 4, 12))
    assert len(dav.puts) == 1
    assert "BDAY:1991-04-12" in dav.text("u1")


async def test_write_birthday_conflict_twice_raises():
    dav = FakeCardDAV()
    dav.add("u1", "A", ["+14155550142"])
    cd = client(dav)
    await cd.contacts()
    dav.conflicts_left = 2
    with pytest.raises(ETagConflict):
        await cd.write_birthday("u1", date(1991, 4, 12))
    assert dav.puts == []
    assert "BDAY" not in dav.text("u1")
    assert cd._cache is None
