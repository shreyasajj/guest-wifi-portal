from datetime import date

import pytest

from app.matching import Birthday, Contact, Outcome, evaluate, normalize_phone, parse_birthday

P = "+14155550142"


def c(uid, phones=(P,), bday=None, name=None):
    return Contact(uid=uid, display_name=name or uid, phones=list(phones), birthday_raw=bday)


@pytest.mark.parametrize("raw", ["(415) 555-0142", "415.555.0142", "+1 415 555 0142", "011 1 415 555 0142",
                                 "tel:+1-415-555-0142", " 4155550142 "])
def test_phone_normalization_us(raw):
    assert normalize_phone(raw, "US") == P


def test_phone_normalization_other_region():
    assert normalize_phone("030 1234567", "DE") == "+49301234567"
    assert normalize_phone("not a phone", "US") is None
    assert normalize_phone("", "US") is None


@pytest.mark.parametrize("raw,expected", [
    ("1991-04-12", Birthday(1991, 4, 12)),
    ("19910412", Birthday(1991, 4, 12)),
    ("1991-04-12T00:00:00Z", Birthday(1991, 4, 12)),
    ("--0412", Birthday(None, 4, 12)),
    ("--04-12", Birthday(None, 4, 12)),
    ("1604-04-12", Birthday(None, 4, 12)),  # Apple's year-less marker
    ("--0229", Birthday(None, 2, 29)),
])
def test_parse_birthday(raw, expected):
    assert parse_birthday(raw) == expected


@pytest.mark.parametrize("raw", ["", None, "April 12", "1991-13-01", "--1340", "garbage"])
def test_parse_birthday_invalid(raw):
    assert parse_birthday(raw) is None


def test_success_with_matching_bday():
    r = evaluate([c("a", bday="1991-04-12")], P, date(1991, 4, 12))
    assert r.outcome == Outcome.success and r.matched.uid == "a"


def test_multiple_contacts_same_phone_any_match_wins():
    contacts = [c("old", bday="1980-01-01"), c("dup", bday="1991-04-12"), c("other", phones=["+14155550000"])]
    r = evaluate(contacts, P, date(1991, 4, 12))
    assert r.outcome == Outcome.success
    assert r.matched.uid == "dup"
    assert [x.uid for x in r.candidates] == ["old", "dup"]


def test_one_with_bday_one_without_and_bday_matches():
    r = evaluate([c("nobday"), c("withbday", bday="1991-04-12")], P, date(1991, 4, 12))
    assert r.outcome == Outcome.success and r.matched.uid == "withbday"


def test_one_with_bday_one_without_mismatch_rejects_never_approval():
    r = evaluate([c("nobday"), c("withbday", bday="1991-04-12")], P, date(1990, 1, 1))
    assert r.outcome == Outcome.reject_birthday
    assert r.rejected


def test_bday_mismatch_rejects():
    r = evaluate([c("a", bday="1991-04-12")], P, date(1991, 4, 13))
    assert r.outcome == Outcome.reject_birthday


def test_unparseable_bday_counts_as_present_and_rejects():
    r = evaluate([c("a", bday="sometime in spring")], P, date(1991, 4, 12))
    assert r.outcome == Outcome.reject_birthday


def test_all_without_bday_needs_approval():
    r = evaluate([c("a"), c("b")], P, date(1991, 4, 12))
    assert r.outcome == Outcome.needs_approval
    assert {x.uid for x in r.candidates} == {"a", "b"}


def test_yearless_bday_matches_month_and_day_only():
    contacts = [c("a", bday="--0412")]
    assert evaluate(contacts, P, date(1991, 4, 12)).outcome == Outcome.success
    assert evaluate(contacts, P, date(2003, 4, 12)).outcome == Outcome.success
    assert evaluate(contacts, P, date(1991, 4, 13)).outcome == Outcome.reject_birthday


def test_full_bday_requires_year():
    assert evaluate([c("a", bday="19910412")], P, date(1992, 4, 12)).outcome == Outcome.reject_birthday


def test_unknown_phone_rejects():
    r = evaluate([c("a", bday="1991-04-12")], "+14155559999", date(1991, 4, 12))
    assert r.outcome == Outcome.reject_no_phone


def test_no_phone_input_rejects():
    assert evaluate([c("a")], None, date(1991, 4, 12)).outcome == Outcome.reject_no_phone
