"""Phone/birthday matching against address-book contacts.

Rules (see spec):
  * every contact whose TEL normalises to the entered phone is a candidate
  * any candidate with a matching BDAY            -> SUCCESS
  * candidates exist, at least one has a BDAY,
    none of them match                            -> REJECT (never approval)
  * candidates exist, none has a BDAY             -> NEEDS_APPROVAL
  * no candidate                                  -> REJECT
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import date
from enum import Enum

import phonenumbers

# Apple Contacts stores year-less birthdays as 1604-MM-DD (with X-APPLE-OMIT-YEAR).
_YEARLESS_SENTINELS = {1604, 0}


@dataclass(frozen=True)
class Birthday:
    year: int | None
    month: int
    day: int

    def matches(self, entered: date) -> bool:
        if self.month != entered.month or self.day != entered.day:
            return False
        return self.year is None or self.year == entered.year

    def iso(self) -> str:
        return f"{self.year:04d}-{self.month:02d}-{self.day:02d}" if self.year else f"--{self.month:02d}-{self.day:02d}"


_FULL = re.compile(r"^(\d{4})-?(\d{2})-?(\d{2})")
_YEARLESS = re.compile(r"^--(\d{2})-?(\d{2})$")


def parse_birthday(raw: str | None) -> Birthday | None:
    """Parse vCard BDAY values: YYYY-MM-DD, YYYYMMDD, --MMDD, --MM-DD (time part ignored)."""
    if not raw:
        return None
    value = str(raw).strip()
    m = _YEARLESS.match(value)
    if m:
        month, day = int(m.group(1)), int(m.group(2))
        year = None
    else:
        m = _FULL.match(value)
        if not m:
            return None
        year, month, day = int(m.group(1)), int(m.group(2)), int(m.group(3))
        if year in _YEARLESS_SENTINELS:
            year = None
    try:
        date(year or 2000, month, day)  # 2000 is a leap year, so --0229 is valid
    except ValueError:
        return None
    return Birthday(year, month, day)


def normalize_phone(raw: str | None, region: str) -> str | None:
    if not raw:
        return None
    raw = raw.strip()
    if raw.lower().startswith("tel:"):  # vCard 4 URI form
        raw = raw[4:].split(";", 1)[0]
    try:
        num = phonenumbers.parse(raw, region)
    except phonenumbers.NumberParseException:
        return None
    if not phonenumbers.is_possible_number(num):
        return None
    return phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.E164)


@dataclass
class Contact:
    uid: str
    display_name: str
    phones: list[str]  # E.164
    emails: list[str] = field(default_factory=list)
    birthday_raw: str | None = None
    href: str = ""
    etag: str | None = None

    @property
    def has_birthday(self) -> bool:
        return bool(self.birthday_raw)

    @property
    def birthday(self) -> Birthday | None:
        return parse_birthday(self.birthday_raw)


class Outcome(str, Enum):
    success = "success"
    needs_approval = "needs_approval"
    reject_no_phone = "reject_no_phone"
    reject_birthday = "reject_birthday"


@dataclass
class MatchResult:
    outcome: Outcome
    candidates: list[Contact]
    matched: Contact | None = None

    @property
    def rejected(self) -> bool:
        return self.outcome in (Outcome.reject_no_phone, Outcome.reject_birthday)


def evaluate(contacts: list[Contact], phone_e164: str | None, entered: date) -> MatchResult:
    if not phone_e164:
        return MatchResult(Outcome.reject_no_phone, [])
    candidates = [c for c in contacts if phone_e164 in c.phones]
    if not candidates:
        return MatchResult(Outcome.reject_no_phone, [])
    for c in candidates:
        bday = c.birthday
        if bday and bday.matches(entered):
            return MatchResult(Outcome.success, candidates, c)
    # A BDAY that exists but can't be parsed still counts as "has a birthday":
    # it must never fall through to the approval path.
    if any(c.has_birthday for c in candidates):
        return MatchResult(Outcome.reject_birthday, candidates)
    return MatchResult(Outcome.needs_approval, candidates)
