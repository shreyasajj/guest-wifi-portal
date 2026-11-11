"""Database models. All timestamps are timezone-aware UTC."""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from sqlmodel import Field, SQLModel


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(value: datetime | None) -> str | None:
    """ISO-8601 UTC with a trailing Z."""
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class DeviceType(str, Enum):
    phone = "phone"  # the one device per person that drives home/away
    other = "other"


class ApprovalStatus(str, Enum):
    pending = "pending"
    approved = "approved"
    approved_no_save = "approved_no_save"
    denied = "denied"
    expired = "expired"


class DecidedBy(str, Enum):
    admin_ui = "admin_ui"
    home_assistant = "home_assistant"
    system = "system"


class Person(SQLModel, table=True):
    contact_uid: str = Field(primary_key=True)
    display_name: str = ""
    phones_json: str = "[]"
    email: Optional[str] = None
    blocked: bool = False
    blocked_at: Optional[datetime] = None
    home: bool = False
    home_changed_at: Optional[datetime] = None
    created_at: datetime = Field(default_factory=utcnow)

    @property
    def phones(self) -> list[str]:
        return json.loads(self.phones_json or "[]")


class Device(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    mac: str = Field(index=True, unique=True)
    person_uid: Optional[str] = Field(default=None, index=True, foreign_key="person.contact_uid")
    type: str = DeviceType.other.value
    nickname: Optional[str] = None
    hostname: Optional[str] = None
    user_agent: Optional[str] = None
    first_seen: datetime = Field(default_factory=utcnow)
    last_seen: Optional[datetime] = None
    current_ip: Optional[str] = None
    online: bool = False
    revoked: bool = False
    revoked_at: Optional[datetime] = None
    revoke_reason: Optional[str] = None

    @property
    def label(self) -> str:
        return self.nickname or self.hostname or self.type.capitalize()


class ApprovalRequest(SQLModel, table=True):
    __tablename__ = "approval_requests"

    id: str = Field(default_factory=lambda: uuid.uuid4().hex, primary_key=True)
    contact_uids_json: str = "[]"
    contact_name: str = ""
    entered_birthday: str = ""  # YYYY-MM-DD
    client_ip: str = ""
    mac: str = Field(index=True)
    user_agent: Optional[str] = None
    created_at: datetime = Field(default_factory=utcnow)
    expires_at: datetime
    status: str = Field(default=ApprovalStatus.pending.value, index=True)
    decided_by: Optional[str] = None
    decided_at: Optional[datetime] = None
    chosen_contact_uid: Optional[str] = None
    note: Optional[str] = None
    error: Optional[str] = None

    @property
    def contact_uids(self) -> list[str]:
        return json.loads(self.contact_uids_json or "[]")


class LoginAttempt(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    at: datetime = Field(default_factory=utcnow, index=True)
    ip: Optional[str] = Field(default=None, index=True)
    mac: Optional[str] = Field(default=None, index=True)
    success: bool = False
    reason: str = ""


class Event(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    at: datetime = Field(default_factory=utcnow, index=True)
    type: str
    payload_json: str = "{}"

    def as_dict(self) -> dict:
        return {"id": self.id, "type": self.type, "at": iso(self.at), "data": json.loads(self.payload_json)}


class AuditLog(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    at: datetime = Field(default_factory=utcnow, index=True)
    actor: str = "system"
    action: str
    target: Optional[str] = None
    detail_json: str = "{}"
    needs_review: bool = False

    @property
    def detail(self) -> dict:
        return json.loads(self.detail_json or "{}")


class UnidentifiedDevice(SQLModel, table=True):
    mac: str = Field(primary_key=True)
    ip: Optional[str] = None
    sources: str = ""  # "zone", "alias", "session" (comma list)
    session_id: Optional[str] = None
    first_seen: datetime = Field(default_factory=utcnow)
    last_seen: datetime = Field(default_factory=utcnow)
