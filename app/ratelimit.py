"""Login rate limiting with exponential backoff, keyed separately on IP and MAC.

After LOGIN_MAX_FAILURES failures inside LOGIN_WINDOW_SECONDS (counted since the last
success for that key), each further failure doubles the lockout:
base, 2*base, 4*base ... capped at LOGIN_BACKOFF_MAX_SECONDS.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlmodel import Session, col, select

from .models import LoginAttempt, utcnow


# Logged attempts that neither count as a wrong guess nor reset the counter.
NON_FAILURE_REASONS = {"approval_requested", "approval_reused", "approval_cooldown", "rate_limited", "no_mac",
                       "invalid_input", "backend_error"}


@dataclass
class LimitPolicy:
    max_failures: int = 5
    window_seconds: int = 900
    base_seconds: int = 60
    max_seconds: int = 3600


class LoginLimiter:
    def __init__(self, policy: LimitPolicy):
        self.p = policy

    def _retry_after_for(self, session: Session, column, value: str | None, now: datetime) -> int:
        if not value:
            return 0
        window_start = now - timedelta(seconds=max(self.p.window_seconds, self.p.max_seconds))
        rows = session.exec(
            select(LoginAttempt).where(column == value, LoginAttempt.at >= window_start)
            .order_by(col(LoginAttempt.at).desc())
        ).all()
        failures: list[datetime] = []
        for r in rows:
            if r.success:
                break
            if r.reason in NON_FAILURE_REASONS:
                continue
            failures.append(r.at)
        recent = [f for f in failures if f >= now - timedelta(seconds=self.p.window_seconds)]
        if len(recent) < self.p.max_failures:
            return 0
        over = len(failures) - self.p.max_failures
        backoff = min(self.p.base_seconds * (2 ** over), self.p.max_seconds)
        until = failures[0] + timedelta(seconds=backoff)
        return max(0, int((until - now).total_seconds() + 0.999))

    def retry_after(self, session: Session, ip: str | None, mac: str | None, now: datetime | None = None) -> int:
        now = now or utcnow()
        return max(
            self._retry_after_for(session, LoginAttempt.ip, ip, now),
            self._retry_after_for(session, LoginAttempt.mac, mac, now),
        )

    def record(self, session: Session, ip: str | None, mac: str | None, success: bool, reason: str,
               now: datetime | None = None) -> None:
        session.add(LoginAttempt(ip=ip, mac=mac, success=success, reason=reason, at=now or utcnow()))
        session.commit()
