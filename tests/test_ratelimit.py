from datetime import timedelta

from app.models import utcnow
from app.ratelimit import LimitPolicy, LoginLimiter

IP, MAC = "10.0.20.5", "aa:bb:cc:00:00:01"


def test_lockout_and_exponential_backoff(session):
    lim = LoginLimiter(LimitPolicy(max_failures=3, window_seconds=900, base_seconds=60, max_seconds=3600))
    t = utcnow()
    for i in range(2):
        lim.record(session, IP, MAC, False, "reject_birthday", now=t + timedelta(seconds=i))
    assert lim.retry_after(session, IP, MAC, now=t + timedelta(seconds=2)) == 0
    lim.record(session, IP, MAC, False, "reject_birthday", now=t + timedelta(seconds=2))
    assert lim.retry_after(session, IP, MAC, now=t + timedelta(seconds=2)) == 60
    lim.record(session, IP, MAC, False, "reject_birthday", now=t + timedelta(seconds=70))
    assert lim.retry_after(session, IP, MAC, now=t + timedelta(seconds=70)) == 120


def test_mac_limit_applies_across_ips(session):
    lim = LoginLimiter(LimitPolicy(max_failures=2, base_seconds=30))
    t = utcnow()
    lim.record(session, "10.0.20.5", MAC, False, "reject_no_phone", now=t)
    lim.record(session, "10.0.20.6", MAC, False, "reject_no_phone", now=t)
    assert lim.retry_after(session, "10.0.20.7", MAC, now=t) == 30


def test_success_resets_and_non_failures_ignored(session):
    lim = LoginLimiter(LimitPolicy(max_failures=2, base_seconds=30))
    t = utcnow()
    lim.record(session, IP, MAC, False, "reject_birthday", now=t)
    lim.record(session, IP, MAC, True, "success", now=t + timedelta(seconds=1))
    lim.record(session, IP, MAC, False, "reject_birthday", now=t + timedelta(seconds=2))
    for i in range(5):
        lim.record(session, IP, MAC, False, "approval_cooldown", now=t + timedelta(seconds=3 + i))
    assert lim.retry_after(session, IP, MAC, now=t + timedelta(seconds=10)) == 0
