import re

_HEX = re.compile(r"[^0-9a-f]")


def normalize_mac(value: str | None) -> str | None:
    """Return a lower-case, colon-separated MAC, or None if it isn't one."""
    if not value:
        return None
    digits = _HEX.sub("", value.lower())
    if len(digits) != 12:
        return None
    return ":".join(digits[i : i + 2] for i in range(0, 12, 2))


def is_randomized(mac: str) -> bool:
    """Locally administered bit set: typical of iOS/Android private addresses."""
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except (ValueError, IndexError):
        return False
