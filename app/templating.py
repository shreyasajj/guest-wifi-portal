from datetime import datetime
from pathlib import Path

from fastapi.templating import Jinja2Templates

from .config import get_settings
from .macs import is_randomized
from .models import utcnow
from .scene import scene_svg
from .security import csrf_token

templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
templates.env.globals.update(csrf_token=csrf_token, scene=scene_svg())


def _ago(value: datetime | None) -> str:
    if not value:
        return "never"
    secs = int((utcnow() - value).total_seconds())
    if secs < 60:
        return "just now"
    if secs < 3600:
        return f"{secs // 60} min ago"
    if secs < 86400:
        return f"{secs // 3600} h ago"
    return f"{secs // 86400} d ago"


def _until(value: datetime | None) -> str:
    if not value:
        return ""
    secs = int((value - utcnow()).total_seconds())
    return "expired" if secs <= 0 else f"{secs // 60}:{secs % 60:02d}"


def _device_hint(ua: str | None) -> str:
    ua = ua or ""
    for needle, label in (("iPhone", "iPhone"), ("iPad", "iPad"), ("Android", "Android"), ("Macintosh", "Mac"),
                          ("Windows", "Windows PC"), ("CrOS", "Chromebook"), ("Linux", "Linux")):
        if needle in ua:
            return label
    return "Unknown device"


templates.env.filters.update(ago=_ago, until=_until, device_hint=_device_hint, is_private=is_randomized)


def set_site_name(name: str) -> None:
    templates.env.globals["site_name"] = name


set_site_name(get_settings().site_name)
