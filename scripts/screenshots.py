"""Regenerate the README screenshots in docs/screenshots/.

    pip install -r requirements.txt -r scripts/requirements-screenshots.txt
    playwright install chromium
    python scripts/screenshots.py

Starts scripts/demo_server.py (fake OPNsense + Nextcloud with made-up data) on a free port,
walks through the guest flow and the admin pages in headless Chromium, then stops the server.
Set CHROME_PATH to use an existing Chromium/headless-shell binary instead of Playwright's.
"""
from __future__ import annotations

import argparse
import asyncio
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

from playwright.async_api import async_playwright

ROOT = Path(__file__).resolve().parent.parent
PHONE = {"viewport": {"width": 390, "height": 844}, "device_scale_factor": 2, "is_mobile": True, "has_touch": True}
DESKTOP = {"viewport": {"width": 1440, "height": 640}, "device_scale_factor": 2}


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_healthy(base: str, proc: subprocess.Popen, timeout: float = 30) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise SystemExit(f"demo server exited with code {proc.returncode}")
        try:
            with urllib.request.urlopen(base + "/healthz", timeout=1):
                return
        except OSError:
            time.sleep(0.3)
    raise SystemExit("demo server did not start")


class Shooter:
    def __init__(self, browser, base: str, out: Path):
        self.browser, self.base, self.out = browser, base, out

    async def settle(self, page) -> None:
        await page.wait_for_load_state("networkidle")
        await page.evaluate("document.fonts.ready")
        await page.wait_for_timeout(400)

    async def shot(self, page, name: str, full_page: bool = False) -> None:
        await page.screenshot(path=self.out / f"{name}.png", full_page=full_page)
        print("  ", name)

    async def guest_login(self, page, phone: str, bday: str) -> None:
        await page.goto(self.base + "/")
        await page.fill("#phone", phone)
        await page.fill("#birthday", bday)
        await page.click("button[type=submit]")
        await self.settle(page)

    async def admin(self) -> None:
        ctx = await self.browser.new_context(color_scheme="dark", **DESKTOP)
        page = await ctx.new_page()
        await page.goto(self.base + "/admin/login")
        await self.settle(page)
        await self.shot(page, "admin-login")
        await page.fill("#username", "admin")
        await page.fill("#password", "demo")
        await page.click("form[action='/admin/login'] button[type=submit]")
        await self.settle(page)
        await page.wait_for_timeout(800)  # live feed
        await self.shot(page, "admin-dashboard", full_page=True)
        for name in ("people", "devices", "unidentified", "audit"):
            await page.goto(f"{self.base}/admin/{name}")
            await self.settle(page)
            await self.shot(page, f"admin-{name}", full_page=True)
        await ctx.close()

    async def guest_light(self) -> None:
        # Before the guest flow: once this browser's device is registered, / shows "already connected".
        ctx = await self.browser.new_context(color_scheme="light", **PHONE)
        page = await ctx.new_page()
        await page.goto(self.base + "/")
        await self.settle(page)
        await self.shot(page, "guest-login-light")
        await ctx.close()

    async def guest(self) -> None:
        ctx = await self.browser.new_context(color_scheme="dark", **PHONE)
        page = await ctx.new_page()
        await page.goto(self.base + "/")
        await self.settle(page)
        await self.shot(page, "guest-login")

        # Maya has a birthday: device page.
        await self.guest_login(page, "(415) 555-0134", "1991-04-12")
        await self.shot(page, "guest-device")

        # Lena has no birthday: waiting for approval.
        await self.guest_login(page, "415 555 0175", "1997-09-14")
        await page.wait_for_timeout(600)
        await self.shot(page, "guest-waiting")

        # Taylor is new: registered.
        await self.guest_login(page, "+1 415 555 0162", "1995-06-30")
        await page.check("#t-phone", force=True)
        await page.fill("#nickname", "Taylor's phone")
        await page.click("form[action='/device'] button[type=submit]")
        await self.settle(page)
        await self.shot(page, "guest-done")
        await ctx.close()


async def capture(base: str, out: Path) -> None:
    async with async_playwright() as p:
        browser = await p.chromium.launch(executable_path=os.environ.get("CHROME_PATH") or None)
        shooter = Shooter(browser, base, out)
        await shooter.admin()
        await shooter.guest_light()
        await shooter.guest()
        await browser.close()


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", type=Path, default=ROOT / "docs" / "screenshots")
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    port = free_port()
    base = f"http://127.0.0.1:{port}"
    with tempfile.TemporaryDirectory() as tmp:
        proc = subprocess.Popen([sys.executable, str(ROOT / "scripts" / "demo_server.py"), str(Path(tmp) / "demo.db"),
                                 str(port)])
        try:
            wait_healthy(base, proc)
            print(f"Capturing into {args.out}")
            asyncio.run(capture(base, args.out))
        finally:
            proc.terminate()
            proc.wait(timeout=10)


if __name__ == "__main__":
    main()
