"""Capture the Gate 3 API-ready and recovery surfaces for bounded visual review."""

from __future__ import annotations

import sys
from pathlib import Path

from playwright.sync_api import Page, sync_playwright


BASE_URL = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:4173/"
OUTPUT = Path(__file__).resolve().parents[2] / ".impeccable" / "review"


def submit_seed(page: Page) -> None:
    page.goto(f"{BASE_URL}?fixture=clean&time=5000")
    page.locator("#scan-url").fill("https://gallery.example/")
    page.get_by_role("button", name="START X-RAY").click()
    page.get_by_text("IMMUTABLE RESULT READY", exact=True).wait_for(timeout=10_000)
    page.wait_for_url("**/r/r_*", timeout=10_000)


def main() -> None:
    OUTPUT.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        desktop = browser.new_page(viewport={"width": 1440, "height": 900})
        submit_seed(desktop)
        desktop.screenshot(path=OUTPUT / "gate3-api-ready-desktop.png", full_page=True)

        mobile = browser.new_page(viewport={"width": 390, "height": 844}, device_scale_factor=1)
        submit_seed(mobile)
        mobile.screenshot(path=OUTPUT / "gate3-api-ready-mobile.png", full_page=True)
        mobile.locator("#scan-url").fill("https://www.example.org/")
        mobile.get_by_role("button", name="START X-RAY").click()
        mobile.get_by_role("alert").wait_for()
        mobile.screenshot(path=OUTPUT / "gate3-api-disabled-mobile.png", full_page=True)
        browser.close()

    print(f"Captured Gate 3 interface evidence in {OUTPUT}")


if __name__ == "__main__":
    main()
