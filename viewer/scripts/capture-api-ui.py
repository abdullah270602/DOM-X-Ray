"""Capture Gate 3 API and Gate 5 hosted-share surfaces for visual review."""

from __future__ import annotations

import sys
from pathlib import Path

from playwright.sync_api import Page, sync_playwright


BASE_URL = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:4173/"
OUTPUT = Path(__file__).resolve().parents[2] / ".impeccable" / "review"


def submit_seed(page: Page) -> str:
    page.goto(f"{BASE_URL}?fixture=clean&time=5000")
    page.locator("#scan-url").fill("https://gallery.example/")
    page.get_by_role("button", name="START X-RAY").click()
    page.get_by_text("IMMUTABLE RESULT READY", exact=True).wait_for(timeout=45_000)
    page.wait_for_url("**/r/r_*", timeout=45_000)
    return page.url


def open_published_result(page: Page, result_url: str) -> None:
    page.goto(result_url)
    page.get_by_role("button", name="SHARE RESULT").wait_for(timeout=20_000)


def open_verified_share(page: Page) -> None:
    page.get_by_role("button", name="SHARE RESULT").click()
    page.get_by_role("dialog", name="SHARE RESULT").wait_for()
    page.get_by_text("SERVER COPY MATCHES IMMUTABLE MANIFEST", exact=True).wait_for(
        timeout=20_000
    )
    page.get_by_text("MOTION COPY MATCHES IMMUTABLE MANIFEST", exact=True).wait_for(
        timeout=20_000
    )


def show_motion(page: Page) -> None:
    page.get_by_role("button", name="5 SEC MOTION").click()
    page.locator(".share-preview video").wait_for()
    page.locator(".share-dialog").evaluate("element => { element.scrollTop = 0; }")
    page.wait_for_timeout(1_200)


def main() -> None:
    OUTPUT.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        desktop = browser.new_page(viewport={"width": 1440, "height": 900})
        result_url = submit_seed(desktop)
        desktop.screenshot(path=OUTPUT / "gate3-api-ready-desktop.png", full_page=True)
        open_verified_share(desktop)
        desktop.screenshot(path=OUTPUT / "gate5-hosted-share-desktop.png", full_page=True)
        show_motion(desktop)
        desktop.screenshot(path=OUTPUT / "gate5-hosted-share-motion-desktop.png", full_page=True)

        mobile = browser.new_page(viewport={"width": 390, "height": 844}, device_scale_factor=1)
        open_published_result(mobile, result_url)
        mobile.screenshot(path=OUTPUT / "gate3-api-ready-mobile.png", full_page=True)
        open_verified_share(mobile)
        mobile.screenshot(path=OUTPUT / "gate5-hosted-share-mobile.png")
        show_motion(mobile)
        mobile.screenshot(path=OUTPUT / "gate5-hosted-share-motion-mobile.png")
        mobile.get_by_role("button", name="CLOSE SHARE RESULT").click()
        mobile.locator("#scan-url").fill("https://www.example.org/")
        mobile.get_by_role("button", name="START X-RAY").click()
        mobile.get_by_role("alert").wait_for()
        mobile.screenshot(path=OUTPUT / "gate3-api-disabled-mobile.png", full_page=True)
        browser.close()

    print(f"Captured Gate 3 interface evidence in {OUTPUT}")


if __name__ == "__main__":
    main()
