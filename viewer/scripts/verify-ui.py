"""Verify the local DOM X-Ray viewer against its public interaction contract."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from playwright.sync_api import sync_playwright


BASE_URL = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:4173/"
ROOT = Path(__file__).resolve().parents[2]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> None:
    image_runtime = json.loads(
        (ROOT / "fixtures" / "viewer-runtime" / "image-heavy.json").read_text(encoding="utf-8")
    )
    clean_runtime = json.loads(
        (ROOT / "fixtures" / "viewer-runtime" / "clean.json").read_text(encoding="utf-8")
    )
    third_runtime = json.loads(
        (ROOT / "fixtures" / "viewer-runtime" / "third-party-heavy.json").read_text(
            encoding="utf-8"
        )
    )
    browser_errors: list[str] = []

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        page = browser.new_page(viewport={"width": 1440, "height": 900})
        page.on("pageerror", lambda error: browser_errors.append(str(error)))
        page.goto(f"{BASE_URL}?fixture=image-heavy&time=5000&mode=weight")
        page.get_by_role("heading", name="DOM X-RAY").wait_for()
        require(
            page.get_by_text(image_runtime["presentation"]["finding"]["statement"], exact=True).count()
            == 1,
            "image-heavy hero was not bound from the runtime",
        )
        require(
            page.get_by_role("button", name="WEIGHT").get_attribute("aria-pressed") == "true",
            "screenshot route did not restore its mode",
        )
        page.get_by_role("button", name="VIEW EVIDENCE").click()
        page.get_by_role("complementary", name="Evidence for selected object").wait_for()
        require(page.get_by_text("finding:primary", exact=True).count() == 1, "hero evidence did not open")
        page.get_by_role("button", name="Close evidence").click()

        page.locator("#fixture").select_option("third-party-heavy")
        require(
            page.get_by_text(third_runtime["presentation"]["finding"]["statement"], exact=True).count()
            == 1,
            "third-party fixture reused hard-coded hero copy",
        )
        require(page.get_by_text("PARTIAL CAPTURE", exact=True).count() == 1, "partial status was hidden")

        page.get_by_role("button", name="OBJECT INDEX").click()
        require(
            page.locator(".text-scene li").count() == len(third_runtime["selectables"]),
            "text path omitted selectable evidence",
        )

        page.goto(f"{BASE_URL}?fixture=clean&motion=reduced")
        require(page.get_by_role("button", name="NEXT STAGE").count() == 1, "reduced motion did not step")
        for _ in range(4):
            page.get_by_role("button", name="NEXT STAGE").click()
        require(page.locator(".timeline-control output").text_content() == "100%", "five steps did not finish")

        page.goto(f"{BASE_URL}?fixture=clean&fallback=text&time=5000")
        page.get_by_role("heading", name="MODEL INDEX").wait_for()
        require(page.locator("canvas").count() == 0, "text fallback mounted WebGL")
        require(
            page.locator(".text-scene li").count() == len(clean_runtime["selectables"]),
            "clean text fallback did not expose its complete runtime index",
        )

        page.locator("#scan-url").fill("ftp://private.invalid/")
        page.get_by_role("button", name="X-RAY DEMO").click()
        require(
            page.get_by_role("alert").text_content() == "Enter a complete public HTTP or HTTPS URL.",
            "invalid URL recovery was not explicit",
        )
        browser.close()

    require(not browser_errors, f"browser errors: {browser_errors}")
    print(
        "Verified image-heavy and third-party runtime binding, deterministic route state, "
        "evidence drawer, partial status, reduced-motion steps, text fallback, and URL error recovery."
    )


if __name__ == "__main__":
    main()
