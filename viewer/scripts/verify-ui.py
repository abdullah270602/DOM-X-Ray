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
        page.on(
            "console",
            lambda message: browser_errors.append(f"console: {message.text}")
            if message.type == "error"
            else None,
        )
        page.on(
            "requestfailed",
            lambda request: browser_errors.append(
                f"request failed: {request.url} ({request.failure})"
            ),
        )
        page.goto(f"{BASE_URL}?fixture=image-heavy&time=5000&mode=weight")
        try:
            page.get_by_role("heading", name="DOM X-RAY").wait_for()
        except Exception as error:
            raise AssertionError(f"viewer shell did not mount: {browser_errors}") from error
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
        page.get_by_role("button", name="START X-RAY").click()
        require(
            page.get_by_role("alert").text_content() == "Enter a complete public HTTP or HTTPS URL.",
            "invalid URL recovery was not explicit",
        )

        page.locator("#scan-url").fill("https://gallery.example/")
        page.get_by_role("button", name="START X-RAY").click()
        page.get_by_text("IMMUTABLE RESULT READY", exact=True).wait_for(timeout=10_000)
        page.wait_for_url("**/r/r_*", timeout=10_000)
        admitted_result_url = page.url
        require(
            page.get_by_text(image_runtime["presentation"]["finding"]["statement"], exact=True).count()
            == 1,
            "API result did not render its admitted hero",
        )
        require(page.get_by_text("ADMITTED", exact=True).count() == 1, "transport admission was not visible")
        page.reload()
        page.get_by_text(image_runtime["presentation"]["finding"]["statement"], exact=True).wait_for()
        require(page.url == admitted_result_url, "stable result reload changed its route")

        error_count_before_disabled_request = len(browser_errors)
        page.locator("#scan-url").fill("https://www.example.org/")
        page.get_by_role("button", name="START X-RAY").click()
        page.get_by_role("alert").wait_for()
        require(
            page.get_by_role("alert").text_content()
            == "Public scanning is disabled in this local safety proof.",
            "disabled public scanner did not preserve the current result with clear recovery",
        )
        disabled_request_errors = browser_errors[error_count_before_disabled_request:]
        require(
            all("status of 503" in message for message in disabled_request_errors),
            f"disabled request emitted an unexpected browser error: {disabled_request_errors}",
        )
        del browser_errors[error_count_before_disabled_request:]

        page.go_back()
        page.get_by_text("FIXTURE", exact=True).wait_for()
        require("fixture=clean" in page.url, "browser back did not restore the fixture route")
        page.go_forward()
        page.get_by_text("ADMITTED", exact=True).wait_for()
        require(page.url == admitted_result_url, "browser forward did not restore the immutable result")

        missing_result_id = "r_ffffffffffffffffffffffffffffffff"
        missing_error_count = len(browser_errors)
        page.goto(f"{BASE_URL.rstrip('/')}/r/{missing_result_id}")
        page.get_by_role("alert").wait_for()
        require(
            page.get_by_role("alert").text_content()
            == "This immutable result is unavailable. Choose a seeded capture below.",
            "missing result route did not expose explicit recovery",
        )
        require(
            page.get_by_text("FIXTURE", exact=True).count() == 1
            and page.get_by_text("ADMITTED", exact=True).count() == 0,
            "missing result route relabeled its fallback fixture as admitted",
        )
        missing_request_errors = browser_errors[missing_error_count:]
        require(
            all("status of 404" in message for message in missing_request_errors),
            f"missing result emitted an unexpected browser error: {missing_request_errors}",
        )
        del browser_errors[missing_error_count:]

        corrupt_etag = f'"{"0" * 64}"'
        page.route(
            "**/api/results/*",
            lambda route: route.fulfill(
                status=200,
                content_type="application/json",
                headers={"ETag": corrupt_etag},
                body="{}",
            ),
        )
        page.locator("#scan-url").fill("https://gallery.example/")
        page.get_by_role("button", name="START X-RAY").click()
        bundle_error = (
            "The scan finished, but its immutable result could not be verified. "
            "Your current result is unchanged."
        )
        page.get_by_text(bundle_error, exact=True).wait_for(timeout=10_000)
        require(
            page.get_by_text("IMMUTABLE RESULT READY", exact=True).count() == 0,
            "failed bundle admission left a ready job visible",
        )
        require(
            page.get_by_text("FIXTURE", exact=True).count() == 1,
            "failed bundle admission displaced the current valid fixture",
        )
        page.unroute("**/api/results/*")
        browser.close()

    require(not browser_errors, f"browser errors: {browser_errors}")
    print(
        "Verified image-heavy and third-party runtime binding, deterministic route state, "
        "evidence drawer, partial status, reduced-motion steps, text fallback, URL recovery, "
        "transport-backed submission, immutable reload and history restoration, disabled-public-scanner honesty, "
        "missing-result fallback truthfulness, and corrupt-bundle recovery."
    )


if __name__ == "__main__":
    main()
