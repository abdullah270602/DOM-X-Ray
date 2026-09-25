"""Verify the local DOM X-Ray viewer against its public interaction contract."""

from __future__ import annotations

import base64
import hashlib
import json
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

from playwright.sync_api import Page, Request, sync_playwright


BASE_URL = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:4173/"
ROOT = Path(__file__).resolve().parents[2]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def observe_browser(page: Page, browser_errors: list[str]) -> None:
    def record_request_failure(request: Request) -> None:
        failure = request.failure
        # Playwright reports deliberate route changes, lazy-module cancellation,
        # and blob downloads as ERR_ABORTED. Each critical request below still
        # has a user-visible completion assertion, so these cancellations are
        # noise rather than permission to ignore a missing result.
        if failure and "ERR_ABORTED" in failure:
            return
        browser_errors.append(f"request failed: {request.url} ({failure})")

    page.on("pageerror", lambda error: browser_errors.append(str(error)))
    page.on(
        "console",
        lambda message: browser_errors.append(f"console: {message.text}")
        if message.type == "error"
        else None,
    )
    page.on(
        "requestfailed",
        record_request_failure,
    )


def publish_result(page: Page, target_url: str, expected_statement: str) -> None:
    if page.url != "about:blank":
        page.wait_for_load_state("networkidle", timeout=10_000)
    page.goto(f"{BASE_URL}?fixture=clean&fallback=text&time=5000")
    page.locator("#scan-url").fill(target_url)
    page.get_by_role("button", name="START X-RAY").click()
    page.get_by_text("IMMUTABLE RESULT READY", exact=True).wait_for(timeout=45_000)
    page.wait_for_url("**/r/r_*", timeout=45_000)
    require(page.get_by_text(expected_statement, exact=True).count() == 1, "published hero did not render")
    page.wait_for_load_state("networkidle", timeout=10_000)


def rendered_image_digest(page: Page, data_url: str) -> dict[str, object]:
    return page.evaluate(
        """
        async (source) => {
          const image = await new Promise((resolve, reject) => {
            const element = new Image();
            element.onload = () => resolve(element);
            element.onerror = () => reject(new Error("image decode failed"));
            element.src = source;
          });
          const canvas = document.createElement("canvas");
          canvas.width = image.naturalWidth;
          canvas.height = image.naturalHeight;
          const context = canvas.getContext("2d");
          if (!context) throw new Error("canvas unavailable");
          context.drawImage(image, 0, 0);
          const pixels = context.getImageData(0, 0, canvas.width, canvas.height).data;
          const digest = await crypto.subtle.digest("SHA-256", pixels);
          return {
            width: image.naturalWidth,
            height: image.naturalHeight,
            digest: Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, "0")).join(""),
          };
        }
        """,
        data_url,
    )


def verify_published_share(
    page: Page,
    target_url: str,
    runtime: dict[str, object],
) -> tuple[int, float, str, int, float, str, int, float, str]:
    publish_result(page, target_url, runtime["presentation"]["finding"]["statement"])
    result_id = urlsplit(page.url).path.rsplit("/", 1)[-1]
    bundle_response = page.request.get(f"{BASE_URL.rstrip('/')}/api/results/{result_id}")
    require(bundle_response.status == 200, "published result bundle was unavailable")
    bundle = bundle_response.json()
    published_result = bundle["result"]
    poster_descriptor = published_result["exports"]["poster"]
    artifact = poster_descriptor["artifact"]
    require(
        poster_descriptor["state"] == "ready"
        and isinstance(artifact, dict)
        and isinstance(artifact.get("sha256"), str)
        and isinstance(artifact.get("byteLength"), int),
        "published result did not register a ready poster artifact",
    )
    poster_url = f"{BASE_URL.rstrip('/')}/api/results/{result_id}/poster.png"
    poster_response = page.request.get(poster_url)
    require(poster_response.status == 200, "registered poster artifact was unavailable")
    poster_payload = poster_response.body()
    poster_headers = {key.lower(): value for key, value in poster_response.headers.items()}
    poster_sha256 = hashlib.sha256(poster_payload).hexdigest()
    require(
        poster_payload.startswith(b"\x89PNG\r\n\x1a\n")
        and len(poster_payload) == artifact["byteLength"]
        and poster_sha256 == artifact["sha256"]
        and poster_headers.get("content-type") == "image/png"
        and poster_headers.get("etag") == f'"{artifact["sha256"]}"'
        and poster_headers.get("cache-control") == "no-store",
        "poster response did not match its immutable manifest binding",
    )
    video_descriptor = published_result["exports"]["video"]
    video_artifact = video_descriptor["artifact"]
    require(
        video_descriptor["state"] == "ready"
        and video_descriptor["durationMs"] == 5_000
        and isinstance(video_artifact, dict)
        and isinstance(video_artifact.get("sha256"), str)
        and isinstance(video_artifact.get("byteLength"), int),
        "published result did not register a ready five-second video artifact",
    )
    video_url = f"{BASE_URL.rstrip('/')}/api/results/{result_id}/video.mp4"
    video_response = page.request.get(video_url)
    require(video_response.status == 200, "registered video artifact was unavailable")
    video_payload = video_response.body()
    video_headers = {key.lower(): value for key, value in video_response.headers.items()}
    video_sha256 = hashlib.sha256(video_payload).hexdigest()
    require(
        len(video_payload) >= 12
        and video_payload[4:8] == b"ftyp"
        and len(video_payload) == video_artifact["byteLength"]
        and video_sha256 == video_artifact["sha256"]
        and video_headers.get("content-type") == "video/mp4"
        and video_headers.get("etag") == f'"{video_artifact["sha256"]}"'
        and video_headers.get("cache-control") == "no-store",
        "video response did not match its immutable manifest binding",
    )

    require(page.get_by_role("button", name="SHARE RESULT").count() == 1, "published artifact share action was missing")
    page.get_by_role("button", name="SHARE RESULT").click()
    page.get_by_role("dialog", name="SHARE RESULT").wait_for()
    page.get_by_text("SERVER COPY MATCHES IMMUTABLE MANIFEST", exact=True).wait_for(timeout=20_000)
    page.get_by_text("MOTION COPY MATCHES IMMUTABLE MANIFEST", exact=True).wait_for(timeout=20_000)
    require(page.get_by_role("button", name="COPY PNG LINK").count() == 1, "verified poster URL action was missing")
    preview = page.locator(".share-preview img")
    preview.wait_for()
    preview_src = preview.get_attribute("src")
    require(
        preview_src is not None and preview_src.startswith("blob:"),
        "share preview did not switch to the digest-verified hosted PNG",
    )
    require(
        page.get_by_text("1080 × 1080 PNG · VERIFIED HOSTED ARTIFACT", exact=False).count() == 1,
        "share preview did not identify its verified hosted source",
    )

    preview_render = rendered_image_digest(page, preview_src)
    require(
        preview_render["width"] == 1080 and preview_render["height"] == 1080,
        "share preview did not decode to 1080x1080",
    )
    server_data_url = "data:image/png;base64," + base64.b64encode(poster_payload).decode("ascii")
    server_render = rendered_image_digest(page, server_data_url)
    require(
        preview_render["digest"] == server_render["digest"],
        "verified share preview pixels diverged from the registered poster",
    )

    page.get_by_role("button", name="5 SEC MOTION").click()
    motion_preview = page.locator(".share-preview video")
    motion_preview.wait_for()
    motion_src = motion_preview.get_attribute("src")
    require(
        motion_src is not None
        and motion_src.startswith("blob:")
        and motion_preview.get_attribute("controls") is not None,
        "share preview did not expose the verified interactive MP4",
    )

    video_started = time.monotonic()
    with page.expect_download(timeout=10_000) as video_download_info:
        page.get_by_role("button", name="DOWNLOAD 5 SEC VIDEO").click()
    video_download = video_download_info.value
    video_path = video_download.path()
    require(video_path is not None, "video download did not produce a file")
    downloaded_video = Path(video_path).read_bytes()
    video_elapsed = time.monotonic() - video_started
    require(video_elapsed <= 10, f"video download exceeded the local 10 second bound ({video_elapsed:.3f}s)")
    require(
        video_download.suggested_filename.endswith(".mp4")
        and downloaded_video == video_payload
        and len(downloaded_video) <= 8_000_000,
        "downloaded video diverged from the registered MP4 artifact",
    )
    page.get_by_text("VERIFIED 5 SEC MP4 · DOWNLOAD STARTED", exact=True).wait_for()

    limitation = published_result["limitations"][0]["message"] if published_result["limitations"] else None

    def download_once() -> tuple[int, float, str]:
        started = time.monotonic()
        with page.expect_download(timeout=10_000) as download_info:
            page.get_by_role("button", name="DOWNLOAD POSTER").click()
        download = download_info.value
        path = download.path()
        require(path is not None, "poster download did not produce a file")
        payload = Path(path).read_bytes()
        elapsed = time.monotonic() - started
        require(elapsed <= 10, f"poster download exceeded the local 10 second bound ({elapsed:.3f}s)")
        require(
            download.suggested_filename.endswith(".png")
            and payload.startswith(b"\x89PNG\r\n\x1a\n"),
            "poster download was not a PNG file",
        )
        require(len(payload) <= 5_000_000, f"poster PNG exceeded 5 MB ({len(payload)} bytes)")
        require(payload == poster_payload, "downloaded poster bytes diverged from the registered artifact")
        encoded_png = "data:image/png;base64," + base64.b64encode(payload).decode("ascii")
        rendered = rendered_image_digest(page, encoded_png)
        require(
            rendered["width"] == 1080 and rendered["height"] == 1080,
            "poster PNG did not decode to 1080x1080",
        )
        require(
            rendered["digest"] == preview_render["digest"],
            "poster PNG pixels diverged from the rendered share preview",
        )
        page.get_by_text("VERIFIED HOSTED PNG · DOWNLOAD STARTED", exact=True).wait_for()
        return len(payload), elapsed, rendered["digest"]

    first = download_once()
    second = download_once()
    require(first[2] == second[2], "two poster downloads had different rendered pixel digests")
    if published_result["status"] == "partial":
        require(limitation, "partial export lost its exact limitation binding")
    page.get_by_role("button", name="CLOSE SHARE RESULT").click()
    return (*first, *second, len(downloaded_video), video_elapsed, video_sha256)


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
        browser_version = browser.version
        page = browser.new_page(viewport={"width": 1440, "height": 900})
        observe_browser(page, browser_errors)
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
        page.get_by_text("IMMUTABLE RESULT READY", exact=True).wait_for(timeout=45_000)
        page.wait_for_url("**/r/r_*", timeout=45_000)
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

        image_downloads = verify_published_share(
            page,
            "https://gallery.example/",
            image_runtime,
        )

        share_page = browser.new_page(viewport={"width": 1440, "height": 900})
        observe_browser(share_page, browser_errors)
        third_downloads = verify_published_share(
            share_page,
            "https://newsroom.example/",
            third_runtime,
        )
        publish_result(
            share_page,
            "https://clean.example/",
            clean_runtime["presentation"]["finding"]["statement"],
        )
        require(
            share_page.get_by_role("button", name="SHARE RESULT").count() == 0
            and share_page.get_by_role("button", name="DOWNLOAD POSTER").count() == 0,
            "published clean result exposed a poster action",
        )
        require(
            share_page.get_by_role("button", name="COPY RESULT LINK").count() == 1,
            "published clean result did not remain link-only",
        )
        share_page.close()

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
            missing_request_errors
            and all("status of 404" in message for message in missing_request_errors),
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
        "missing-result fallback truthfulness, corrupt-bundle recovery, and manifest-verified hosted poster/video exports."
    )
    print(
        f"Local Chromium {browser_version} share-export evidence: "
        f"image-heavy PNGs {image_downloads[0]} bytes/{image_downloads[1]:.3f}s and "
        f"{image_downloads[3]} bytes/{image_downloads[4]:.3f}s, digest {image_downloads[2]}; "
        f"MP4 {image_downloads[6]} bytes/{image_downloads[7]:.3f}s, digest {image_downloads[8]}; "
        f"third-party-heavy PNGs {third_downloads[0]} bytes/{third_downloads[1]:.3f}s and "
        f"{third_downloads[3]} bytes/{third_downloads[4]:.3f}s, digest {third_downloads[2]}; "
        f"MP4 {third_downloads[6]} bytes/{third_downloads[7]:.3f}s, digest {third_downloads[8]}."
    )


if __name__ == "__main__":
    main()
