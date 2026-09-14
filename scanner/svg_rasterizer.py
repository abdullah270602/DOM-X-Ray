"""No-network Chromium rasterization for product-owned SVG frames."""

from __future__ import annotations

from collections.abc import Sequence

from playwright.sync_api import sync_playwright


class SvgRasterizationError(RuntimeError):
    """Raised when a trusted SVG cannot be rasterized exactly."""


def rasterize_svg_frames(svgs: Sequence[str], *, size: int) -> tuple[bytes, ...]:
    """Rasterize bounded SVG strings in one disposable browser context."""

    if isinstance(svgs, (str, bytes)) or not svgs or len(svgs) > 8:
        raise SvgRasterizationError("SVG frame count is outside the trusted envelope")
    if not isinstance(size, int) or isinstance(size, bool) or size <= 0 or size > 2_048:
        raise SvgRasterizationError("SVG raster size is outside the trusted envelope")
    if any(not isinstance(svg, str) or not svg for svg in svgs):
        raise SvgRasterizationError("SVG frames must be non-empty strings")

    results: list[bytes] = []
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            try:
                context = browser.new_context(
                    viewport={"width": size, "height": size},
                    service_workers="block",
                    locale="en-US",
                    timezone_id="UTC",
                    color_scheme="light",
                    reduced_motion="reduce",
                    device_scale_factor=1,
                )
                try:
                    context.route("**/*", lambda route: route.abort())
                    page = context.new_page()
                    page.set_content("<html><head></head><body></body></html>")
                    for svg in svgs:
                        encoded = page.evaluate(
                            """
                            async ({svg, size}) => {
                              const url = URL.createObjectURL(
                                new Blob([svg], {type: "image/svg+xml;charset=utf-8"})
                              );
                              try {
                                const image = new Image();
                                await new Promise((resolve, reject) => {
                                  image.onload = resolve;
                                  image.onerror = () => reject(new Error("SVG decode failed"));
                                  image.src = url;
                                });
                                const canvas = document.createElement("canvas");
                                canvas.width = size;
                                canvas.height = size;
                                const context = canvas.getContext("2d");
                                if (!context) throw new Error("canvas unavailable");
                                context.drawImage(image, 0, 0, size, size);
                                const blob = await new Promise((resolve, reject) =>
                                  canvas.toBlob(
                                    (value) => value
                                      ? resolve(value)
                                      : reject(new Error("PNG encode failed")),
                                    "image/png",
                                  )
                                );
                                return Array.from(new Uint8Array(await blob.arrayBuffer()));
                              } finally {
                                URL.revokeObjectURL(url);
                              }
                            }
                            """,
                            {"svg": svg, "size": size},
                        )
                        results.append(bytes(encoded))
                finally:
                    context.close()
            finally:
                browser.close()
    except Exception as error:
        raise SvgRasterizationError("Chromium SVG rasterization failed") from error
    return tuple(results)


def rasterize_svg_screenshots(svgs: Sequence[str], *, size: int) -> tuple[bytes, ...]:
    """Capture trusted SVG stages as opaque PNGs without JSON byte expansion."""

    if isinstance(svgs, (str, bytes)) or not svgs or len(svgs) > 8:
        raise SvgRasterizationError("SVG frame count is outside the trusted envelope")
    if not isinstance(size, int) or isinstance(size, bool) or size <= 0 or size > 2_048:
        raise SvgRasterizationError("SVG raster size is outside the trusted envelope")
    if any(not isinstance(svg, str) or not svg for svg in svgs):
        raise SvgRasterizationError("SVG frames must be non-empty strings")

    results: list[bytes] = []
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            try:
                context = browser.new_context(
                    viewport={"width": size, "height": size},
                    service_workers="block",
                    locale="en-US",
                    timezone_id="UTC",
                    color_scheme="light",
                    reduced_motion="reduce",
                    device_scale_factor=1,
                    java_script_enabled=False,
                )
                try:
                    context.route("**/*", lambda route: route.abort())
                    page = context.new_page()
                    frame_style = (
                        f"<style>html,body{{margin:0;width:{size}px;height:{size}px;"
                        "overflow:hidden;background:#e9e1d2}}</style>"
                    )
                    for svg in svgs:
                        page.set_content(frame_style + svg, wait_until="commit")
                        results.append(
                            page.screenshot(
                                type="png",
                                animations="disabled",
                                caret="hide",
                                omit_background=False,
                            )
                        )
                finally:
                    context.close()
            finally:
                browser.close()
    except Exception as error:
        raise SvgRasterizationError("Chromium SVG screenshot rasterization failed") from error
    return tuple(results)


__all__ = [
    "SvgRasterizationError",
    "rasterize_svg_frames",
    "rasterize_svg_screenshots",
]
