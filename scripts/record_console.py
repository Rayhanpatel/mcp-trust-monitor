#!/usr/bin/env python3
"""Record a read-only tour of an existing local console, never a workflow proof.

uv run --no-project --with playwright python scripts/record_console.py \
  --url-file /private/console-url.txt --output-dir /private/new-tour --mp4

Only same-origin GET requests are allowed. No tool, assessment, approval, verdict,
lesson-preview, publication or other POST action is submitted. The temporary
browser profile, URL/token, HTTP headers and raw network responses are not saved.
The captured viewport can contain the console's actual metadata and lessons:
keep artifacts private until their contents have been reviewed for sharing.
"""
from __future__ import annotations

import argparse
import asyncio
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
from urllib.parse import parse_qs, urlsplit


class RecordingError(Exception):
    """Messages are fixed local classifications, never browser/provider text."""


def private_url(path: Path) -> tuple[str, str]:
    value = path.read_text(encoding="utf-8").strip()
    if len(value) > 4096:
        raise RecordingError("invalid_console_url")
    parsed = urlsplit(value)
    fragment = parse_qs(parsed.fragment, keep_blank_values=True)
    token = fragment.get("token", [])
    if (parsed.scheme != "http" or parsed.hostname != "127.0.0.1"
            or parsed.username or parsed.password or not parsed.port
            or parsed.path not in ("", "/") or parsed.query
            or set(fragment) != {"token"} or len(token) != 1
            or not re.fullmatch(r"[A-Za-z0-9_-]{16,512}", token[0])):
        raise RecordingError("invalid_console_url")
    return value, f"http://127.0.0.1:{parsed.port}"


def write_report(path: Path, report: dict) -> None:
    path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    path.chmod(0o600)


async def record(args, url: str, origin: str, output: Path, report: dict) -> None:
    # Prevent optional Playwright debugging from emitting the URL or auth headers.
    for name in ("DEBUG", "PWDEBUG", "DEBUG_FILE"):
        os.environ.pop(name, None)
    from playwright.async_api import async_playwright
    from importlib.metadata import version

    chrome = args.chrome or ("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
                             if sys.platform == "darwin" else shutil.which("google-chrome"))
    if not chrome or not Path(chrome).is_file():
        raise RecordingError("installed_google_chrome_required")
    report["playwright_version"] = version("playwright")
    started = time.monotonic()
    video_path = None
    with tempfile.TemporaryDirectory(prefix="mtm-console-browser-") as profile:
        async with async_playwright() as playwright:
            context = await playwright.chromium.launch_persistent_context(
                profile, executable_path=chrome, headless=True,
                viewport={"width": args.width, "height": args.height},
                record_video_dir=str(output / "video-parts"),
                record_video_size={"width": args.width, "height": args.height},
                accept_downloads=False, service_workers="block", color_scheme="light")

            async def read_only(route):
                request = route.request
                parsed = urlsplit(request.url)
                if request.method != "GET" or f"{parsed.scheme}://{parsed.netloc}" != origin:
                    report["blocked_requests"] += 1
                    await route.abort()
                    return
                await route.continue_()

            await context.route("**/*", read_only)
            page = context.pages[0] if context.pages else await context.new_page()
            page.set_default_timeout(15000)
            page.on("pageerror", lambda _: report.__setitem__("javascript_errors", report["javascript_errors"] + 1))
            try:
                await page.goto(url, wait_until="domcontentloaded")
                await page.locator("#workspace").wait_for(state="visible")
                await page.locator("#servers button").first.wait_for(state="visible")
                # App captured its per-run token already; remove it from browser history.
                await page.evaluate("history.replaceState(null, '', location.pathname)")

                async def snapshot(label: str) -> None:
                    filename = f"{len(report['shots']) + 1:02d}-{label}.png"
                    await page.screenshot(path=str(output / filename))
                    server = await page.locator("#server-name").inner_text()
                    state = await page.locator("#trust-state").inner_text()
                    count = await page.locator("#catalog-count").inner_text()
                    report["shots"].append({"file": filename,
                        "elapsed_seconds": round(time.monotonic() - started, 2),
                        "selected_server_id_sha256": hashlib.sha256(server.encode()).hexdigest(),
                        "displayed_state": state if state in {"unreviewed", "approved", "pending review", "quarantined", "not observed"} else "unrecognized",
                        "displayed_catalog_count": int(count) if count.isdigit() else None})
                    await page.wait_for_timeout(args.hold_seconds * 1000)

                if args.server_id:
                    selected = page.locator("#servers button").filter(
                        has=page.locator("span").filter(has_text=re.compile("^" + re.escape(args.server_id) + "$")))
                    if await selected.count() != 1:
                        raise RecordingError("requested_server_not_found")
                    await selected.click()
                await snapshot("server-review")
                await page.locator("#after").scroll_into_view_if_needed()
                await snapshot("covered-metadata")
                await page.locator("#catalog").scroll_into_view_if_needed()
                await snapshot("protected-catalog")

                if not args.server_id and await page.locator("#servers button").count() > 1:
                    await page.locator("#servers button").nth(1).click()
                    await page.locator("#server-name").scroll_into_view_if_needed()
                    await snapshot("second-server")

                await page.locator("[data-tab='memory']").click()
                await snapshot("reviewed-memory")
                if await page.locator("#memory-configured").is_visible():
                    await page.locator("#lessons").scroll_into_view_if_needed()
                    await snapshot("lesson-registry")
                    lesson_details = page.locator("#lessons details summary")
                    if await lesson_details.count():
                        # Native <details> is client-side. The preview button is a POST and is not used.
                        await lesson_details.first.click()
                        await snapshot("recorded-lesson-detail")

                await page.locator("[data-tab='history']").click()
                await snapshot("policy-and-delivery")
                await page.locator("#events").scroll_into_view_if_needed()
                await snapshot("recorded-timeline")
                detail = page.locator("#events details summary")
                if await detail.count():
                    await detail.first.click()
                    await snapshot("recorded-event-detail")
                report["status"] = "passed" if not report["blocked_requests"] and not report["javascript_errors"] else "needs_review"
            finally:
                video = page.video
                await context.close()
                if video is not None:
                    video_path = await video.path()

    if video_path:
        target = output / "console-tour.webm"
        Path(video_path).rename(target)
        report["video"] = target.name
        remaining = list((output / "video-parts").iterdir())
        if not remaining:
            (output / "video-parts").rmdir()
    if args.mp4 and video_path:
        ffmpeg = args.ffmpeg or shutil.which("ffmpeg")
        if not ffmpeg:
            raise RecordingError("ffmpeg_required_for_mp4")
        converted = subprocess.run([ffmpeg, "-hide_banner", "-loglevel", "error", "-n",
            "-i", str(output / "console-tour.webm"), "-c:v", "libx264", "-pix_fmt", "yuv420p",
            "-movflags", "+faststart", "-an", str(output / "console-tour.mp4")],
            stdin=subprocess.DEVNULL, capture_output=True, timeout=120)
        if converted.returncode:
            raise RecordingError("mp4_conversion_failed")
        report["mp4"] = "console-tour.mp4"
    report["duration_seconds"] = round(time.monotonic() - started, 2)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url-file", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--server-id", help="optional exact configured server ID to focus on")
    parser.add_argument("--width", type=int, default=1600)
    parser.add_argument("--height", type=int, default=1100)
    parser.add_argument("--hold-seconds", type=float, default=4.0)
    parser.add_argument("--chrome", help="explicit path to an installed Google Chrome executable")
    parser.add_argument("--mp4", action="store_true", help="also make an MP4 with native FFmpeg")
    parser.add_argument("--ffmpeg", help="explicit FFmpeg executable; default searches PATH")
    args = parser.parse_args()
    report = {"schema_version": 1, "kind": "read_only_console_tour", "status": "started",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "mutations_performed": False, "network_policy": "same-origin GET only",
        "background_changes_possible": True, "url_and_token_retained": False,
        "workflow_execution_proof": False, "viewport": {"width": args.width, "height": args.height},
        "javascript_errors": 0, "blocked_requests": 0, "shots": [], "video": None, "mp4": None}
    output = None
    created_output = False
    try:
        if not (390 <= args.width <= 3840 and 600 <= args.height <= 2160
                and math.isfinite(args.hold_seconds) and 0.2 <= args.hold_seconds <= 15):
            raise RecordingError("invalid_recording_dimensions_or_duration")
        url, origin = private_url(args.url_file)
        output = args.output_dir.resolve()
        output.mkdir(parents=True, mode=0o700, exist_ok=False)
        created_output = True
        output.chmod(0o700)
        asyncio.run(record(args, url, origin, output, report))
    except (Exception, KeyboardInterrupt) as exc:
        report["status"] = "failed"
        report["error_type"] = type(exc).__name__
        report["error_code"] = str(exc) if isinstance(exc, RecordingError) else "recording_failed"
    finally:
        # No traceback/exception text: browser errors can contain the private URL.
        if created_output:
            try:
                write_report(output / "recording.json", report)
            except OSError:
                report["status"] = "failed"
                report["error_type"] = "EvidenceWriteError"
                report["error_code"] = "recording_report_unavailable"
    print(json.dumps({"status": report["status"], "kind": report["kind"],
        "screenshots": len(report["shots"]), "video": report["video"], "mp4": report["mp4"],
        "error_type": report.get("error_type"), "error_code": report.get("error_code")}))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
