"""Deterministic origin/DNS injection for the real supervised Linux lifecycle."""

import json
import faulthandler
import os
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from scanner.egress_capture_worker import load_capture_config, capture_granted_page, publish_worker_result
from scanner.worker_supervisor import RESULT_NONCE_ENV
from scripts.verify_browser_egress_proxy import FixtureOrigin


def descendants():
    rows = {}
    for path in Path("/proc").iterdir():
        if not path.name.isdecimal():
            continue
        try:
            text = (path / "stat").read_text()
            fields = text[text.rfind(")") + 2:].split()
            rows[int(path.name)] = (int(fields[1]), fields[19], "chrome" in text or "headless" in text)
        except (OSError, ValueError, IndexError):
            continue
    owned, pending = [], [os.getpid()]
    while pending:
        parent = pending.pop()
        for pid, (ppid, started, chromium) in rows.items():
            if ppid == parent:
                owned.append({"pid": pid, "startTicks": started, "chromium": chromium})
                pending.append(pid)
    return owned


def main():
    grant, runtime = load_capture_config(Path(sys.argv[1]))
    result_path = Path(sys.argv[2])
    requests, grants, dns = [], [], []
    phase = Path(os.environ["DOM_XRAY_FIXTURE_MARKER"]).with_suffix(".phase.json")
    trace = phase.with_suffix(".trace.txt").open("w")
    faulthandler.dump_traceback_later(10, file=trace)
    phase.write_text(json.dumps({"phase": "config-loaded", "hang": os.environ.get("DOM_XRAY_FIXTURE_HANG")}))
    def connector(destination, **_kwargs):
        grants.append(destination)
        phase.write_text(json.dumps({"phase": "origin-contact", "requestCount": len(grants), "hostname": destination.hostname}))
        return FixtureOrigin(destination, requests)
    def after_capture(probe, home):
        if grants[0] != grant.destination or any(value.addresses != ("1.0.0.1",) for value in grants[1:]):
            raise AssertionError("fixture grant pinning drifted")
        marker = {"profileHome": str(home), "configHome": str(result_path.parent),
                  "requestCount": len(requests), "lookupCount": len(dns),
                  "descendants": descendants(), "status": probe.record["status"]}
        if "AWS_SECRET_ACCESS_KEY" in os.environ or "PYTHONPATH" in os.environ:
            raise AssertionError("worker inherited application secrets/package overrides")
        Path(os.environ["DOM_XRAY_FIXTURE_MARKER"]).write_text(json.dumps(marker))
        phase.write_text(json.dumps({"phase": "capture-complete", "hang": os.environ.get("DOM_XRAY_FIXTURE_HANG")}))
        if os.environ.get("DOM_XRAY_FIXTURE_HANG") == "1":
            time.sleep(60)
    record = capture_granted_page(grant, runtime,
        resolver=lambda h, p: dns.append((h, p)) or ["1.0.0.1"],
        connector=connector, after_capture=after_capture)
    publish_worker_result(result_path, os.environ[RESULT_NONCE_ENV], record)
    faulthandler.cancel_dump_traceback_later()
    trace.close()


if __name__ == "__main__":
    main()
