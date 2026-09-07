"""Static worker outcomes for the public-scan transport contract."""

from __future__ import annotations

import copy
import json
import os
import sys
import time
from pathlib import Path


RESULT_NONCE_ENV = "DOM_X_RAY_WORKER_RESULT_NONCE"
REQUESTED_URL_OVERRIDE_ENV = "DOM_X_RAY_FIXTURE_REQUESTED_URL"
OVERSIZED_RESULT_BYTES = 4_000_100


def _atomic_json(path: Path, payload: object) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(payload, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    os.replace(temporary, path)


def main() -> None:
    if len(sys.argv) != 4:
        raise SystemExit("usage: scan_transport_worker_fixture.py MODE RECORD RESULT")
    mode, record_value, result_value = sys.argv[1:]
    record_path = Path(record_value)
    result_path = Path(result_value)
    nonce = os.environ.get(RESULT_NONCE_ENV, "")

    if mode == "crash":
        raise SystemExit(17)
    if mode == "timeout":
        time.sleep(60)
        return
    if mode == "oversized-result":
        result_path.write_text("x" * OVERSIZED_RESULT_BYTES, encoding="utf-8")
        return
    if mode == "nonregular-result":
        result_path.mkdir()
        return

    record = json.loads(record_path.read_text(encoding="utf-8"))
    if mode == "rewrite-requested-url":
        requested_url = os.environ.get(REQUESTED_URL_OVERRIDE_ENV)
        if not requested_url:
            raise ValueError("missing requested URL override")
        record = copy.deepcopy(record)
        record["requestedUrl"] = requested_url
    elif mode == "schema-invalid":
        record = copy.deepcopy(record)
        record.pop("mappingVersion")
    elif mode == "semantic-invalid":
        record = copy.deepcopy(record)
        record["resources"].append(copy.deepcopy(record["resources"][0]))

    if mode == "invalid-nonce":
        supervisor_nonce = "wrong"
    else:
        supervisor_nonce = nonce

    if mode == "malformed-envelope":
        payload: object = {
            "supervisorNonce": supervisor_nonce,
            "result": {"unexpected": True},
        }
    elif mode in {
        "valid",
        "rewrite-requested-url",
        "schema-invalid",
        "semantic-invalid",
        "invalid-nonce",
    }:
        payload = {
            "supervisorNonce": supervisor_nonce,
            "result": {"record": record},
        }
    else:
        raise SystemExit(f"unknown mode: {mode}")
    _atomic_json(result_path, payload)


if __name__ == "__main__":
    main()
