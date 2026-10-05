"""Adversarial resolver helper outputs; never a production resolver."""

import json
import os
from pathlib import Path
import subprocess
import sys
import time

mode, query_path, result_path = sys.argv[1], Path(sys.argv[2]), Path(sys.argv[3])
query = json.loads(query_path.read_text())
assert set(query) == {"hostname", "port"}
nonce = os.environ["DOM_X_RAY_WORKER_RESULT_NONCE"]
addresses = ["1.1.1.1", "2606:4700:4700::1111"]
if mode == "private":
    addresses = ["127.0.0.1"]
elif mode == "mixed":
    addresses = ["1.1.1.1", "10.0.0.1"]
elif mode == "mixed-family":
    addresses = ["1.1.1.1", "fe80::1"]
elif mode == "duplicates":
    addresses = ["1.1.1.1", "1.1.1.1"]
elif mode == "overflow":
    addresses = [f"1.1.1.{index}" for index in range(1, 18)]
elif mode == "invalid-address":
    addresses = ["private-provider-message"]
elif mode == "noncanonical":
    addresses = ["2606:4700:4700:0:0:0:0:1111"]
elif mode == "wrong-type":
    addresses = [True]
elif mode == "scope":
    addresses = ["fe80::1%interface"]
elif mode == "empty":
    addresses = []
result = {"outcome": "resolved", "addresses": addresses}
if mode == "unavailable":
    result = {"outcome": "unavailable", "addresses": []}
elif mode == "answer-limit":
    result = {"outcome": "answer-limit", "addresses": []}
elif mode == "invalid-answer":
    result = {"outcome": "invalid-answer", "addresses": []}
elif mode == "extra-result":
    result["providerPrivateText"] = "fixture-secret"
elif mode == "invalid-outcome":
    result["outcome"] = []
elif mode == "failure-addresses":
    result["outcome"] = "unavailable"
payload = {"supervisorNonce": nonce, "result": result}
if mode == "wrong-nonce":
    payload["supervisorNonce"] = "stale-nonce"
elif mode == "extra-envelope":
    payload["hostname"] = query["hostname"]
elif mode == "oversized":
    payload["padding"] = "x" * 2_048
encoded = json.dumps(payload).encode()
if mode == "duplicate-field":
    encoded = (f'{{"supervisorNonce":"{nonce}","result":{{"outcome":"resolved",'
               '"addresses":["10.0.0.1"],"addresses":["1.1.1.1"]}}').encode()
if mode == "truncated":
    encoded = encoded[:len(encoded) // 2]
if mode == "directory":
    result_path.mkdir()
elif mode == "symlink":
    result_path.symlink_to(query_path)
elif mode != "no-artifact":
    result_path.write_bytes(encoded)
if mode == "crash":
    raise SystemExit(2)
if mode == "stdout":
    os.write(1, b"fixture-provider-private-text" * 50_000)
if mode == "hang-descendant":
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    (result_path.parent / "child.json").write_text(json.dumps({"pid": child.pid}))
    time.sleep(30)
if mode == "hang-after-result":
    time.sleep(30)
