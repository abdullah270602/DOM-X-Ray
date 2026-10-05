"""Native mount-root, host file/socket denial, and hard-kill cleanup evidence."""

import json
import os
from pathlib import Path
import shutil
import socket
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scanner.browser_namespace import write_namespace_wrapper
import scanner.browser_namespace as namespace
from scanner.namespace_bridge import NamespaceBridge
from scanner.browser_egress_proxy import run_browser_egress_proxy
from scanner.destination_policy import DestinationPolicy
from scanner.origin_exchange import OriginExchange
from scanner.worker_supervisor import run_worker_command
from scripts.verify_network_namespace import Origin, members


def require(value, message):
    if not value:
        raise AssertionError(message)


def main():
    require(sys.platform == "linux", "native Linux filesystem proof required")
    for hang in (False, True):
        with tempfile.TemporaryDirectory(prefix="dxr-fs-", dir="/tmp") as temporary:
            directory = Path(temporary)
            home, runtime = directory / "browser", directory / "runtime"
            home.mkdir(mode=0o700)
            runtime.mkdir(mode=0o700)
            for name in (".pki", "config", "data", "cache", "tmp"):
                (home / name).mkdir(mode=0o700)
            fixture = runtime / "probe.py"
            shutil.copyfile(ROOT / "fixtures/worker/filesystem_namespace_fixture.py", fixture)
            secret = directory / "scanner-signing-key-canary"
            secret.write_bytes(b"host-secret-canary")
            operator_home = directory / "operator-home-canary"
            operator_home.write_bytes(b"host-home-canary")
            immutable = runtime / "runtime-canary"
            immutable.write_bytes(b"immutable")
            (home / ".pki/nssdb").mkdir(mode=0o700)
            nss = home / ".pki/nssdb/cert9.db"
            nss.write_bytes(b"public-root-only")
            escape = home / "data" / "escape-link"
            escape.symlink_to(secret)
            hidden_socket = directory / "other.sock"
            abstract = "dxr-hidden-" + directory.name
            with socket.socket(socket.AF_UNIX) as listener, socket.socket(socket.AF_UNIX) as abstract_listener:
                listener.bind(str(hidden_socket))
                abstract_listener.bind("\0" + abstract)
                for server in (listener, abstract_listener):
                    server.listen()
                    server.setblocking(False)
                contacts = []
                policy = DestinationPolicy(lambda h, p: ["1.1.1.1"])
                exchange = OriginExchange(policy, user_agent="DOM-X-Ray-Filesystem-Fixture/0.1",
                    connector=lambda grant, **kwargs: Origin(contacts))
                with run_browser_egress_proxy(initial_url="http://xray.test/", policy=policy, exchange=exchange,
                        tls_context=lambda h: None) as proxy, NamespaceBridge(proxy.server_address[1], temporary_parent=directory) as bridge:
                    config, result, marker = home / "data/config.json", home / "data/result.json", home / "data/marker.json"
                    config.write_text(json.dumps({"hiddenFiles": [str(secret), str(operator_home), str(escape)],
                        "readonlyFiles": [str(immutable), "/etc/hosts"], "privateNssFile": str(nss),
                        "writableFile": str(home / "data/writable"),
                        "hiddenSocket": str(hidden_socket), "abstractSocket": abstract, "marker": str(marker), "hang": hang}))
                    original_entrypoint = namespace.__file__
                    try:
                        namespace.__file__ = str(ROOT / "fixtures/worker/filesystem_diagnostic_entry.py")
                        wrapper = write_namespace_wrapper(home, executable=Path("/usr/bin/python3"), bridge_path=bridge.path,
                            port=proxy.server_address[1], preserve_pipes=False, filesystem_runtime_directories=[runtime])
                    finally:
                        namespace.__file__ = original_entrypoint
                    diagnostic = home / "data/setup-diagnostic.txt"
                    run = run_worker_command([sys.executable, "-I", str(ROOT / "fixtures/worker/detached_namespace_parent.py"),
                        "--leak-directory", str(directory), str(wrapper), "-I", str(fixture), str(config), str(result)], result_path=result,
                        environment={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "DXR_FILESYSTEM_DIAGNOSTIC": str(diagnostic)},
                        deadline_seconds=4 if hang else 10)
                    detail = diagnostic.read_text() if diagnostic.exists() else "no trusted setup diagnostic"
                    require(run.outcome == ("timeout" if hang else "completed"), f"filesystem worker outcome {run.outcome}: {detail}")
                    require(marker.exists(), "filesystem child did not reach boundary proof")
                    proof = json.loads(marker.read_text())
                    require(proof.get('scratchExecutionDenied') is True, 'writable scratch exec denial missing')
                    require(proof["mount"] != os.readlink("/proc/self/ns/mnt")
                            and proof["ipc"] != os.readlink("/proc/self/ns/ipc"), "host mount/IPC namespace reused")
                    require(proof["nestedRemountDenied"], "nested namespace remount denial missing")
                    print(f"Nested user namespace created={proof['nestedNamespaceCreated']}; runtime remount denied; hang={hang}", flush=True)
                    stopped = time.monotonic() + 0.4
                    while members(proof["pid"]) and time.monotonic() < stopped:
                        time.sleep(0.01)
                    require(not members(proof["pid"]), "filesystem namespace survived bounded exit observation")
                    require(len(contacts) == 1 and run.artifact_eligible != hang, "proxy/admission boundary drifted")
                    for server in (listener, abstract_listener):
                        try:
                            connection, _ = server.accept()
                        except BlockingIOError:
                            pass
                        else:
                            connection.close()
                            raise AssertionError("host Unix socket received a connection")
                require(secret.read_bytes() == b"host-secret-canary" and immutable.read_bytes() == b"immutable"
                        and nss.read_bytes() == b"public-root-only", "host/runtime canary modified")
                require(not list((home / "filesystem-root").iterdir()), "filesystem mounts leaked into parent namespace")
                if not hang:
                    # The trusted diagnostic entrypoint exercises the real setup
                    # guards; Python's own unknown-option failure is not evidence.
                    nonempty = directory / "playwright_chromiumdev_profile-foreign"
                    nonempty.mkdir(mode=0o700)
                    (nonempty / "secret").write_bytes(b"not-a-fresh-profile")
                    bad_name = directory / "not-playwright-profile"
                    bad_name.mkdir(mode=0o700)
                    profile_link = directory / "playwright_chromiumdev_profile-link"
                    profile_link.symlink_to(bad_name, target_is_directory=True)
                    cases = [("nonempty", ["--user-data-dir=" + str(nonempty)], "browser-filesystem-profile"),
                             ("name", ["--user-data-dir=" + str(bad_name)], "browser-filesystem-profile"),
                             ("symlink", ["--user-data-dir=" + str(profile_link)], "browser-filesystem-private-directory")]
                    for label, arguments, expected_error in cases:
                        diagnostic.unlink(missing_ok=True)
                        rejected = run_worker_command([str(wrapper), *arguments], result_path=home / f"data/rejected-{label}.json",
                            environment={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "DXR_FILESYSTEM_DIAGNOSTIC": str(diagnostic)},
                            deadline_seconds=5)
                        require(rejected.outcome == "crashed" and not rejected.artifact_eligible
                                and diagnostic.exists() and expected_error in diagnostic.read_text(), "profile guard failed at wrong boundary")
                    with NamespaceBridge(12345, temporary_parent=directory) as invalid_setup_bridge:
                        namespace_config = home / "namespace-config.json"
                        payload = json.loads(namespace_config.read_text())
                        payload["bridgePath"] = str(invalid_setup_bridge.path)
                        namespace_config.write_text(json.dumps(payload))
                        for label in ("unknown", "symlink", "oversized"):
                            extra = nss.parent / ("unexpected.pem" if label == "unknown" else "key4.db")
                            if label == "symlink":
                                extra.symlink_to(secret)
                            elif label == "unknown":
                                extra.write_bytes(b"not-an-NSS-file")
                            else:
                                extra.write_bytes(b"x" * 1_048_577)
                            diagnostic.unlink(missing_ok=True)
                            rejected = run_worker_command([str(wrapper), "-I", str(fixture), str(config)],
                                result_path=home / f"data/rejected-nss-{label}.json",
                                environment={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "DXR_FILESYSTEM_DIAGNOSTIC": str(diagnostic)},
                                deadline_seconds=5)
                            extra.unlink()
                            require(rejected.outcome == "crashed" and not rejected.artifact_eligible and diagnostic.exists()
                                    and "browser-filesystem-nss-files" in diagnostic.read_text(), "NSS copy guard failed at wrong boundary")
    print("Verified native private mount/IPC root, detached old root, hidden host-file/proc-root/symlink canaries, "
          "read-only runtime, private writable NSS snapshot with unchanged host database, scoped writable browser data, hidden pathname/abstract Unix sockets, "
          "fixed proxy socket access, nested-user-namespace runtime-remount denial, zero capabilities, and normal/timeout namespace cleanup. "
          "See the separate actual Chromium integration proof; runtime-image integrity and whole-worker quotas remain open.")


if __name__ == "__main__":
    main()
