"""Native Linux supervised capture, grant-file and cleanup integration proof."""

from dataclasses import replace
import argparse
import json
import os
from pathlib import Path
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from jsonschema import Draft202012Validator, FormatChecker
from scanner.destination_policy import DestinationPolicy
from scanner.egress_capture_worker import CaptureRuntime, capture_granted_page, create_capture_launch, load_capture_config
from scanner.scan_transport import run_public_scan_transport, PublicScanGrant
from scripts.validate_fixtures import validate_semantics


def require(value, message):
    if not value:
        raise AssertionError(message)


def alive(row):
    try:
        text = Path(f"/proc/{row['pid']}/stat").read_text()
        fields = text[text.rfind(")") + 2:].split()
        return fields[19] == row["startTicks"] and fields[0] != "Z"
    except (OSError, IndexError):
        return False


def main():
    require(sys.platform == "linux", "native worker proof requires Linux")
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime-root", type=Path, default=ROOT / ".dom-xray-data/linux-trust",
                        help="explicit trusted prepared runtime, optionally on native Linux storage")
    parser.add_argument('--container-limits', action='store_true',
                        help='require the exact bounded Docker fixture limits and host-side process flags')
    options = parser.parse_args()
    base = options.runtime_root.resolve(strict=True)
    if options.container_limits:
        for name, expected in (('memory.max', '1073741824'), ('memory.swap.max', '0'),
                               ('pids.max', '128'), ('cpu.max', '100000 100000')):
            require((Path('/sys/fs/cgroup') / name).read_text().strip() == expected,
                    f'container kernel limit mismatch: {name}')
        status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
        require(os.getuid() == 10001 and status['NoNewPrivs'].strip() == '1' and status['Seccomp'].strip() == '2'
                and all(int(status[key].strip(), 16) == 0 for key in ('CapEff', 'CapPrm', 'CapBnd')),
                'container verifier identity/capabilities/filter mismatch')
    runtime = CaptureRuntime(Path("/usr/bin/openssl"), base / "root/usr/bin/certutil",
        base / "browsers/chromium_headless_shell-1187/chrome-linux/headless_shell",
        base / "root/usr/lib/x86_64-linux-gnu")
    packages = base / "python"
    fixture = ROOT / "fixtures/worker/egress_capture_fixture.py"
    schema = Draft202012Validator(json.loads((ROOT / "docs/SCAN_RECORD.schema.json").read_text()),
                                  format_checker=FormatChecker())
    with tempfile.TemporaryDirectory(prefix="dxr-egress-", dir="/tmp") as temporary:
        directory = Path(temporary)
        for hang, expected in ((False, "admitted"), (True, "worker-timeout")):
            marker_path = directory / ("timeout.json" if hang else "complete.json")
            initial_dns, launch_environments = [], []
            def launch(grant, result_path):
                configured = create_capture_launch(grant, result_path, runtime,
                    packages_directory=packages, entrypoint=fixture)
                require(grant.target_url not in configured.command and
                        all("1.1.1.1" not in argument for argument in configured.command),
                        "grant material escaped to process arguments")
                launch_environments.append(dict(configured.environment))
                require(set(configured.environment) == {"PATH", "LANG", "LC_ALL", "HOME", "TMPDIR"},
                        "worker environment was not minimal")
                return replace(configured, environment={**configured.environment,
                    "DOM_XRAY_FIXTURE_MARKER": str(marker_path), "DOM_XRAY_FIXTURE_HANG": "1" if hang else "0"})
            before_secret = os.environ.get("AWS_SECRET_ACCESS_KEY")
            os.environ["AWS_SECRET_ACCESS_KEY"] = "fixture-canary"
            try:
                transport = run_public_scan_transport("https://xray.test/",
                    policy=DestinationPolicy(lambda h, p: initial_dns.append((h, p)) or ["1.1.1.1"]),
                    launch_worker=launch, schema_validator=lambda r: schema.validate(r),
                    semantic_validator=lambda r: validate_semantics(r, "supervised egress capture", schema),
                    temporary_root=directory, deadline_seconds=15)
            finally:
                if before_secret is None:
                    del os.environ["AWS_SECRET_ACCESS_KEY"]
                else:
                    os.environ["AWS_SECRET_ACCESS_KEY"] = before_secret
            if transport.outcome != expected:
                phase = marker_path.with_suffix(".phase.json")
                observed = phase.read_text() if phase.exists() else "before fixture entrypoint"
                trace = phase.with_suffix(".trace.txt")
                stack = trace.read_text() if trace.exists() else ""
                raise AssertionError(f"unexpected supervised result: {transport.outcome}; last phase: {observed}\n{stack}")
            require(len(initial_dns) == 1 and len(launch_environments) == 1, "initial launch grant resolved twice")
            marker = json.loads(marker_path.read_text())
            require(marker.get('sandboxWitness') is True, 'active offline sandbox witness missing')
            if options.container_limits:
                counters = marker['cgroupCounters']
                require(counters['memory.current'] < 1073741824 and counters['pids.current'] <= 128,
                        'live capture exceeded its fixture limit')
                print('Live capture cgroup counters: ' + json.dumps(counters, sort_keys=True), flush=True)
            require(marker["descendants"] and any(row["chromium"] for row in marker["descendants"]),
                    "real capture did not observe live Chromium descendants")
            chromium_rows = [row for row in marker['descendants'] if row['chromium'] and 'seccomp' in row]
            require(chromium_rows and all(row['noNewPrivileges'] == 1
                                          and not row['sandboxDisabled'] for row in chromium_rows),
                    'actual Chromium lacked NNP or used --no-sandbox')
            require(any(row['seccomp'] == 2 for row in chromium_rows),
                    'no actual Chromium process had a syscall filter')
            if options.container_limits:
                require(all(row['seccomp'] == 2 for row in chromium_rows),
                        'container Chromium process lacked the inherited syscall filter')
            # Signal delivery/exit transitions are asynchronous. Observe exact
            # process instances for a bounded interval, not just one scheduler tick.
            stopped_deadline = time.monotonic() + 0.4
            while any(alive(row) for row in marker["descendants"]) and time.monotonic() < stopped_deadline:
                time.sleep(0.01)
            survivors = [row for row in marker["descendants"] if alive(row)]
            require(not survivors, f"browser descendants survived bounded exit observation: {survivors}")
            require(not Path(marker["profileHome"]).exists() and not Path(marker["configHome"]).exists(),
                    "scan-owned trust/config files survived transport cleanup")
            bridge = Path(marker["bridgePath"])
            require(not bridge.exists() and not bridge.parent.exists(),
                    "scan-owned bridge socket/directory survived transport cleanup")
            observed = [row["networkNamespace"] for row in marker["descendants"]
                        if row["chromium"] and "networkNamespace" in row]
            require(observed and all(value != marker["hostNetworkNamespace"] for value in observed),
                    "transport did not launch Chromium through isolated networking")
            for key, host_key in (("mountNamespace", "hostMountNamespace"), ("ipcNamespace", "hostIpcNamespace")):
                observed = [row[key] for row in marker["descendants"] if row["chromium"] and key in row]
                require(observed and all(value != marker[host_key] for value in observed),
                        "actual Chromium retained host mount/IPC namespace")
            profiles = [Path(row["profilePath"]) for row in marker["descendants"] if row["chromium"] and "profilePath" in row]
            require(profiles and all(profile.is_relative_to(marker["configHome"]) and not profile.exists() for profile in profiles),
                    "actual Chromium profile was not parent-owned and cleaned up")
            if not hang:
                require(transport.admitted and transport.record["status"] == "complete"
                        and marker["lookupCount"] > 0 and marker["requestCount"] > 1,
                        "complete supervised HTTPS/service-worker capture was not admitted")
                require(any(row.get("requestOwner") == "service-worker"
                            and row.get("initiatorType") == "service-worker-registration"
                            and isinstance(row.get("transferredBytes"), int) and row["transferredBytes"] > 0
                            for row in transport.record["resources"]),
                        "supervised capture omitted measured service-worker bootstrap bytes")
            else:
                require(not transport.admitted and transport.record is None and not transport.worker.artifact_present,
                        "timed-out capture published a record")
                require(transport.worker.duration_ms < 15200, "capture hang escaped outer wall-time ceiling")
            print(f"Native supervised {'timeout' if hang else 'complete'} evidence: {transport.worker.duration_ms:.0f} ms", flush=True)

        public = run_public_scan_transport("https://example.com/",
            policy=DestinationPolicy(lambda h, p: ["1.1.1.1"]),
            launch_worker=lambda grant, result: create_capture_launch(grant, result, runtime, packages_directory=packages),
            schema_validator=lambda r: schema.validate(r),
            semantic_validator=lambda r: validate_semantics(r, "guarded public rejection", schema),
            temporary_root=directory)
        require(public.outcome == "worker-crashed" and public.record is None and not public.worker.artifact_present,
                "stock entrypoint admitted an arbitrary public scan before containment proof")

        # Strict parsing rejects unknown/duplicate keys, oversize/symlink input,
        # forged destination and booleans before browser setup.
        private = directory / "config-tests"
        private.mkdir(mode=0o700)
        target = "https://xray.test/"
        grant = PublicScanGrant(target, DestinationPolicy(lambda h, p: ["1.1.1.1"]).validate(target, purpose="initial"))
        configured = create_capture_launch(grant, private / "result.json", runtime, packages_directory=packages)
        config = private / "capture-config.json"
        original = config.read_bytes()
        require(load_capture_config(config)[0] == grant, "private grant roundtrip drifted")
        previous_tmpdir = os.environ.pop("TMPDIR", None)
        try:
            try:
                capture_granted_page(grant, runtime)
            except ValueError as error:
                require(str(error) == "capture-worker-private-temp-required", "missing TMPDIR failed at wrong boundary")
            else:
                raise AssertionError("capture silently fell back to unowned temporary storage")
        finally:
            if previous_tmpdir is not None:
                os.environ["TMPDIR"] = previous_tmpdir
        default_directory = directory / "default-packages"
        default_directory.mkdir(mode=0o700)
        default = create_capture_launch(grant, default_directory / "result.json", runtime)
        require(all(default.command), "installed-package launch used an invalid empty process argument")
        variants = [original[:-1] + b',"unknown":true}', b'{"grant":{},"grant":{},"runtime":{}}',
                    b"x" * 16_385]
        forged = json.loads(original)
        forged["grant"]["destination"]["addresses"] = ["127.0.0.1"]
        variants.append(json.dumps(forged).encode())
        forged = json.loads(original)
        forged["grant"]["destination"]["port"] = True
        variants.append(json.dumps(forged).encode())
        for payload in variants:
            config.write_bytes(payload)
            try:
                load_capture_config(config)
            except (ValueError, OSError):
                pass
            else:
                raise AssertionError("malformed worker config was accepted")
        config.write_bytes(original)
        symlink = private / "config-link.json"
        symlink.symlink_to(config)
        try:
            load_capture_config(symlink)
        except ValueError:
            pass
        else:
            raise AssertionError("symlink worker config was accepted")
    print("Verified native sandboxed Chromium capture through grant-file launch, supervisor, normal private NSS "
          "trust, HTTPS proxy/service-worker capture, schema+semantic admission, minimal secret-free env, "
          "strict config rejection, isolated browser network/mount/IPC namespaces and profile, live-browser post-capture timeout, "
          "descendant kill and parent-owned bridge/scan-file cleanup. "
          "Public capture and full filesystem/container containment remain disabled/unproven.")


if __name__ == "__main__":
    main()
