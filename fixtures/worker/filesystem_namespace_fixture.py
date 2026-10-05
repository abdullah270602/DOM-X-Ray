"""Adversarial native child inside the explicit filesystem root."""

import errno
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import traceback
import ctypes

def diagnostic(kind, value, trace):
    Path(os.environ["DXR_FILESYSTEM_DIAGNOSTIC"]).write_text("".join(traceback.format_exception(kind, value, trace)))

sys.excepthook = diagnostic


def require(value, message):
    if not value:
        raise AssertionError(message)


config = json.loads(Path(sys.argv[1]).read_text())
status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
require(os.getuid() != 0 and status["NoNewPrivs"].strip() == "1"
        and all(int(status[key].strip(), 16) == 0 for key in ("CapEff", "CapPrm", "CapInh", "CapAmb", "CapBnd")),
        "filesystem child retained capabilities")
for hidden in config["hiddenFiles"]:
    for path in (hidden, "/proc/1/root" + hidden, "/proc/self/root" + hidden):
        try:
            Path(path).read_bytes()
        except OSError:
            pass
        else:
            raise AssertionError("host canary accessible")
require(not Path("/.old-root").exists(), "old root remained reachable")
require(not Path("/mnt").exists() and not Path("/home").exists() and not Path("/root").exists(), "host tree exposed")
for readonly in config["readonlyFiles"]:
    try:
        Path(readonly).write_bytes(b"corrupted")
    except OSError as error:
        require(error.errno == errno.EROFS, "readonly runtime failed for wrong reason")
    else:
        raise AssertionError("readonly mount was writable")
Path(config["writableFile"]).write_bytes(b"scan-only-data")
for parent in (Path(config['writableFile']).parent, Path('/tmp')):
    executable = parent / 'scratch-exec-canary'
    executable.write_bytes(b'#!/bin/sh\nexit 0\n')
    executable.chmod(0o700)
    try:
        subprocess.run([str(executable)], check=True, timeout=1)
    except OSError as error:
        require(error.errno == errno.EACCES, 'scratch exec denied for wrong reason')
    else:
        raise AssertionError('writable browser scratch was executable')
require(Path(config["privateNssFile"]).read_bytes() == b"public-root-only", "NSS snapshot copy drifted")
Path(config["privateNssFile"]).write_bytes(b"private-browser-NSS")
# Chromium can create deeper user namespaces with capabilities scoped there.
# Those capabilities must not unlock inherited read-only runtime mounts.
child = os.fork()
if child == 0:
    library = ctypes.CDLL(None, use_errno=True)
    if library.unshare(0x10000000 | 0x00020000) != 0:  # NEWUSER | NEWNS
        os._exit(11 if ctypes.get_errno() == errno.EPERM else 12)
    nested = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
    if not int(nested["CapEff"].strip(), 16) & (1 << 21):  # scoped SYS_ADMIN
        os._exit(12)
    target = os.fsencode(Path(config["readonlyFiles"][0]).parent)
    changed = library.mount(None, target, None, 32 | 4096 | 2 | 4, None)
    os._exit(10 if changed != 0 and ctypes.get_errno() == errno.EPERM else 12)
_, nested_status = os.waitpid(child, 0)
require(os.WIFEXITED(nested_status) and os.WEXITSTATUS(nested_status) in (10, 11), "nested namespace unlocked runtime mount")
for address in (config["hiddenSocket"], "\0" + config["abstractSocket"]):
    with socket.socket(socket.AF_UNIX) as connection:
        connection.settimeout(0.5)
        try:
            connection.connect(address)
        except OSError:
            pass
        else:
            raise AssertionError("unrelated host Unix socket accessible")
for directory in ("/proc/self/fd", "/proc/1/fd"):
    for descriptor in tuple(Path(directory).iterdir()):
        if int(descriptor.name) <= 2:
            continue
        try:
            require(not descriptor.is_dir(), "inherited host directory FD survived")
        except OSError:
            pass
with socket.socket(socket.AF_UNIX) as connection:
    connection.settimeout(2)
    connection.connect("/run/proxy.sock")
    connection.sendall(b"GET http://xray.test/ HTTP/1.1\r\nHost: xray.test\r\nConnection: close\r\n\r\n")
    response = bytearray()
    while chunk := connection.recv(4096):
        response.extend(chunk)
require(response.startswith(b"HTTP/1.1 200 ") and b"TLS proxy works" in response, "allowed proxy socket failed")
proof = {"mount": os.readlink("/proc/self/ns/mnt"), "ipc": os.readlink("/proc/self/ns/ipc"),
         "pid": os.readlink("/proc/self/ns/pid"), "hostFilesHidden": True, "runtimeReadonly": True,
         "nestedRemountDenied": True, "nestedNamespaceCreated": os.WEXITSTATUS(nested_status) == 10}
proof['scratchExecutionDenied'] = True
Path(config["marker"]).write_text(json.dumps(proof))
if config["hang"]:
    time.sleep(60)
Path(sys.argv[2]).write_text(json.dumps({"supervisorNonce": os.environ["DOM_X_RAY_WORKER_RESULT_NONCE"], "result": proof}))
