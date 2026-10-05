"""Trusted namespace init: loopback setup, cap drop, relay, then non-root child.

Invoked only through the reviewed unshare wrapper. Network/PID isolation is not
filesystem isolation. The child is never allowed setup privileges or host IP fds.
"""

import ctypes
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
from threading import Thread

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scanner.namespace_bridge import NamespaceRelay


def drop_capabilities():
    library = ctypes.CDLL(None, use_errno=True)
    def prctl(option, *arguments):
        if library.prctl(option, *arguments, *([0] * (4 - len(arguments)))) != 0:
            raise OSError("namespace-capability-drop")
    last = int(Path("/proc/sys/kernel/cap_last_cap").read_text())
    if not 0 <= last <= 63:
        raise ValueError("namespace-capability-range")
    for capability in range(last + 1):
        prctl(24, capability)  # PR_CAPBSET_DROP
    prctl(47, 4)  # PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL
    prctl(38, 1)  # PR_SET_NO_NEW_PRIVS
    class Header(ctypes.Structure):
        _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]
    class Data(ctypes.Structure):
        _fields_ = [("effective", ctypes.c_uint32), ("permitted", ctypes.c_uint32),
                    ("inheritable", ctypes.c_uint32)]
    if library.capset(ctypes.byref(Header(0x20080522, 0)), ctypes.byref((Data * 2)())) != 0:
        raise OSError("namespace-capability-drop")
    status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
    if (any(int(status[key].strip(), 16) for key in ("CapEff", "CapPrm", "CapInh", "CapAmb", "CapBnd"))
            or status["NoNewPrivs"].strip() != "1" or os.getuid() == 0):
        raise ValueError("namespace-capability-postcondition")


def write_namespace_wrapper(directory, *, executable, bridge_path, port, preserve_pipes=True):
    """Generated runtime wrapper, with all paths from trusted program config."""
    import shlex
    directory = Path(directory)
    executable = Path(executable)
    if (sys.platform != "linux" or not directory.is_absolute() or not directory.is_dir()
            or directory.stat().st_mode & 0o077 or not executable.is_absolute() or not executable.is_file()
            or not isinstance(preserve_pipes, bool) or not isinstance(port, int) or isinstance(port, bool)
            or not 1 <= port <= 65535 or not Path(bridge_path).is_absolute()):
        raise ValueError("namespace-wrapper-configuration")
    config, wrapper = directory / "namespace-config.json", directory / "browser-wrapper"
    payload = {"executable": str(executable), "bridgePath": str(bridge_path),
               "port": port, "preservePipes": preserve_pipes}
    with config.open("x") as stream:
        json.dump(payload, stream)
    config.chmod(0o600)
    command = ["/usr/bin/python3", "-I", str(Path(__file__).resolve()), "--launch", str(config)]
    with wrapper.open("x") as stream:
        stream.write("#!/bin/sh\nexec " + " ".join(shlex.quote(item) for item in command) + ' "$@"\n')
    wrapper.chmod(0o700)
    return wrapper


def launch_namespace():
    """Tie Playwright's detached launcher to its actual parent before exec."""
    parent = os.getppid()
    if parent <= 1 or os.getuid() == 0:
        raise ValueError("namespace-launch-parent")
    library = ctypes.CDLL(None, use_errno=True)
    if library.prctl(1, signal.SIGKILL, 0, 0, 0) != 0:  # PR_SET_PDEATHSIG
        raise OSError("namespace-launch-parent-death")
    # Parent death before prctl would otherwise miss the notification.
    if os.getppid() != parent:
        raise ValueError("namespace-launch-parent-changed")
    command = ["/usr/bin/unshare", "--user", "--map-current-user", "--net", "--pid", "--fork",
               "--mount-proc", "--kill-child", "--keep-caps", "/usr/bin/python3", "-I",
               str(Path(__file__).resolve()), *sys.argv[2:]]
    os.execv(command[0], command)


def main():
    config_path = Path(sys.argv[1])
    if config_path.is_symlink() or not config_path.is_file() or config_path.stat().st_size > 16_384:
        raise ValueError("namespace-config")
    config = json.loads(config_path.read_text())
    if not isinstance(config, dict) or set(config) != {"executable", "bridgePath", "port", "preservePipes"}:
        raise ValueError("namespace-config")
    if (os.getpid() != 1 or os.getuid() == 0 or not isinstance(config["port"], int)
            or isinstance(config["port"], bool) or not 1 <= config["port"] <= 65535
            or not isinstance(config["preservePipes"], bool)
            or any(not isinstance(config[key], str) or not Path(config[key]).is_absolute()
                   for key in ("executable", "bridgePath"))):
        raise ValueError("namespace-postcondition")
    # Only change this newly created network namespace, never host networking.
    subprocess.run(["/usr/sbin/ip", "link", "set", "lo", "up"], check=True,
                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
    if socket_interfaces() != {"lo"}:
        raise ValueError("namespace-interface-postcondition")
    drop_capabilities()
    relay = NamespaceRelay(config["bridgePath"], config["port"])
    thread = Thread(target=relay.serve_forever, daemon=True)
    thread.start()
    pipes = (3, 4) if config["preservePipes"] else ()
    for descriptor in pipes:
        os.fstat(descriptor)
    # close_fds excludes all other inherited sockets/namespace handles.
    child = subprocess.Popen([config["executable"], *sys.argv[2:]], close_fds=True, pass_fds=pipes)
    def terminate(_signum, _frame):
        child.kill()
    signal.signal(signal.SIGTERM, terminate)
    signal.signal(signal.SIGINT, terminate)
    try:
        returncode = child.wait()
    finally:
        relay.shutdown()
        relay.server_close()
        thread.join(timeout=5)
        if thread.is_alive():
            raise RuntimeError("namespace-relay-listener-cleanup")
        relay.close_handlers()
    # Exiting namespace PID 1 also destroys detached children in this PID ns.
    raise SystemExit(returncode if returncode >= 0 else 1)


def socket_interfaces():
    import socket
    return {name for _index, name in socket.if_nameindex()}


if __name__ == "__main__":
    try:
        if len(sys.argv) > 1 and sys.argv[1] == "--launch":
            launch_namespace()
        else:
            main()
    except Exception:
        raise SystemExit(2) from None
