"""Trusted x86-64 Linux mount-root setup, before browser capability drop.

Runtime directories are deployment inputs, not visitor settings. This exposes
the selected runtime image, not host homes, broker keys, or other Unix sockets.
It does not establish runtime integrity, kernel safety, or whole-worker quotas.
"""

import ctypes
import os
from pathlib import Path
import platform
import stat
import subprocess

SYSTEM_RUNTIME = ("/usr/bin", "/usr/sbin", "/usr/lib/x86_64-linux-gnu", "/usr/lib64", "/usr/lib/python3.12")
OPTIONAL_RUNTIME = ("/usr/lib/locale", "/usr/share/fonts", "/usr/share/fontconfig", "/usr/share/zoneinfo")


def _private_directory(value):
    path = Path(value)
    if (not path.is_absolute() or path.resolve(strict=True) != path or not path.is_dir()
            or path.stat().st_mode & 0o077 or path.stat().st_uid != os.getuid()):
        raise ValueError("browser-filesystem-private-directory")
    return path


def filesystem_config(home, runtime_directories):
    home = _private_directory(home)
    if not isinstance(runtime_directories, (tuple, list)) or len(runtime_directories) > 4:
        raise ValueError("browser-filesystem-runtime")
    directories = []
    for value in runtime_directories:
        path = Path(value)
        if (not path.is_absolute() or path.resolve(strict=True) != path or not path.is_dir()
                or path in map(Path, ("/", "/tmp", "/home", "/mnt", "/etc", "/run", "/dev", "/proc"))
                or path.is_relative_to(home) or home.is_relative_to(path)):
            raise ValueError("browser-filesystem-runtime")
        if not any(path.is_relative_to(parent) for parent in SYSTEM_RUNTIME + OPTIONAL_RUNTIME) and str(path) not in directories:
            directories.append(str(path))
    for name in (".pki", "config", "data", "cache", "tmp"):
        _private_directory(home / name)
    root = home / "filesystem-root"
    root.mkdir(mode=0o700)
    return {"home": str(home), "root": str(root), "runtimeDirectories": directories}


def _mount(*arguments):
    subprocess.run(["/usr/bin/mount", *map(str, arguments)], check=True, timeout=2,
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def enter_browser_filesystem(config, bridge_path, *, preserve_pipes, child_arguments=()):
    """Pivot to explicit mounts and detach old root; return visible proxy path."""
    if (platform.machine() != "x86_64" or os.getpid() != 1 or os.getuid() == 0
            or not isinstance(config, dict) or set(config) != {"home", "root", "runtimeDirectories"}
            or not isinstance(config["runtimeDirectories"], list)
            or len(config["runtimeDirectories"]) > 4):
        raise ValueError("browser-filesystem-config")
    home, root = _private_directory(config["home"]), _private_directory(config["root"])
    if root != home / "filesystem-root" or list(root.iterdir()):
        raise ValueError("browser-filesystem-root")
    runtime = []
    for value in config["runtimeDirectories"]:
        path = Path(value)
        if (not path.is_absolute() or path.resolve(strict=True) != path or not path.is_dir()
                or path in map(Path, ("/", "/tmp", "/home", "/mnt", "/etc", "/run", "/dev", "/proc"))
                or path.is_relative_to(home) or home.is_relative_to(path)
                or any(path.is_relative_to(parent) for parent in SYSTEM_RUNTIME + OPTIONAL_RUNTIME)):
            raise ValueError("browser-filesystem-runtime")
        runtime.append(path)
    profile_arguments = [value.split("=", 1)[1] for value in child_arguments
                         if value.startswith("--user-data-dir=")]
    if len(profile_arguments) > 1:
        raise ValueError("browser-filesystem-profile")
    profile = None
    if profile_arguments:
        profile = _private_directory(profile_arguments[0])
        if (profile.parent != home.parent or not profile.name.startswith("playwright_chromiumdev_profile-")
                or list(profile.iterdir())):
            raise ValueError("browser-filesystem-profile")
    bridge = Path(bridge_path)
    if not bridge.is_absolute() or not stat.S_ISSOCK(bridge.lstat().st_mode):
        raise ValueError("browser-filesystem-bridge")
    # No setup-time host directory handles survive into namespace PID 1.
    keep = {0, 1, 2, 3, 4} if preserve_pipes else {0, 1, 2}
    for descriptor in tuple(Path("/proc/self/fd").iterdir()):
        number = int(descriptor.name)
        if number not in keep:
            try:
                os.close(number)
            except OSError:
                pass
    _mount("--make-rprivate", "/")
    options = f"size=16m,mode=0700,uid={os.getuid()},gid={os.getgid()},nosuid,nodev"
    _mount("-t", "tmpfs", "-o", options, "tmpfs", root)

    def target(path, directory=True):
        result = root / str(path).lstrip("/")
        result.parent.mkdir(parents=True, exist_ok=True)
        if directory:
            result.mkdir(exist_ok=True)
        else:
            result.touch(exist_ok=True)
        return result

    def bind(source, destination, *, readonly=True, device=False):
        path = target(destination, Path(source).is_dir())
        _mount("--bind", source, path)  # deliberately non-recursive
        flags = "remount,bind,nosuid" + (",ro" if readonly else "") + ("" if device else ",nodev")
        _mount("-o", flags, path)

    # Do not bind all /usr: WSL carries nested host-driver mounts there, and
    # unprivileged non-recursive bind must not unmask locked child mounts.
    for directory in SYSTEM_RUNTIME:
        if not Path(directory).is_dir():
            raise ValueError("browser-filesystem-system-runtime")
        bind(directory, directory)
    for directory in OPTIONAL_RUNTIME:
        if Path(directory).is_dir():
            bind(directory, directory)
    for name in ("bin", "sbin", "lib", "lib64"):
        if os.readlink("/" + name) != "usr/" + name:
            raise ValueError("browser-filesystem-usr-merged-layout")
        (root / name).symlink_to("usr/" + name)
    # Mount ancestors first; otherwise private /tmp hides the runtime/home
    # bind mounts whose original absolute paths are under /tmp.
    for directory in ("/tmp", "/dev/shm"):
        path = target(directory)
        _mount("-t", "tmpfs", "-o", options.replace("size=16m", "size=64m"), "tmpfs", path)
    for directory in runtime:
        bind(directory, directory)
    if profile is not None:
        bind(profile, profile, readonly=False)
    target(home)
    for name in ("config", "data", "cache", "tmp"):
        directory = _private_directory(home / name)
        bind(directory, directory, readonly=False)
    # Chromium's NSS initialization needs a writable database. Copy only the
    # bounded public-root database into private tmpfs, never bind host trust RW
    # and never expose an issuer private key or the operator's NSS directory.
    pki = target(home / ".pki")
    _mount("-t", "tmpfs", "-o", options.replace("size=16m", "size=8m"), "tmpfs", pki)
    source = _private_directory(home / ".pki")
    if [path.name for path in source.iterdir()] != ["nssdb"]:
        raise ValueError("browser-filesystem-nss-layout")
    database = _private_directory(source / "nssdb")
    copied = pki / "nssdb"
    copied.mkdir(mode=0o700)
    total = 0
    for path in database.iterdir():
        metadata = path.lstat()
        if (path.name not in {"cert9.db", "key4.db", "pkcs11.txt"}
                or not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 1_048_576 - total):
            raise ValueError("browser-filesystem-nss-files")
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor, "rb") as stream:
            opened = os.fstat(stream.fileno())
            if (not stat.S_ISREG(opened.st_mode)
                    or (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino)):
                raise ValueError("browser-filesystem-nss-files")
            content = stream.read(1_048_577 - total)
        total += len(content)
        if total > 1_048_576:
            raise ValueError("browser-filesystem-nss-files")
        (copied / path.name).write_bytes(content)
        (copied / path.name).chmod(0o600)
    for name in ("null", "zero", "random", "urandom"):
        bind("/dev/" + name, "/dev/" + name, device=True)
    bind(bridge, "/run/proxy.sock")
    if Path("/etc/ld.so.cache").is_file():
        bind("/etc/ld.so.cache", "/etc/ld.so.cache")
    if Path("/etc/fonts").is_dir():
        bind("/etc/fonts", "/etc/fonts")
    etc = target("/etc")
    (etc / "passwd").write_text(f"scanner:x:{os.getuid()}:{os.getgid()}:scanner:{home}:/bin/false\n")
    (etc / "group").write_text(f"scanner:x:{os.getgid()}:\n")
    (etc / "nsswitch.conf").write_text("passwd: files\ngroup: files\nhosts: files\n")
    (etc / "hosts").write_text("127.0.0.1 localhost\n::1 localhost\n")
    (etc / "resolv.conf").write_text("")
    _mount("-t", "proc", "-o", "nosuid,nodev,noexec", "proc", target("/proc"))
    old = target("/.old-root")
    library = ctypes.CDLL(None, use_errno=True)
    if library.syscall(155, os.fsencode(root), os.fsencode(old)) != 0:  # x86-64 pivot_root
        raise OSError("browser-filesystem-pivot")
    os.chdir("/")
    if library.umount2(b"/.old-root", 2) != 0:  # MNT_DETACH, only in this mount namespace
        raise OSError(ctypes.get_errno(), "browser-filesystem-detach-old-root")
    Path("/.old-root").rmdir()
    _mount("-o", "remount,ro,nosuid,nodev", "/")
    return Path("/run/proxy.sock")
