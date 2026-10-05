"""Disposable Linux NSS root trust; never the operator's certificate store.

This prepares browser-only trust. It is not network containment and does not
launch Chromium or disable any certificate checks. Close the browser before
destroying its trust profile. NSS certutil is a trusted Linux dependency, not
Windows' unrelated certutil executable.
"""

from __future__ import annotations

import base64
import os
from pathlib import Path
import ssl
import stat
import subprocess
import sys
import tempfile
import time

_NICKNAME = "DOM-X-Ray disposable scan root"
_MAX_CERT_BYTES = 65_536


class BrowserTrustError(ValueError):
    """Content-free trust setup/cleanup failure."""


def _certificate(path):
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= _MAX_CERT_BYTES:
        raise ValueError("invalid certificate file")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as stream:
        opened = os.fstat(stream.fileno())
        if (not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino)
                or not 0 < opened.st_size <= _MAX_CERT_BYTES):
            raise ValueError("invalid certificate file")
        raw = stream.read(_MAX_CERT_BYTES + 1)
    if len(raw) > _MAX_CERT_BYTES:
        raise ValueError("invalid certificate size")
    text = raw.decode("ascii").strip()
    if (text.count("-----BEGIN CERTIFICATE-----") != 1
            or text.count("-----END CERTIFICATE-----") != 1
            or not text.startswith("-----BEGIN CERTIFICATE-----")
            or not text.endswith("-----END CERTIFICATE-----")):
        raise ValueError("invalid certificate encoding")
    # Strict base64 rejects stray content that the tolerant ssl helper may ignore.
    encoded = "".join(text.splitlines()[1:-1])
    der = base64.b64decode(encoded, validate=True)
    if not der or ssl.PEM_cert_to_DER_cert(text) != der:
        raise ValueError("invalid certificate encoding")
    return der, text + "\n"


class LinuxBrowserTrust:
    """One scan's NSS database under a newly created, owned private HOME.

    No ambient environment or trust files are copied. The caller launches the
    browser with ``environment``; the operator's process environment is unchanged.
    Existing legacy NSS-path detection keeps this usable with pinned Chromium
    140 and newer releases that prefer a different default path.
    """

    def __init__(self, root_certificate: str | Path, certutil: str | Path, *, timeout_seconds: float = 5.0,
                 runtime_library_path: str | Path | None = None):
        if sys.platform != "linux":
            raise BrowserTrustError("browser-trust-platform")
        if (isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float))
                or not 0 < timeout_seconds <= 5.0):
            raise BrowserTrustError("browser-trust-configuration")
        try:
            executable = Path(certutil)
            valid_executable = executable.is_absolute() and executable.is_file()
        except (TypeError, OSError):
            valid_executable = False
        if not valid_executable:
            raise BrowserTrustError("browser-trust-configuration")
        if runtime_library_path is not None:
            try:
                libraries = Path(runtime_library_path)
                valid_libraries = libraries.is_absolute() and libraries.is_dir() and ":" not in str(libraries)
            except (TypeError, OSError):
                valid_libraries = False
            if not valid_libraries:
                raise BrowserTrustError("browser-trust-configuration")
        deadline = time.monotonic() + timeout_seconds
        self._closed = False
        self._temporary = None
        try:
            expected, pem = _certificate(Path(root_certificate))
            self._temporary = tempfile.TemporaryDirectory(prefix="dom-xray-browser-trust-")
            self._directory = Path(self._temporary.name)
            self._directory.chmod(0o700)
            self._database = self._directory / ".pki" / "nssdb"
            self._database.mkdir(parents=True, mode=0o700)
            self._database.parent.chmod(0o700)
            for name in ("config", "data", "cache", "tmp"):
                (self._directory / name).mkdir(mode=0o700)
            self._environment = {
                "HOME": str(self._directory), "XDG_CONFIG_HOME": str(self._directory / "config"),
                "XDG_DATA_HOME": str(self._directory / "data"), "XDG_CACHE_HOME": str(self._directory / "cache"),
                "TMPDIR": str(self._directory / "tmp"), "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
            }
            if runtime_library_path is not None:
                # Deliberate reviewed runtime dependency directory, not an
                # ambient LD_LIBRARY_PATH or a visitor-controlled setting.
                self._environment["LD_LIBRARY_PATH"] = str(libraries)
            # Snapshot the public root so later issuer-file changes cannot alter
            # what certutil imports. No private key is ever copied here.
            root = self._directory / "scan-root.pem"
            root.write_text(pem, encoding="ascii")
            root.chmod(0o600)
            database = f"sql:{self._database}"
            self._run(executable, ["-N", "-d", database, "--empty-password"], deadline)
            self._run(executable, ["-A", "-d", database, "-n", _NICKNAME,
                                   "-t", "C,,", "-i", str(root)], deadline)
            # Export the installed identity and require an exact root match.
            installed = self._run(executable, ["-L", "-d", database, "-n", _NICKNAME, "-a"],
                                  deadline, capture=True)
            exported = self._directory / "installed-root.pem"
            exported.write_bytes(installed)
            if _certificate(exported)[0] != expected:
                raise BrowserTrustError("browser-trust-identity")
            exported.unlink()
        except (OSError, UnicodeError, ValueError, TypeError, subprocess.SubprocessError) as error:
            self._closed = True
            if self._temporary is not None:
                try:
                    self._temporary.cleanup()
                except OSError:
                    raise BrowserTrustError("browser-trust-cleanup") from None
            if isinstance(error, BrowserTrustError):
                raise error from None
            if isinstance(error, subprocess.TimeoutExpired):
                raise BrowserTrustError("browser-trust-timeout") from None
            raise BrowserTrustError("browser-trust-setup") from None

    def _run(self, executable, arguments, deadline, *, capture=False):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise BrowserTrustError("browser-trust-timeout")
        # Bound memory even if a misconfigured certutil produces excess output.
        # The trusted binary's disk output still needs the worker's temp quota.
        with tempfile.TemporaryFile(dir=self._directory) as output:
            subprocess.run([str(executable), *arguments], stdin=subprocess.DEVNULL,
                stdout=output if capture else subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                env=dict(self._environment), cwd=self._directory, check=True, timeout=remaining)
            if time.monotonic() >= deadline:
                raise BrowserTrustError("browser-trust-timeout")
            if capture:
                output.seek(0)
                captured = output.read(_MAX_CERT_BYTES + 1)
                if len(captured) > _MAX_CERT_BYTES:
                    raise BrowserTrustError("browser-trust-identity")
                return captured
            return b""

    @property
    def environment(self):
        if self._closed:
            raise BrowserTrustError("browser-trust-closed")
        return dict(self._environment)

    def close(self):
        self._closed = True
        try:
            if self._temporary is not None:
                self._temporary.cleanup()
        except OSError:
            raise BrowserTrustError("browser-trust-cleanup") from None

    def __enter__(self):
        return self

    def __exit__(self, *_exception):
        self.close()


__all__ = ["LinuxBrowserTrust", "BrowserTrustError"]
