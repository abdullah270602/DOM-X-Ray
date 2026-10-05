"""Ephemeral browser-side certificates; never origin trust or system trust.

The caller must destroy the disposable worker after its overall deadline and
scope root trust to that browser alone. OpenSSL is a trusted deployment binary.
"""

from __future__ import annotations

import ipaddress
import os
from pathlib import Path
import secrets
import ssl
import subprocess
import tempfile
from threading import Lock
import time

from scanner.destination_policy import DestinationPolicy


class CertificateIssuerError(ValueError):
    """Content-free certificate setup/issuance failure."""


def _host(hostname):
    if not isinstance(hostname, str) or not hostname or len(hostname) > 253:
        raise CertificateIssuerError("certificate-host")
    authority = f"[{hostname}]" if ":" in hostname else hostname
    try:
        grant = DestinationPolicy(lambda _host, _port: ["1.1.1.1"]).validate(
            f"https://{authority}/", purpose="subresource")
        if grant.hostname != hostname:
            raise ValueError("noncanonical")
    except ValueError:
        raise CertificateIssuerError("certificate-host") from None
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        return f"DNS:{hostname}"
    return f"IP:{hostname}"


class ScanCertificateIssuer:
    """One private CA per scan, independent host keys, and fresh TLS contexts.

    Setup and each factory call have a five-second budget, including lock waits.
    All calls also share a monotonic scan lifetime of at most fifteen seconds.
    No command, hostname, key, or provider output appears in an exception.
    """

    def __init__(self, openssl: str | Path, *, max_hosts: int = 128,
                 lifetime_seconds: float = 15.0, operation_seconds: float = 5.0):
        if isinstance(max_hosts, bool) or not isinstance(max_hosts, int) or not 1 <= max_hosts <= 500:
            raise CertificateIssuerError("certificate-configuration")
        for value, ceiling in ((lifetime_seconds, 15.0), (operation_seconds, 5.0)):
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 < value <= ceiling:
                raise CertificateIssuerError("certificate-configuration")
        executable = Path(openssl)
        if not executable.is_absolute() or not executable.is_file():
            raise CertificateIssuerError("certificate-configuration")
        self._executable = executable
        self._max_hosts = max_hosts
        self._operation_seconds = operation_seconds
        self._expires = time.monotonic() + lifetime_seconds
        self._lock = Lock()
        self._closed = False
        self._leaves = {}
        try:
            self._temporary = tempfile.TemporaryDirectory(prefix="dom-xray-scan-ca-")
        except OSError:
            raise CertificateIssuerError("certificate-setup") from None
        self._directory = Path(self._temporary.name)
        self._root = self._directory / "root.pem"
        self._root_key = self._directory / "root-key.pem"
        self._configuration = self._directory / "req.cnf"
        deadline = min(self._expires, time.monotonic() + operation_seconds)
        try:
            self._directory.chmod(0o700)
            # Prevent ambient request extension configuration from changing purpose.
            self._configuration.write_text("[req]\ndistinguished_name=dn\n[dn]\n", encoding="ascii")
            self._run(["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                "-nodes", "-sha256", "-days", "1", "-batch", "-config", str(self._configuration),
                "-subj", "/CN=DOM-X-Ray transient scan root", "-set_serial", self._serial(),
                "-keyout", str(self._root_key), "-out", str(self._root),
                "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
                "-addext", "keyUsage=critical,keyCertSign", "-addext", "subjectKeyIdentifier=hash"], deadline)
            self._root_key.chmod(0o600)
        except (CertificateIssuerError, OSError):
            self._closed = True
            try:
                self._temporary.cleanup()
            except OSError:
                raise CertificateIssuerError("certificate-cleanup") from None
            raise CertificateIssuerError("certificate-setup") from None

    @staticmethod
    def _serial():
        return "0x" + secrets.token_hex(16)

    def _remaining(self, deadline):
        remaining = min(deadline, self._expires) - time.monotonic()
        if remaining <= 0:
            raise CertificateIssuerError("certificate-timeout")
        return remaining

    def _run(self, arguments, deadline, *, capture=False):
        environment = {key: value for key, value in os.environ.items()
                       if not key.upper().startswith("OPENSSL_") and key.upper() != "RANDFILE"}
        # x509 may load ambient OpenSSL config, too. This file has no external
        # includes or provider/engine directives; the executable is explicit.
        environment["OPENSSL_CONF"] = str(self._configuration)
        try:
            result = subprocess.run([str(self._executable), *arguments], stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE if capture else subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True,
                timeout=self._remaining(deadline), env=environment,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
        except subprocess.TimeoutExpired:
            raise CertificateIssuerError("certificate-timeout") from None
        except (subprocess.CalledProcessError, OSError):
            raise CertificateIssuerError("certificate-command") from None
        self._remaining(deadline)
        if capture:
            # Only trusted x509's bounded SAN output is captured, never key data.
            if len(result.stdout) > 4_096:
                raise CertificateIssuerError("certificate-binding")
            return result.stdout
        return b""

    def _check_identity(self, leaf, hostname, deadline):
        output = self._run(["x509", "-in", str(leaf), "-noout", "-ext", "subjectAltName"],
                           deadline, capture=True)
        try:
            lines = [line.strip() for line in output.decode("ascii").splitlines() if line.strip()]
            if len(lines) != 2 or lines[0] != "X509v3 Subject Alternative Name:":
                raise ValueError("SAN")
            try:
                address = ipaddress.ip_address(hostname)
            except ValueError:
                if lines[1] != f"DNS:{hostname}":
                    raise ValueError("SAN")
            else:
                if not lines[1].startswith("IP Address:") or ipaddress.ip_address(lines[1][11:]) != address:
                    raise ValueError("SAN")
        except (UnicodeError, ValueError):
            raise CertificateIssuerError("certificate-binding") from None

    @property
    def trust_certificate(self):
        if self._closed:
            raise CertificateIssuerError("certificate-closed")
        self._remaining(self._expires)
        return self._root

    def __call__(self, hostname):
        if self._closed:
            raise CertificateIssuerError("certificate-closed")
        san = _host(hostname)
        deadline = min(self._expires, time.monotonic() + self._operation_seconds)
        if not self._lock.acquire(timeout=self._remaining(deadline)):
            raise CertificateIssuerError("certificate-timeout")
        try:
            if self._closed:
                raise CertificateIssuerError("certificate-closed")
            self._remaining(deadline)
            if hostname not in self._leaves:
                if len(self._leaves) >= self._max_hosts:
                    raise CertificateIssuerError("certificate-host-limit")
                # File names contain no requested-host material.
                token = secrets.token_hex(16)
                key = self._directory / f"{token}.key"
                request = self._directory / f"{token}.csr"
                leaf = self._directory / f"{token}.pem"
                chain = self._directory / f"{token}.chain.pem"
                try:
                    self._run(["req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                        "-nodes", "-sha256", "-batch", "-config", str(self._configuration),
                        "-subj", "/CN=DOM-X-Ray intercepted host", "-keyout", str(key), "-out", str(request),
                        "-addext", f"subjectAltName={san}",
                        "-addext", "basicConstraints=critical,CA:FALSE",
                        "-addext", "keyUsage=critical,digitalSignature",
                        "-addext", "extendedKeyUsage=serverAuth"], deadline)
                    key.chmod(0o600)
                    self._run(["x509", "-req", "-in", str(request), "-CA", str(self._root),
                        "-CAkey", str(self._root_key), "-set_serial", self._serial(), "-days", "1",
                        "-sha256", "-copy_extensions", "copy", "-out", str(leaf)], deadline)
                    self._check_identity(leaf, hostname, deadline)
                    chain.write_bytes(leaf.read_bytes() + self._root.read_bytes())
                    request.unlink()
                    self._remaining(deadline)
                    self._leaves[hostname] = (chain, key)
                except (CertificateIssuerError, OSError):
                    cleanup_failed = False
                    for path in (key, request, leaf, chain):
                        try:
                            path.unlink(missing_ok=True)
                        except OSError:
                            cleanup_failed = True
                    if cleanup_failed:
                        raise CertificateIssuerError("certificate-cleanup") from None
                    raise CertificateIssuerError("certificate-issuance") from None
            chain, key = self._leaves[hostname]
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.set_alpn_protocols(["http/1.1"])
            try:
                context.load_cert_chain(chain, key)
            except (OSError, ssl.SSLError):
                raise CertificateIssuerError("certificate-context") from None
            self._remaining(deadline)
            return context
        finally:
            self._lock.release()

    def close(self):
        # Issuance itself is bounded; do not remove files beneath an active call.
        if not self._lock.acquire(timeout=5.0):
            raise CertificateIssuerError("certificate-cleanup-timeout")
        try:
            self._closed = True
            self._leaves.clear()
            try:
                self._temporary.cleanup()
            except OSError:
                raise CertificateIssuerError("certificate-cleanup") from None
        finally:
            self._lock.release()

    def __enter__(self):
        return self

    def __exit__(self, *_exception):
        self.close()


__all__ = ["ScanCertificateIssuer", "CertificateIssuerError"]
