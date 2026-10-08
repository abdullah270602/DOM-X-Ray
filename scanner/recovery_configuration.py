"""Private operator registry loader. No discovery, hot reload or public inputs."""

import csv
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess

from scanner.docker_broker_pair_supervisor import DockerBrokerPairSupervisor
from scanner.docker_worker_supervisor import _pairs, _invalid_constant, _require
from scanner.lease_journal import LeaseJournal
from scanner.lease_recovery_poller import LeaseRecoveryPoller
from scanner.lease_recovery_registry import LeaseRecoveryRegistry, MAX_RECOVERY_ROOTS

MAX_CONFIGURATION_BYTES = 32768


class _PrivateFileGuard:
    # Reuse the journal's exact private metadata/ACL policy without constructing
    # a journal or acquiring authority. This object is never a LeaseJournal.
    _safe = LeaseJournal._safe
    _windows_acl = LeaseJournal._windows_acl

    def __init__(self):
        self.sid = None
        if os.name == 'nt':
            response = subprocess.run(['whoami', '/user', '/fo', 'csv', '/nh'], capture_output=True,
                                      check=True, text=True, timeout=3)
            rows = list(csv.reader(response.stdout.strip().splitlines()))
            _require(len(rows) == 1 and len(rows[0]) == 2 and re.fullmatch('S-1-[0-9-]{1,180}', rows[0][1]),
                     'recovery-config-owner')
            self.sid = rows[0][1]


def _read(path):
    path = Path(path)
    _require(path.is_absolute() and path.resolve(strict=True) == path, 'recovery-config-path')
    guard = _PrivateFileGuard()
    guard._safe(path.parent, directory=True)
    guard._safe(path)
    metadata = path.lstat()
    _require(metadata.st_size <= MAX_CONFIGURATION_BYTES, 'recovery-config-size')
    descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    try:
        os.set_inheritable(descriptor, False)
        held = os.fstat(descriptor)
        _require(stat.S_ISREG(held.st_mode) and held.st_nlink == 1
                 and (held.st_dev, held.st_ino) == (metadata.st_dev, metadata.st_ino), 'recovery-config-replaced')
        with os.fdopen(descriptor, 'rb', closefd=False) as stream:
            raw = stream.read(MAX_CONFIGURATION_BYTES + 1)
        _require(len(raw) <= MAX_CONFIGURATION_BYTES, 'recovery-config-size')
        guard._safe(path)
        current = path.stat()
        _require((current.st_dev, current.st_ino) == (held.st_dev, held.st_ino), 'recovery-config-replaced')
        return raw
    finally:
        os.close(descriptor)


def _identity(value):
    _require(type(value) is list and len(value) == 2
             and all(type(item) is int and 0 <= item < 2**128 for item in value), 'recovery-config-identity')
    return tuple(value)


def load_recovery_registry(path, expected_sha256):
    """Hash is supplied separately by the trusted operator, never read from file."""
    _require(isinstance(expected_sha256, str) and re.fullmatch('[0-9a-f]{64}', expected_sha256),
             'recovery-config-digest')
    raw = _read(path)
    _require(hashlib.sha256(raw).hexdigest() == expected_sha256, 'recovery-config-integrity')
    value = json.loads(raw, object_pairs_hook=_pairs, parse_constant=_invalid_constant)
    _require(type(value) is dict and set(value) == {'version', 'entries'}
             and type(value['version']) is int and value['version'] == 1
             and type(value['entries']) is list and 1 <= len(value['entries']) <= MAX_RECOVERY_ROOTS,
             'recovery-config-shape')
    pollers = []
    runtime_fields = {'docker_executable', 'context', 'image_id', 'seccomp_path', 'seccomp_sha256',
                      'command', 'initializer_command', 'broker_command'}
    for entry in value['entries']:
        _require(type(entry) is dict and set(entry) == {'root', 'identities', 'runtimeFingerprint', 'runtime'},
                 'recovery-config-entry')
        _require(isinstance(entry['root'], str) and 0 < len(entry['root']) <= 4096,
                 'recovery-config-root')
        _require(type(entry['identities']) is list and len(entry['identities']) == 3,
                 'recovery-config-identities')
        identities = tuple(_identity(item) for item in entry['identities'])
        fingerprint = entry['runtimeFingerprint']
        _require(isinstance(fingerprint, str) and re.fullmatch('[0-9a-f]{64}', fingerprint),
                 'recovery-config-fingerprint')
        runtime = entry['runtime']
        _require(type(runtime) is dict and set(runtime) == runtime_fields, 'recovery-config-runtime')
        for name in ('docker_executable', 'seccomp_path'):
            _require(isinstance(runtime[name], str) and 0 < len(runtime[name]) <= 4096
                     and Path(runtime[name]).is_absolute()
                     and Path(runtime[name]).resolve(strict=True) == Path(runtime[name]), 'recovery-config-runtime-path')
        for name in ('command', 'initializer_command', 'broker_command'):
            _require(type(runtime[name]) is list and 1 <= len(runtime[name]) <= 16
                     and all(isinstance(item, str) and 0 < len(item) <= 4096 and '\0' not in item
                             for item in runtime[name]), 'recovery-config-command')
        for name in ('context', 'image_id', 'seccomp_sha256'):
            _require(isinstance(runtime[name], str), 'recovery-config-runtime-field')
        configuration = dict(runtime)
        for name in ('command', 'initializer_command', 'broker_command'):
            configuration[name] = tuple(configuration[name])
        def factory(journal, configuration=configuration):
            return DockerBrokerPairSupervisor(**configuration, lease_journal=journal)
        poller = LeaseRecoveryPoller(entry['root'], factory)
        _require(poller.identities == identities and poller.fingerprint == fingerprint,
                 'recovery-config-binding')
        pollers.append(poller)
    return LeaseRecoveryRegistry(tuple(pollers))
