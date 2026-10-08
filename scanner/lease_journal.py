"""Local single-controller cleanup authority, not a recovery daemon.

No target, grant, addresses, capability, nonce, output or error text is stored.
Process-crash persistence is testable; power-loss/filesystem durability is a
deployment requirement, not established by this module's settings alone.
"""

from contextlib import contextmanager
import csv
import ctypes
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import subprocess
from threading import RLock
import time

from scanner.docker_worker_supervisor import _pairs, _invalid_constant

ROLES = ('volume', 'initialize', 'broker', 'worker')
MAX_ROWS = 1000
MAX_BYTES = 4_194_304
APP_ID = 0x4458524C
TABLE = 'CREATE TABLE leases (token TEXT PRIMARY KEY, payload TEXT NOT NULL)'


def require(value):
    if not value:
        raise ValueError('lease-journal-invalid')


def _hex(value, size):
    require(isinstance(value, str) and re.fullmatch('[0-9a-f]{' + str(size) + '}', value))


def _validate(record):
    require(isinstance(record, dict) and set(record) == {'version', 'token', 'runtimeFingerprint',
        'engineId', 'expiresAtMs', 'resources'} and record['version'] == 1 and type(record['version']) is int)
    _hex(record['token'], 32)
    _hex(record['runtimeFingerprint'], 64)
    require(record['engineId'] is None or (isinstance(record['engineId'], str)
            and re.fullmatch('[A-Za-z0-9:_-]{1,128}', record['engineId'])))
    require(type(record['expiresAtMs']) is int and 0 < record['expiresAtMs'] < 2**53)
    require(isinstance(record['resources'], dict) and set(record['resources']) == set(ROLES))
    for role, resource in record['resources'].items():
        require(isinstance(resource, dict) and set(resource) == {'state', 'id'}
                and resource['state'] in ('unrequested', 'intent', 'created', 'removed'))
        if resource['id'] is not None:
            require(role != 'volume')
            _hex(resource['id'], 64)
        if resource['state'] in ('unrequested', 'intent'):
            require(resource['id'] is None)
        if resource['state'] in ('created', 'removed') and role != 'volume':
            require(resource['id'] is not None)
        if resource['state'] != 'unrequested':
            require(record['engineId'] is not None)
    containers = [record['resources'][role] for role in ROLES if role != 'volume']
    volume_state = record['resources']['volume']['state']
    if any(r['state'] != 'unrequested' for r in containers):
        require(volume_state in ('created', 'removed'))
    if volume_state == 'removed':
        require(all(r['state'] in ('unrequested', 'removed') for r in containers))
    if record['resources']['broker']['state'] != 'unrequested':
        require(record['resources']['initialize']['state'] in ('created', 'removed'))
    if record['resources']['worker']['state'] != 'unrequested':
        require(record['resources']['initialize']['state'] in ('created', 'removed')
                and record['resources']['broker']['state'] in ('created', 'removed'))
    return record


def _dump(record):
    _validate(record)
    payload = json.dumps(record, separators=(',', ':'), allow_nan=False)
    require(len(payload.encode()) <= 8192)
    return payload


class LeaseJournal:
    """One private local directory, one non-inherited process-lifetime lock."""

    def __init__(self, root):
        self.root = Path(root)
        require(self.root.is_absolute() and self.root.parent.resolve(strict=True) == self.root.parent)
        self.closed, self.lock_fd, self.owner_pid, self.mutex = True, None, os.getpid(), RLock()
        self.active = 0
        self.connection = None
        self.sid = None
        if os.name == 'nt':
            response = subprocess.run(['whoami', '/user', '/fo', 'csv', '/nh'], capture_output=True,
                                      check=True, text=True, timeout=3)
            rows = list(csv.reader(response.stdout.strip().splitlines()))
            require(len(rows) == 1 and len(rows[0]) == 2 and re.fullmatch('S-1-[0-9-]{1,180}', rows[0][1]))
            self.sid = rows[0][1]
        fresh = not self.root.exists()
        if fresh:
            self.root.mkdir(mode=0o700)
            if os.name == 'nt':
                subprocess.run(['icacls', str(self.root), '/inheritance:r', '/grant:r',
                    '*' + self.sid + ':(OI)(CI)F', '*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F'],
                    capture_output=True, check=True, timeout=3)
        self._safe(self.root, directory=True)
        metadata = self.root.stat()
        self.root_identity = metadata.st_dev, metadata.st_ino
        try:
            lock = self.root / 'owner.lock'
            if lock.exists():
                self._safe(lock)
            self.lock_fd = os.open(lock, os.O_CREAT | os.O_RDWR | getattr(os, 'O_NOFOLLOW', 0), 0o600)
            os.set_inheritable(self.lock_fd, False)
            require(os.fstat(self.lock_fd).st_nlink == 1)
            if os.name == 'nt':
                import msvcrt
                if os.fstat(self.lock_fd).st_size == 0:
                    os.write(self.lock_fd, b'0')
                    os.fsync(self.lock_fd)
                os.lseek(self.lock_fd, 0, os.SEEK_SET)
                msvcrt.locking(self.lock_fd, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.closed = False
            self.path = self.root / 'leases.sqlite3'
            new_db = not self.path.exists()
            if new_db:
                fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
                os.close(fd)
            self._safe(self.path)
            metadata = self.path.stat()
            self.db_identity = metadata.st_dev, metadata.st_ino
            with self._db(bootstrap=new_db) as connection:
                if new_db:
                    connection.execute('PRAGMA application_id=' + str(APP_ID))
                    connection.execute(TABLE)
                require(connection.execute('PRAGMA application_id').fetchone()[0] == APP_ID)
                self._schema(connection)
                require(connection.execute('PRAGMA quick_check').fetchall() == [('ok',)])
            if os.name != 'nt':
                directory = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
        except Exception:
            self.close()
            raise

    def _windows_acl(self, path, directory):
        advapi, kernel = ctypes.WinDLL('advapi32'), ctypes.WinDLL('kernel32')
        get = advapi.GetNamedSecurityInfoW
        get.argtypes = [ctypes.c_wchar_p, ctypes.c_ulong, ctypes.c_ulong,
            ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p)]
        get.restype = ctypes.c_ulong
        convert = advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW
        convert.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong,
                           ctypes.POINTER(ctypes.c_wchar_p), ctypes.c_void_p]
        convert.restype = ctypes.c_int
        kernel.LocalFree.argtypes, kernel.LocalFree.restype = [ctypes.c_void_p], ctypes.c_void_p
        descriptor, owner, output = ctypes.c_void_p(), ctypes.c_void_p(), ctypes.c_wchar_p()
        try:
            require(get(str(path), 1, 5, ctypes.byref(owner), None, None, None, ctypes.byref(descriptor)) == 0)
            require(convert(descriptor, 1, 5, ctypes.byref(output), None))
            sddl = output.value
            require(isinstance(sddl, str) and len(sddl) <= 8192)
            match = re.fullmatch(r'O:([^:]+)D:([^()]*)((?:\([^()]+\))+)', sddl)
            require(match is not None)
            allowed = {'SY', 'BA', self.sid}
            require(match[1] in allowed and (not directory or 'P' in match[2]))
            # OWNER RIGHTS resolves only to the owner already validated above.
            allowed.add('OW')
            for ace in re.findall(r'\(([^()]+)\)', match[3]):
                fields = ace.split(';')
                require(len(fields) == 6 and fields[0] == 'A' and fields[5] in allowed)
        finally:
            if output:
                kernel.LocalFree(ctypes.cast(output, ctypes.c_void_p))
            if descriptor:
                kernel.LocalFree(descriptor)

    def _safe(self, path, *, directory=False):
        metadata = path.lstat()
        require(not path.is_symlink() and not getattr(metadata, 'st_file_attributes', 0) & 1024
                and (stat.S_ISDIR(metadata.st_mode) if directory else stat.S_ISREG(metadata.st_mode))
                and (directory or (metadata.st_nlink == 1 and metadata.st_size <= MAX_BYTES)))
        if not directory:
            fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
            try:
                opened = os.fstat(fd)
                require(stat.S_ISREG(opened.st_mode) and opened.st_size <= MAX_BYTES and opened.st_nlink == 1
                        and (opened.st_dev, opened.st_ino) == (metadata.st_dev, metadata.st_ino))
            finally:
                os.close(fd)
        if os.name == 'nt':
            self._windows_acl(path, directory)
        else:
            require(metadata.st_uid == os.geteuid() and stat.S_IMODE(metadata.st_mode) == (0o700 if directory else 0o600))

    def _guard(self):
        require(not self.closed and os.getpid() == self.owner_pid and self.root.resolve(strict=True) == self.root)
        self._safe(self.root, directory=True)
        metadata = self.root.stat()
        require((metadata.st_dev, metadata.st_ino) == self.root_identity)
        for path in self.root.iterdir():
            require(path.name in ('owner.lock', 'leases.sqlite3', 'leases.sqlite3-journal'))
            self._safe(path)
        self._safe(self.path)
        metadata = self.path.stat()
        require((metadata.st_dev, metadata.st_ino) == self.db_identity)
        lock = (self.root / 'owner.lock').stat()
        held = os.fstat(self.lock_fd)
        require((lock.st_dev, lock.st_ino) == (held.st_dev, held.st_ino))

    @contextmanager
    def _db(self, *, bootstrap=False):
        with self.mutex:
            self._guard()
            if self.connection is None:
                self.connection = sqlite3.connect(self.path.as_uri() + '?mode=rw', uri=True,
                    timeout=0.05, isolation_level=None, check_same_thread=False)
                connection = self.connection
                require(connection.execute('PRAGMA journal_mode=DELETE').fetchone()[0] == 'delete')
                connection.execute('PRAGMA synchronous=EXTRA')
                require(connection.execute('PRAGMA synchronous').fetchone()[0] == 3)
                require(connection.execute('PRAGMA page_size').fetchone()[0] == 4096)
                require(connection.execute('PRAGMA max_page_count=1024').fetchone()[0] == 1024)
                connection.execute('PRAGMA trusted_schema=OFF')
                connection.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 8192)
            connection = self.connection
            try:
                if not bootstrap:
                    require(connection.execute('PRAGMA application_id').fetchone()[0] == APP_ID)
                    self._schema(connection)
                require(connection.execute('PRAGMA journal_mode').fetchone()[0] == 'delete')
                require(connection.execute('PRAGMA synchronous').fetchone()[0] == 3)
                connection.execute('BEGIN IMMEDIATE')
                yield connection
                connection.execute('COMMIT')
            except Exception:
                if connection.in_transaction:
                    connection.execute('ROLLBACK')
                raise

    @staticmethod
    def _schema(connection):
        require(connection.execute('SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name').fetchall()
                == [('index', 'sqlite_autoindex_leases_1', 'leases', None), ('table', 'leases', 'leases', TABLE)])

    @contextmanager
    def hold(self):
        with self.mutex:
            self._guard()
            self.active += 1
        try:
            yield
        finally:
            with self.mutex:
                self.active -= 1

    @contextmanager
    def recovery_hold(self):
        # Hold the mutex for the whole pass: no local launcher may start while
        # recovery acts on its journal. The OS lock also excludes other owners.
        with self.mutex:
            self._guard()
            require(self.active == 0)
            self.active += 1
            try:
                yield
            finally:
                self.active -= 1

    def create(self, token, fingerprint, expires_at_ms):
        record = {'version': 1, 'token': token, 'runtimeFingerprint': fingerprint, 'engineId': None,
            'expiresAtMs': expires_at_ms, 'resources': {role: {'state': 'unrequested', 'id': None} for role in ROLES}}
        encoded = _dump(record)
        require(int(time.time() * 1000) < expires_at_ms <= int(time.time() * 1000) + 15000)
        with self._db() as connection:
            require(connection.execute('SELECT count(*) FROM leases').fetchone()[0] < MAX_ROWS)
            connection.execute('INSERT INTO leases VALUES (?, ?)', (token, encoded))

    def snapshot(self):
        with self._db() as connection:
            rows = connection.execute('SELECT token, payload FROM leases ORDER BY token LIMIT 1001').fetchall()
            require(len(rows) <= MAX_ROWS)
            result = []
            for token, payload in rows:
                require(isinstance(payload, str) and len(payload.encode()) <= 8192)
                record = _validate(json.loads(payload, object_pairs_hook=_pairs, parse_constant=_invalid_constant))
                require(token == record['token'])
                result.append(record)
            return result

    def _change(self, token, mutate):
        _hex(token, 32)
        with self._db() as connection:
            row = connection.execute('SELECT payload FROM leases WHERE token=?', (token,)).fetchone()
            require(row is not None)
            record = _validate(json.loads(row[0], object_pairs_hook=_pairs, parse_constant=_invalid_constant))
            require(record['token'] == token)
            mutate(record)
            connection.execute('UPDATE leases SET payload=? WHERE token=?', (_dump(record), token))

    def engine(self, token, identity):
        require(isinstance(identity, str) and re.fullmatch('[A-Za-z0-9:_-]{1,128}', identity))
        def mutate(record):
            require(record['engineId'] is None and all(r['state'] == 'unrequested' for r in record['resources'].values()))
            record['engineId'] = identity
        self._change(token, mutate)

    def intent(self, token, role):
        require(role in ROLES)
        def mutate(record):
            require(record['resources'][role]['state'] == 'unrequested')
            if role != 'volume':
                require(record['resources']['volume']['state'] == 'created')
            if role in ('broker', 'worker'):
                require(record['resources']['initialize']['state'] in ('created', 'removed'))
            if role == 'worker':
                require(record['resources']['broker']['state'] == 'created')
            record['resources'][role]['state'] = 'intent'
        self._change(token, mutate)

    def created(self, token, role, identifier=None):
        require(role in ROLES)
        def mutate(record):
            require(record['resources'][role]['state'] == 'intent')
            record['resources'][role] = {'state': 'created', 'id': identifier}
        self._change(token, mutate)

    def removed(self, token, role):
        require(role in ROLES)
        def mutate(record):
            require(record['resources'][role]['state'] == 'created')
            if role == 'volume':
                require(all(resource['state'] in ('unrequested', 'removed')
                            for name, resource in record['resources'].items() if name != 'volume'))
            record['resources'][role]['state'] = 'removed'
        self._change(token, mutate)

    def finish(self, token):
        _hex(token, 32)
        with self._db() as connection:
            row = connection.execute('SELECT payload FROM leases WHERE token=?', (token,)).fetchone()
            require(row is not None)
            record = _validate(json.loads(row[0], object_pairs_hook=_pairs, parse_constant=_invalid_constant))
            require(record['token'] == token)
            require(all(r['state'] in ('unrequested', 'removed') for r in record['resources'].values()))
            connection.execute('DELETE FROM leases WHERE token=?', (token,))

    def close(self):
        with self.mutex:
            require(self.active == 0)
            if self.connection is not None:
                self.connection.close()
                self.connection = None
            if self.lock_fd is not None:
                os.close(self.lock_fd)
                self.lock_fd = None
            self.closed = True

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()
