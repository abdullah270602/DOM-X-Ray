"""Bounded replacement-controller pass. Never creates resources or admits scans.

Automatic watchdog deployment and independent cgroup-empty proof remain gates.
Unknown/absent intents are retained for later observation, not aged out.
"""

from dataclasses import dataclass
import json
import re
import time

from scanner.docker_broker_pair_supervisor import DockerBrokerPairSupervisor
from scanner.docker_worker_supervisor import _require
from scanner.lease_journal import LeaseJournal
from scanner.worker_supervisor import _validated_deadline


@dataclass(frozen=True)
class RecoveryReport:
    resolved: int
    retained: int
    deferred: int
    skipped: int
    next_after: str | None


def _name(token, role):
    return 'dom-x-ray-pair-' + ('' if role == 'volume' else role + '-') + token


def _remaining(deadline):
    _require(time.monotonic() < deadline, 'lease-recovery-deadline')


def _note(supervisor, deadline, method, *args):
    _remaining(deadline)
    getattr(supervisor.journal, method)(*args)
    # A committed finish cannot be reported as retained merely because its
    # non-preemptible local transaction crossed the scheduling deadline.
    if method != 'finish':
        _remaining(deadline)


def _lookup(supervisor, token, role, deadline):
    _remaining(deadline)
    name = _name(token, role)
    arguments = (['volume', 'ls', '-q', '--filter', f'name=^{name}$'] if role == 'volume' else
                 ['container', 'ls', '-aq', '--no-trunc', '--filter', f'name=^/{name}$'])
    value = supervisor._call(arguments, deadline)
    _remaining(deadline)
    if value:
        _require(value == name if role == 'volume' else bool(re.fullmatch('[0-9a-f]{64}', value)),
                 'lease-recovery-ambiguous-lookup')
    return value


def _container(supervisor, record, role, deadline):
    token, resource = record['token'], record['resources'][role]
    identifier = _lookup(supervisor, token, role, deadline)
    _require(bool(identifier), 'lease-recovery-absence-unresolved')
    if resource['id'] is not None:
        _require(identifier == resource['id'], 'lease-recovery-id-mismatch')
    _remaining(deadline)
    row = supervisor._inspect(identifier, deadline)
    _remaining(deadline)
    supervisor._ownership(row, _name(token, role), token, identifier)
    supervisor._preflight_role(row, role, _name(token, role), token, identifier, _name(token, 'volume'),
                               require_unstarted=False)
    command = supervisor.roles[role].command
    _require(row['Image'] == supervisor.image_id
             and row['Config']['Entrypoint'] == [command[0]] and row['Config']['Cmd'] == list(command[1:])
             and row['Config']['User'] == {'initialize': '0:0', 'broker': '10002:10001', 'worker': '10001:10001'}[role],
             'lease-recovery-runtime-mismatch')
    if resource['state'] == 'intent':
        _note(supervisor, deadline, 'created', token, role, identifier)
        resource.update(state='created', id=identifier)
    _remaining(deadline)
    state = supervisor._cleanup(_name(token, role), token, identifier, deadline)
    _require(state is not None and not state['Running'] and state['Pid'] == 0, 'lease-recovery-stop-unproven')
    _note(supervisor, deadline, 'removed', token, role)
    resource['state'] = 'removed'


def recover_expired_leases(supervisor, *, budget_seconds=15, grace_seconds=5, max_leases=20,
                           after_token=None, now_ms=None):
    """Trusted operator API; cursor/time injection is not visitor input.

    Expiry is only scheduling eligibility. Ownership derives from the journal
    lock, daemon/runtime binding and exact resource inspections, never expiry.
    """
    _require(isinstance(supervisor, DockerBrokerPairSupervisor) and type(supervisor.journal) is LeaseJournal,
             'lease-recovery-configuration')
    budget_seconds = _validated_deadline(budget_seconds)
    _require(type(grace_seconds) is int and 0 <= grace_seconds <= 60
             and type(max_leases) is int and 1 <= max_leases <= 20, 'lease-recovery-bounds')
    _require(after_token is None or isinstance(after_token, str) and re.fullmatch('[0-9a-f]{32}', after_token),
             'lease-recovery-cursor')
    if now_ms is None:
        now_ms = int(time.time() * 1000)
    _require(type(now_ms) is int and 0 < now_ms < 2**53, 'lease-recovery-clock')
    deadline = time.monotonic() + budget_seconds
    resolved = retained = skipped = 0
    cursor = after_token
    with supervisor.journal.recovery_hold():
        records = supervisor.journal.snapshot()
        if after_token is not None:
            records = [r for r in records if r['token'] > after_token] + [r for r in records if r['token'] <= after_token]
        fingerprint = supervisor.runtime_fingerprint()
        eligible = []
        for record in records:
            if record['runtimeFingerprint'] != fingerprint or now_ms < record['expiresAtMs'] + grace_seconds * 1000:
                skipped += 1
            else:
                eligible.append(record)
        engine_id = None
        # No engine call when there are no expired matching leases.
        for record in eligible[:max_leases]:
            if time.monotonic() >= deadline:
                break
            cursor = record['token']
            token, resources = record['token'], record['resources']
            try:
                if all(r['state'] == 'unrequested' for r in resources.values()):
                    _note(supervisor, deadline, 'finish', token)
                    resolved += 1
                    continue
                if engine_id is None:
                    info = json.loads(supervisor._call(['info', '--format', '{{json .}}'], deadline))
                    _remaining(deadline)
                    _require(info['OSType'] == 'linux' and info['CgroupVersion'] == '2', 'lease-recovery-engine')
                    engine_id = info.get('ID')
                    _require(isinstance(engine_id, str) and bool(engine_id), 'lease-recovery-engine-identity')
                _require(record['engineId'] == engine_id, 'lease-recovery-daemon-mismatch')
                containers_resolved = True
                for role in ('worker', 'broker', 'initialize'):
                    resource = resources[role]
                    try:
                        if resource['state'] == 'removed':
                            _require(not _lookup(supervisor, token, role, deadline), 'lease-recovery-removed-resource-reappeared')
                        elif resource['state'] != 'unrequested':
                            _container(supervisor, record, role, deadline)
                    except Exception:
                        containers_resolved = False
                _require(containers_resolved, 'lease-recovery-containers-unresolved')
                volume = resources['volume']
                if volume['state'] == 'removed':
                    _require(not _lookup(supervisor, token, 'volume', deadline), 'lease-recovery-volume-reappeared')
                elif volume['state'] != 'unrequested':
                    _require(bool(_lookup(supervisor, token, 'volume', deadline)), 'lease-recovery-volume-absence-unresolved')
                    supervisor._volume_row(_name(token, 'volume'), token, deadline)
                    if volume['state'] == 'intent':
                        _note(supervisor, deadline, 'created', token, 'volume')
                    _remaining(deadline)
                    supervisor._remove_volume(_name(token, 'volume'), token, True, deadline)
                    _note(supervisor, deadline, 'removed', token, 'volume')
                # Recheck recorded removal proofs before forgetting the row.
                for role, resource in resources.items():
                    if resource['state'] != 'unrequested':
                        _require(not _lookup(supervisor, token, role, deadline), 'lease-recovery-final-absence')
                _require(time.monotonic() < deadline, 'lease-recovery-deadline')
                _note(supervisor, deadline, 'finish', token)
                resolved += 1
            except Exception:
                retained += 1
    return RecoveryReport(resolved, retained, len(eligible) - resolved - retained, skipped, cursor)
