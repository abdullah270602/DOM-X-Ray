"""Bound local admission maps without eviction of active/reusable entries."""
from pathlib import Path
import sys
from threading import Barrier, Thread

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scanner.admission_policy import ScanAdmissionGate


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def main():
    now = [100.0]
    gate = ScanAdmissionGate(duplicate_window_seconds=30, origin_cooling_seconds=10,
        clock=lambda: now[0], max_target_reservations=2, max_origin_reservations=3)
    a, b = 'https://a.example/', 'https://b.example/'
    require(gate.reserve(a).action == gate.reserve(b).action == 'scan', 'initial reservations failed')
    gate.complete(b, 'result-b')
    for index in range(64):
        decision = gate.reserve(f'https://cold{index}.example/')
        require(decision.reason == 'admission-capacity' and decision.retry_after_seconds == 30
                and len(gate._targets) == 2 and len(gate._origins) == 2,
                'target saturation allocated or evicted state')
    require(gate.reserve(b).reusable_result_id == 'result-b', 'capacity blocked existing reuse')
    require(gate.reserve(a).reason == 'identical-scan-in-flight', 'capacity changed active duplicate')
    require(gate.reserve('https://a.example/other').reason == 'origin-cooling', 'capacity replaced cooling')
    now[0] = 130
    require(gate.reserve(a).reason == 'identical-scan-in-flight'
            and a in gate._targets and b not in gate._targets,
            'window expiry evicted active reservation or retained expired result')
    gate.complete(a, 'late-result-a')
    require(gate._targets[a].result_id == 'late-result-a', 'late active completion lost reservation')
    # Existing duplicate expiry is submission-based, not reset by completion.
    require(gate.reserve(a).action == 'scan', 'late completion unexpectedly reset duplicate TTL')
    gate.abandon(a)
    require(not gate._targets and gate._origins, 'abandon erased origin cooling')

    origin_gate = ScanAdmissionGate(duplicate_window_seconds=30, origin_cooling_seconds=10,
        clock=lambda: now[0], max_target_reservations=3, max_origin_reservations=1)
    require(origin_gate.reserve(a).action == 'scan', 'origin setup failed')
    origin_gate.complete(a, 'delete-me')
    origin_gate.forget_result('delete-me')
    for index in range(64):
        decision = origin_gate.reserve(f'https://new{index}.example/')
        require(decision.reason == 'admission-capacity' and decision.retry_after_seconds == 10
                and not origin_gate._targets and len(origin_gate._origins) == 1,
                'deletion bypassed cooling/capacity or flood grew origin map')
    now[0] += 10
    require(origin_gate.reserve(b).action == 'scan' and len(origin_gate._origins) == 1,
            'exact origin expiry did not release capacity')

    active_gate = ScanAdmissionGate(duplicate_window_seconds=10, origin_cooling_seconds=1,
        clock=lambda: now[0], max_target_reservations=1)
    require(active_gate.reserve(a).action == 'scan', 'active setup failed')
    now[0] += 11
    decision = active_gate.reserve(b)
    require(decision.reason == 'admission-capacity' and decision.retry_after_seconds == 1
            and list(active_gate._targets) == [a], 'all-active cap expiry lost original reservation')
    active_gate.abandon(a)
    require(active_gate.reserve(b).action == 'scan', 'active release did not restore capacity')

    concurrent = ScanAdmissionGate(duplicate_window_seconds=30, origin_cooling_seconds=10,
        max_target_reservations=2, max_origin_reservations=2)
    barrier = Barrier(20)
    decisions, errors = [], []
    def reserve(index):
        try:
            barrier.wait(timeout=3)
            decisions.append(concurrent.reserve(f'https://parallel{index}.example/'))
        except Exception as error:
            errors.append(type(error).__name__)
    threads = [Thread(target=reserve, args=(index,)) for index in range(20)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=4)
    require(not errors and not any(thread.is_alive() for thread in threads)
            and len(decisions) == 20 and sum(d.action == 'scan' for d in decisions) == 2
            and len(concurrent._targets) == len(concurrent._origins) == 2,
            'concurrent reservations exceeded capacity or failed to terminate')

    for name in ('max_target_reservations', 'max_origin_reservations'):
        for invalid in (0, -1, True, 1.5, '1', None):
            reject_configuration({name: invalid})
    for name in ('duplicate_window_seconds', 'origin_cooling_seconds'):
        for invalid in (0, -1, True, float('nan'), float('inf'), '1', None, 2 ** 2000):
            reject_configuration({name: invalid})
    print('Admission caps: cold floods, active preservation/late completion, reuse, deletion/cooling, '
          'exact expiry and concurrent limits pass. Count bounds, not distributed or byte-memory proof.')


def reject_configuration(overrides):
    settings = dict(duplicate_window_seconds=30, origin_cooling_seconds=10)
    settings.update(overrides)
    try:
        ScanAdmissionGate(**settings)
    except ValueError:
        return
    raise AssertionError('invalid admission configuration accepted')


if __name__ == '__main__':
    main()
