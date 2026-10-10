"""Failure-path helpers only; no Docker resources or native restart claim."""

from pathlib import Path
import sys
from types import SimpleNamespace
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.verify_native_watchdog_restart import Receipts, stop_owned_jobs


def main():
    jobs = [('first', 'first-job'), ('second', 'second-job')]
    with patch('scripts.verify_native_watchdog_restart.stop_job', side_effect=[RuntimeError('private-canary'), None]) as stop:
        failures = stop_owned_jobs(jobs)
        if stop.call_args_list[0].args != jobs[1] or stop.call_args_list[1].args != jobs[0] or failures != ['RuntimeError']:
            raise AssertionError('stop failure skipped another Job or exposed raw error')
    with patch('scripts.verify_native_watchdog_restart.stop_job') as stop:
        if stop_owned_jobs(jobs) or stop.call_count != 2:
            raise AssertionError('successful stop helper faulted')
    receipts = object.__new__(Receipts)
    receipts.thread = SimpleNamespace(join=Mock(), is_alive=lambda: True)
    receipts.process = SimpleNamespace(stdout=SimpleNamespace(close=Mock()))
    receipts.failures = []
    try:
        receipts.close()
    except AssertionError:
        pass
    else:
        raise AssertionError('live pipe reader was accepted')
    if receipts.process.stdout.close.called:
        raise AssertionError('close attempted while a live reader may hold pipe lock')
    print('All owned Jobs attempted after failure; fixed error categories; no close against live reader. Not native evidence.')


if __name__ == '__main__':
    main()
