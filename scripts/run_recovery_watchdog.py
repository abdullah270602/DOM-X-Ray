"""Foreground operator launcher; does not install a service or enable scans."""

import argparse
from dataclasses import asdict
import json
from pathlib import Path
import signal
import sys
from threading import Event

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scanner.recovery_configuration import load_recovery_registry


def emit(value):
    print(json.dumps(value, separators=(',', ':'), allow_nan=False), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--configuration', type=Path, required=True)
    parser.add_argument('--configuration-sha256', required=True)
    parser.add_argument('--check', action='store_true', help='validate configuration bindings without recovery')
    parser.add_argument('--max-ticks', type=int, help='optional finite fixture/operator run, 1 through 1000')
    options = parser.parse_args()
    if options.max_ticks is not None and not 1 <= options.max_ticks <= 1000:
        emit({'status': 'configuration-fault'})
        return 2
    try:
        registry = load_recovery_registry(options.configuration, options.configuration_sha256)
    except Exception:
        emit({'status': 'configuration-fault'})
        return 2
    emit({'status': 'registered', 'entries': len(registry.pollers)})
    if options.check:
        return 0
    stop, handlers, previous = Event(), {}, {}
    def terminate(_number, _frame):
        stop.set()
    def health(receipt):
        if receipt.entry_index is None:
            return
        value = asdict(receipt.outcome)
        # Emit transitions or nonzero work, not an unbounded idle heartbeat.
        index = receipt.entry_index
        if previous.get(index) != value or value['resolved']:
            emit({'entry_index': index, 'outcome': value})
            previous[index] = value
    try:
        for number in (signal.SIGINT, signal.SIGTERM):
            handlers[number] = signal.signal(number, terminate)
        registry.run(stop, on_status=health, max_ticks=options.max_ticks)
        emit({'status': 'stopped'})
        return 0
    except Exception:
        emit({'status': 'watchdog-fault'})
        return 3
    finally:
        for number, handler in handlers.items():
            signal.signal(number, handler)


if __name__ == '__main__':
    raise SystemExit(main())
