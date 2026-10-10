"""Portable benchmark accounting tests; never a native renderer proof."""
import json
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import verify_video_renderer as benchmark


def main():
    good = SimpleNamespace(media_type='video/mp4', codec='avc1', width=1080,
        height=1080, duration_ms=5000, frame_rate=30, frame_count=150, byte_length=3)
    def measured(sequence, times, metadata=good):
        items = iter(sequence)
        clocks = iter(times)
        def render(_):
            value = next(items)
            if isinstance(value, Exception):
                raise value
            return value
        validation = ({'side_effect': metadata} if isinstance(metadata, Exception)
                      else {'return_value': metadata})
        with patch.object(benchmark, 'validate_share_video_mp4', **validation):
            return benchmark.measure_attempts({}, len(sequence), render=render,
                clock=lambda: next(clocks))
    def rejects(report):
        try:
            benchmark.check_export_gate(report)
        except AssertionError:
            return
        raise AssertionError('failed export evidence passed gate')

    first, report = measured([b'abc', benchmark.VideoRenderError('PRIVATE_CANARY'), b'abc'],
        [0, 2, 2, 17, 17, 20])
    benchmark.require(first == b'abc' and report['successes'] == 2 and report['total'] == 3
        and report['attempts'][1] == {'attempt': 2, 'outcome': 'render-error', 'seconds': 15}
        and report['successP50Seconds'] == 2.5 and report['allAttemptMaxSeconds'] == 15
        and 'PRIVATE_CANARY' not in json.dumps(report), 'failure evidence was lost/leaked')
    rejects(report)
    _, report = measured([b'abc', b'abc'], [0, 1, 1, 2], benchmark.Mp4ValidationError('invalid', 'private'))
    benchmark.require(report['attempted'] == 2 and not report['aborted']
        and all(row['outcome'] == 'invalid-artifact' for row in report['attempts']),
        'known invalid MP4 lost validation evidence')
    rejects(report)
    _, report = measured([b'abc', b'abc'], [0, 1], RuntimeError('PRIVATE_VALIDATOR_CANARY'))
    benchmark.require(report['aborted'] and report['attempted'] == 1
        and 'PRIVATE_VALIDATOR_CANARY' not in json.dumps(report),
        'unexpected validator fault continued or leaked')
    rejects(report)
    output = StringIO()
    with patch.object(benchmark, 'arguments', return_value=SimpleNamespace(
            attempts=2, seeded_gallery=False, output=None)), \
            patch.object(benchmark, 'load_bundle', return_value={}), \
            patch.object(benchmark, 'measure_attempts', return_value=(None, report)), \
            redirect_stdout(output):
        try:
            benchmark.main()
        except AssertionError:
            pass
        else:
            raise AssertionError('failed CLI gate returned success')
    benchmark.require(json.loads(output.getvalue())['successes'] == report['successes'],
        'CLI lost summary before gate rejection')
    first, report = measured([benchmark.VideoRenderError('private')] * 2, [0, 15, 15, 30])
    benchmark.require(first is None and report['successP50Seconds'] is None
        and not report['successfulBytesDeterministic'], 'empty success sample misreported')
    rejects(report)
    _, report = measured([b'abc', b'xyz'], [0, 1, 1, 2])
    rejects(report)
    _, report = measured([b'abc', b'abc'], [0, 10, 10, 11])
    rejects(report)  # Exact ten-second boundary still fails.
    _, report = measured([b'abc', b'abc'], [0, 1, 1, 2],
        SimpleNamespace(**{**vars(good), 'frame_count': 149}))
    benchmark.require(all(row['outcome'] == 'invalid-artifact' for row in report['attempts']),
        'invalid cadence was admitted')
    rejects(report)
    _, report = measured([b'abc'] * 20, list(range(40)))
    benchmark.check_export_gate(report)
    _, report = measured([b'abc'] * 19 + [benchmark.VideoRenderError('private')], list(range(40)))
    benchmark.check_export_gate(report)  # 19/20 meets the existing sample rule, not population confidence.
    _, report = measured([RuntimeError('PRIVATE_OPERATIONAL_CANARY'), b'abc'], [0, 1])
    benchmark.require(report['aborted'] and report['attempted'] == 1 and report['total'] == 2
        and report['attempts'][0]['outcome'] == 'unexpected-error'
        and 'PRIVATE_OPERATIONAL_CANARY' not in json.dumps(report),
        'operational fault restarted workers, lost evidence or leaked error')
    rejects(report)
    for count in (True, 1, 21, 2.0):
        try:
            benchmark.measure_attempts({}, count, render=lambda _: b'abc')
        except AssertionError:
            continue
        raise AssertionError('invalid attempt count accepted')
    print('Benchmark accounting passes: all failure timings retained, no error-text leakage, '
          'invalid artifacts/determinism/deadline rejected, 95% sample boundary preserved. '
          'No native performance/reliability proof.')


if __name__ == '__main__':
    main()
