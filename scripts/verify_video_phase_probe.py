"""Test-only phase observations inside the unchanged supervised video deadline."""

from __future__ import annotations

import json
import argparse
import math
from io import BytesIO
import sys
import time
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
PHASES = ('worker-start', 'storyboard-generated', 'storyboard-validated',
          'raster-start', 'raster-ready', 'encode-start', 'encode-ready',
          'validation-start', 'validation-ready')


def read_phases(path):
    if not path.exists():
        return []
    if path.is_symlink() or not path.is_file():
        raise AssertionError('phase observation is not a regular file')
    with path.open('rb') as source:
        payload = source.read(4097)
    if len(payload) > 4096:
        raise AssertionError('phase observation exceeded its byte envelope')
    events = json.loads(payload)
    if not isinstance(events, list) or len(events) > len(PHASES):
        raise AssertionError('phase observation has an invalid shape')
    previous = 0
    for index, event in enumerate(events):
        if (not isinstance(event, dict) or set(event) != {'phase', 'elapsedSeconds'}
                or event['phase'] != PHASES[index]
                or type(event['elapsedSeconds']) not in (int, float)
                or not math.isfinite(event['elapsedSeconds'])
                or event['elapsedSeconds'] < previous):
            raise AssertionError('phase observation failed validation')
        previous = event['elapsedSeconds']
    return events


def verify_phase_reader():
    class Observation:
        def __init__(self, payload):
            self.payload = payload
        def exists(self):
            return True
        def is_symlink(self):
            return False
        def is_file(self):
            return True
        def open(self, mode):
            return BytesIO(self.payload)

    valid = [{'phase': phase, 'elapsedSeconds': index / 10}
             for index, phase in enumerate(PHASES)]
    for length in range(len(valid) + 1):
        value = valid[:length]
        if read_phases(Observation(json.dumps(value).encode())) != value:
            raise AssertionError('valid phase prefix was rejected')
    invalid = [b' ' * 4097, b'{}', b'null', b'[{}]', b'not-json',
               json.dumps(valid + valid[:1]).encode()]
    for time_value in (-1, True, '0', float('nan'), float('inf')):
        invalid.append(json.dumps([{'phase': PHASES[0], 'elapsedSeconds': time_value}]).encode())
    invalid.extend([b'[{"phase":"private-content","elapsedSeconds":0}]',
        json.dumps([valid[0], {'phase': PHASES[1], 'elapsedSeconds': -0.1}]).encode()])
    for payload in invalid:
        try:
            read_phases(Observation(payload))
        except (AssertionError, ValueError):
            continue
        raise AssertionError('malformed phase observation was accepted')
    print('Bounded phase reader: ordered prefixes accepted; oversize, malformed, '
          'unknown labels and invalid clocks rejected.')


def worker() -> int:
    from scanner import video_renderer_worker as video

    root = video._render_root()
    started = time.monotonic()
    events = []

    def observe(label):
        events.append({'phase': label, 'elapsedSeconds': round(time.monotonic() - started, 6)})
        video._write_atomic(root / 'phase-probe.json', json.dumps(events).encode('ascii'))

    def watched(function, before, after):
        def call(*args, **kwargs):
            observe(before)
            result = function(*args, **kwargs)
            observe(after)
            return result
        return call

    observe('worker-start')
    with patch.object(video, '_storyboard', watched(video._storyboard,
            'storyboard-generated', 'storyboard-validated')), patch.object(video,
            'rasterize_svg_screenshots', watched(video.rasterize_svg_screenshots,
            'raster-start', 'raster-ready')), patch.object(video, '_encode',
            watched(video._encode, 'encode-start', 'encode-ready')), patch.object(video,
            'validate_share_video_mp4', watched(video.validate_share_video_mp4,
            'validation-start', 'validation-ready')):
        return video.main()


def main() -> int:
    from scanner import video_renderer as renderer
    from scripts.verify_video_renderer import load_bundle

    original = renderer.run_worker_command
    observations = []
    parser = argparse.ArgumentParser()
    parser.add_argument('--attempts', type=int, default=2)
    parser.add_argument('--seeded-gallery', action='store_true')
    parser.add_argument('--verify-observations', action='store_true')
    options = parser.parse_args()
    if options.verify_observations:
        verify_phase_reader()
        return 0
    if not 2 <= options.attempts <= 10:
        parser.error('attempt count must be between 2 and 10')

    def probe(command, **kwargs):
        if command[1:3] != ['-m', 'scanner.video_renderer_worker']:
            raise AssertionError('unexpected video command')
        replacement = [command[0], str(Path(__file__).resolve()), '--worker', *command[3:]]
        started = time.monotonic()
        run = original(replacement, **kwargs)
        path = kwargs['result_path'].parent / 'phase-probe.json'
        events = read_phases(path)
        observations.append({'outcome': run.outcome,
            'supervisedSeconds': round(time.monotonic() - started, 6), 'phases': events})
        return run

    bundle = load_bundle('image-heavy')
    if options.seeded_gallery:
        from scanner.local_scan_api import FixtureScanExecutor
        captured = []
        def capture(value):
            captured.append(value)
            raise renderer.VideoRenderError('test-only deferred video render')
        FixtureScanExecutor(video_renderer=capture).execute('https://gallery.example/', lambda _: None)
        if len(captured) != 1:
            raise AssertionError('seeded gallery did not supply exactly one eligible video input')
        bundle = captured[0]
    for _ in range(options.attempts):
        with patch.object(renderer, 'run_worker_command', probe):
            try:
                payload = renderer.render_video_mp4(bundle)
            except renderer.VideoRenderError as error:
                print('render:', str(error))
            else:
                print('validatedVideoBytes:', len(payload))
        print(json.dumps(observations[-1], separators=(',', ':')), flush=True)
    return 0  # Diagnostic completion, not renderer/product success.


if __name__ == '__main__':
    if sys.argv[1:] == ['--worker']:
        raise SystemExit('worker arguments are missing')
    if len(sys.argv) > 1 and sys.argv[1] == '--worker':
        del sys.argv[1]
        try:
            raise SystemExit(worker())
        except Exception:
            raise SystemExit(1)
    raise SystemExit(main())
