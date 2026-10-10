"""Compare old/new encoders on all decoded frames, under owned supervision."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def candidate_command(command):
    command = list(command)
    # The production encoder remains the baseline. Transform only this test run.
    for _ in range(5):
        index = command.index('-stream_loop')
        if command[index + 1] != '-1':
            raise AssertionError('unexpected production image-loop option')
        del command[index:index + 2]
    index = command.index('-filter_complex') + 1
    if command[index].count('scale=1100:1100:flags=bicubic,') != 5:
        raise AssertionError('unexpected production stage graph')
    command[index] = command[index].replace('scale=1100:1100:flags=bicubic,',
        'scale=1100:1100:flags=bicubic,loop=loop=-1:size=1:start=0,setpts=N/(30*TB),')
    return command


def verify_command():
    from scanner import video_renderer_worker as worker
    captured = []
    class Captured(Exception):
        pass
    def capture(command, **kwargs):
        captured.append((command, kwargs))
        raise Captured
    with patch.object(worker.subprocess, 'run', capture):
        try:
            worker._encode(Path('ffmpeg'), tuple(Path(f'stage-{i}.png') for i in range(5)), Path('video.mp4'))
        except Captured:
            pass
    if len(captured) != 1 or captured[0][1]['timeout'] != 10:
        raise AssertionError('production encoding boundary changed')
    baseline = captured[0][0]
    candidate = candidate_command(baseline)
    stripped = []
    index = 0
    while index < len(baseline):
        if baseline[index] == '-stream_loop':
            index += 2
        else:
            stripped.append(baseline[index])
            index += 1
    restored = list(candidate)
    filter_index = restored.index('-filter_complex') + 1
    fragment = 'loop=loop=-1:size=1:start=0,setpts=N/(30*TB),'
    if restored[filter_index].count(fragment) != 5:
        raise AssertionError('candidate must reuse exactly five scaled frames')
    restored[filter_index] = restored[filter_index].replace(fragment, '')
    if restored != stripped or baseline.count('-stream_loop') != 5:
        raise AssertionError('candidate changed options beyond frame reuse')
    print('Command control passes: only five static-image loop mechanisms change; '
          'scene, crop, transitions, codec, output limits and encoding deadline preserved. '
          'No native equivalence/performance claim.')


def child(options):
    from scanner import video_renderer_worker as worker
    root = Path(options.root).resolve(strict=True)
    paths = tuple(root / f'stage-{index}.png' for index in range(5))
    output = root / (options.video if options.variant == 'decode' else f'{options.variant}.mp4')
    original_run = subprocess.run

    def encode_run(command, **kwargs):
        if options.variant == 'reuse':
            command = candidate_command(command)
        return original_run(command, **kwargs)

    if options.variant != 'decode':
        with patch.object(worker.subprocess, 'run', encode_run):
            worker._encode(Path(options.ffmpeg), paths, output)
    payload = output.read_bytes()
    metadata = worker.validate_share_video_mp4(payload)
    if options.variant != 'decode':
        worker._write_atomic(Path(options.result), json.dumps({
            'supervisorNonce': os.environ[worker.RESULT_NONCE_ENV], 'result': {
                'sha256': hashlib.sha256(payload).hexdigest(), 'bytes': metadata.byte_length}}).encode())
        return
    decoded = original_run([options.ffmpeg, '-hide_banner', '-loglevel', 'error',
        '-nostdin', '-threads:v', '1', '-i', str(output), '-map', '0:v:0',
        '-frames:v', '150', '-f', 'framemd5', '-'], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=4,
        check=True, creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
    if len(decoded.stdout) > 65536:
        raise AssertionError('decoded frame evidence exceeded envelope')
    lines = decoded.stdout.decode('ascii').splitlines()
    frames = [line.strip() for line in lines if line and not line.startswith('#')]
    if len(frames) != 150:
        raise AssertionError('decoded cadence is incomplete')
    evidence = {'frames': frames, 'headers': [line for line in lines if line.startswith('#')],
                'sha256': hashlib.sha256(payload).hexdigest(), 'bytes': metadata.byte_length}
    worker._write_atomic(Path(options.result), json.dumps({
        'supervisorNonce': os.environ[worker.RESULT_NONCE_ENV], 'result': evidence}).encode())


def main():
    from PIL import Image, ImageDraw
    from scanner.video_renderer import _trusted_ffmpeg_path, _minimal_environment
    from scanner.worker_supervisor import run_worker_command

    parser = argparse.ArgumentParser()
    parser.add_argument('--variant', choices=('legacy', 'reuse', 'decode'))
    parser.add_argument('--video')
    parser.add_argument('--root')
    parser.add_argument('--result')
    parser.add_argument('--ffmpeg')
    parser.add_argument('--verify-command', action='store_true')
    options = parser.parse_args()
    if options.verify_command:
        verify_command()
        return
    if options.variant:
        child(options)
        return
    ffmpeg = _trusted_ffmpeg_path()
    with tempfile.TemporaryDirectory(prefix='dom-xray-encode-equivalence-') as temporary:
        root = Path(temporary).resolve()
        # Product-sized synthetic stages with gradients, sharp text and geometry;
        # this tests encoder equivalence, not the actual browser raster pipeline.
        for index in range(5):
            image = Image.new('RGB', (1080, 1080))
            draw = ImageDraw.Draw(image)
            for row in range(1080):
                draw.line((0, row, 1079, row), fill=((row + index * 39) % 256,
                    (row // 3 + index * 53) % 256, (row // 7 + index * 71) % 256))
            for column in range(0, 1080, 47):
                draw.rectangle((column, 100, column + 13, 850), fill='white')
                draw.text((column, 900), f'{index}:{column}', fill='black')
            image.save(root / f'stage-{index}.png')
        evidence = {}
        for variant in ('reuse', 'legacy', 'reuse-repeat'):
            actual_variant = 'reuse' if variant == 'reuse-repeat' else variant
            if variant == 'reuse-repeat':
                (root / 'reuse.mp4').rename(root / 'reuse-first.mp4')
            result = root / f'{variant}.json'
            run = run_worker_command([sys.executable, str(Path(__file__).resolve()),
                '--variant', actual_variant, '--root', str(root), '--result', str(result),
                '--ffmpeg', str(ffmpeg)], result_path=result, deadline_seconds=15,
                cwd=ROOT, environment=_minimal_environment())
            print(f'{variant}: {run.outcome} {run.duration_ms / 1000:.3f}s', flush=True)
            if not run.artifact_eligible:
                raise AssertionError('encoder equivalence worker did not complete')
            evidence[variant] = json.loads(result.read_text())['result']
            decoded_result = root / f'{variant}-decoded.json'
            decoded_run = run_worker_command([sys.executable, str(Path(__file__).resolve()),
                '--variant', 'decode', '--video', f'{actual_variant}.mp4', '--root', str(root),
                '--result', str(decoded_result), '--ffmpeg', str(ffmpeg)],
                result_path=decoded_result, deadline_seconds=15, cwd=ROOT,
                environment=_minimal_environment())
            print(f'{variant}-decode: {decoded_run.outcome}', flush=True)
            if not decoded_run.artifact_eligible:
                raise AssertionError('frame inspection worker did not complete')
            evidence[variant].update(json.loads(decoded_result.read_text())['result'])
        if evidence['legacy']['frames'] != evidence['reuse']['frames']:
            raise AssertionError('decoded pixels or frame timestamps changed')
        if evidence['legacy']['headers'] != evidence['reuse']['headers']:
            raise AssertionError('decoded format/dimensions/timebase changed')
        if evidence['reuse'] != evidence['reuse-repeat']:
            raise AssertionError('reused-frame output is not deterministic')
        print('All 150 decoded frame hashes/timestamps and format headers match; '
              'candidate MP4 validates and repeated output is byte-identical. '
              'Synthetic stages only, not end-to-end reliability.')


if __name__ == '__main__':
    main()
