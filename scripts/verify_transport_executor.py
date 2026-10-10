"""Portable adapter controls; transport outcomes are deliberately controlled."""
from pathlib import Path
import sys
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scanner.destination_policy import DestinationPolicy, DestinationPolicyError
from scanner.local_scan_api import TransportScanExecutor, ScanExecutionError
from scanner.scan_transport import ScanTransportResult
from scripts.verify_local_scan_api import require


def main():
    launch, supervisor = Mock(), Mock()
    policy = DestinationPolicy(lambda _h, _p: ['1.1.1.1'])
    policy_factory = Mock(return_value=policy)
    config = dict(supported_targets=('https://xray.test/',),
        policy_factory=policy_factory, launch_worker=launch,
        worker_supervisor=supervisor, deadline_seconds=15)
    executor = TransportScanExecutor(**config)
    require(executor.supports('https://XRAY.test:443/') and not executor.supports('https://xray.test/other')
        and not executor.supports('https://arbitrary.example/')
        and not executor.supports('https://xray.test/?'), 'exact target fence changed')
    with patch('scanner.local_scan_api.run_public_scan_transport') as transport:
        try:
            executor.execute('https://arbitrary.example/', lambda _: None)
        except ScanExecutionError as error:
            require(error.code == 'scanner-disabled', 'unsupported target error changed')
        else:
            raise AssertionError('unsupported execution admitted')
        require(not transport.called and not launch.called and not supervisor.called and not policy_factory.called,
            'unsupported target reached transport')
        for outcome, code in [('worker-timeout', 'scan-timeout'), ('worker-crashed', 'worker-crashed'),
                ('worker-invalid-result', 'invalid-result'), ('invalid-record', 'invalid-result'),
                ('invalid-envelope', 'invalid-result'), ('launch-failed', 'capture-failed'),
                ('supervisor-failed', 'capture-failed')]:
            transport.return_value = ScanTransportResult(outcome, None, None)
            try:
                executor.execute('https://xray.test/', lambda _: None)
            except ScanExecutionError as error:
                require(error.code == code, 'transport error mapping changed')
            else:
                raise AssertionError('failed transport was mapped/published')
            kwargs = transport.call_args.kwargs
            require(kwargs['policy'] is policy and kwargs['launch_worker'] is launch
                and kwargs['worker_supervisor'] is supervisor and kwargs['deadline_seconds'] == 15
                and callable(kwargs['schema_validator']) and callable(kwargs['semantic_validator']),
                'operator transport boundary was replaced')
        for key in ('schema_validator', 'semantic_validator'):
            try:
                kwargs[key]({})
            except Exception:
                pass
            else:
                raise AssertionError('empty record passed forwarded validator')
        transport.side_effect = DestinationPolicyError('private canary')
        try:
            executor.execute('https://xray.test/', lambda _: None)
        except ScanExecutionError as error:
            require(error.code == 'invalid-target' and 'canary' not in str(error), 'destination fault leaked')
        else:
            raise AssertionError('destination refusal admitted')
    require(policy_factory.call_count == 8, 'policy was not created once per supported scan')
    policies = [DestinationPolicy(lambda _h, _p: ['1.1.1.1']) for _ in range(2)]
    fresh = TransportScanExecutor(**{**config, 'policy_factory': Mock(side_effect=policies)})
    with patch('scanner.local_scan_api.run_public_scan_transport',
            return_value=ScanTransportResult('worker-timeout', None, None)) as transport:
        for policy in policies:
            try:
                fresh.execute('https://xray.test/', lambda _: None)
            except ScanExecutionError as error:
                require(error.code == 'scan-timeout' and transport.call_args.kwargs['policy'] is policy,
                    'scan reused startup policy instead of new factory result')
            else:
                raise AssertionError('controlled timeout admitted')
    private = TransportScanExecutor(**{**config,
        'policy_factory': lambda: DestinationPolicy(lambda _h, _p: ['127.0.0.1'])})
    try:
        private.execute('https://xray.test/', lambda _: None)
    except ScanExecutionError as error:
        require(error.code == 'invalid-target' and not launch.called and not supervisor.called,
            'private resolution reached worker')
    else:
        raise AssertionError('real destination policy private answer admitted')
    invalid = [dict(supported_targets=()), dict(supported_targets=['https://xray.test/']),
        dict(supported_targets=('https://xray.test/',) * 2), dict(supported_targets=('https://XRAY.test/',)),
        dict(supported_targets=('https://xray.test/?',)), dict(policy_factory=object()), dict(launch_worker=None),
        dict(worker_supervisor=object()), dict(deadline_seconds=True), dict(deadline_seconds=0),
        dict(deadline_seconds=16), dict(deadline_seconds=float('nan')), dict(deadline_seconds=float('inf')),
        dict(poster_renderer=None), dict(video_renderer=None), dict(result_id_factory=1)]
    for delta in invalid:
        try:
            TransportScanExecutor(**{**config, **delta})
        except (ValueError, TypeError):
            continue
        raise AssertionError('invalid operator configuration accepted')
    for factory in (lambda: object(), Mock(side_effect=RuntimeError('PRIVATE_CANARY'))):
        broken = TransportScanExecutor(**{**config, 'policy_factory': factory})
        try:
            broken.execute('https://xray.test/', lambda _: None)
        except ScanExecutionError as error:
            require(error.code == 'internal-error' and not launch.called and not supervisor.called
                and 'PRIVATE_CANARY' not in str(error), 'policy factory fault leaked/reached worker')
        else:
            raise AssertionError('bad policy factory admitted')
    print('Transport executor controls pass: exact targets, explicit trusted seams, validators, '
          'content-free failure mapping and configuration refusal. Controlled outcomes, not public capture.')


if __name__ == '__main__':
    main()
