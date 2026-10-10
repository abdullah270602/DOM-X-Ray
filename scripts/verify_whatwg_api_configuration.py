"""CLI configuration/order proof with real pin validation and mocked hosting."""

from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
import sys
from unittest.mock import patch, Mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scanner.local_scan_api import build_target_parser, main
from scanner.whatwg_url import WhatwgUrlParser
from scripts.verify_whatwg_api_admission import fixture_parser


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def invoke(arguments, accepted):
    host = Mock(server_port=8787)
    service = Mock()
    errors, output = StringIO(), StringIO()
    with patch.object(sys, 'argv', ['local_scan_api', *arguments]), \
            patch('scanner.local_scan_api.build_result_backend', return_value=object()) as backend, \
            patch('scanner.local_scan_api.LocalScanJobService', return_value=service) as construct, \
            patch('scanner.local_scan_api.build_server', return_value=host) as server, \
            redirect_stderr(errors), redirect_stdout(output):
        succeeded = False
        try:
            main()
            succeeded = True
        except SystemExit as error:
            require(error.code == 2, 'unexpected CLI configuration exit')
        require(succeeded == accepted, 'CLI configuration outcome differs')
        if accepted:
            require(backend.call_count == construct.call_count == server.call_count == 1,
                    'configured CLI did not wire authorities once')
            return construct.call_args.kwargs['target_parser']
        require(not backend.called and not construct.called and not server.called,
                'invalid parser started storage, job pool or network hosting')
        require('private-config-canary' not in errors.getvalue(), 'configuration details leaked')


def main_test():
    parser = fixture_parser()
    values = [str(parser.node), *parser.pins]
    names = ['--url-parser-node', '--url-parser-node-sha256',
             '--url-parser-module-sha256', '--url-parser-worker-sha256']
    arguments = [part for pair in zip(names, values) for part in pair]
    require(build_target_parser(None, None, None, None) is None and invoke([], True) is None,
            'default configured parser implicitly')
    configured = invoke(arguments, True)
    require(type(configured) is WhatwgUrlParser and configured.pins == parser.pins
            and configured.node == parser.node, 'CLI altered explicit pins/path')
    for missing in range(4):
        partial = [part for index, pair in enumerate(zip(names, values)) if index != missing for part in pair]
        invoke(partial, False)
    for index in range(4):
        invalid = values.copy()
        invalid[index] = 'private-config-canary' if index == 0 else '0' * 64
        invoke([part for pair in zip(names, invalid) for part in pair], False)
    invoke(['--url-parser-node', 'relative-node', *arguments[2:]], False)
    print('Explicit CLI parser pins verified; default unset; partial/mismatched/relative config stops before storage/pool/server. Hosting was mocked, not deployed.')


if __name__ == '__main__':
    main_test()
