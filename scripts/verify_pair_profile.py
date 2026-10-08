"""Portable fixture diagnostic framing tests; not native capture evidence."""

from contextlib import redirect_stdout
import io
from pathlib import Path
import sys
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.verify_pair_transport import print_profile


def main():
    raw = (b'profile installed 0\nprofile browser-end 894\nprofile navigation-end 489\n'
           b'profile bridge-listener-stop-begin 0\nprofile probe-error 1\n'
           b'profile unknown-secret 123\nprofile browser-end secret\n'
           b'profile browser-end 123456789\n{"result":"private-fixture-canary"}\n'
           b'profile browser-end 1 extra\nprofile browser-end -1\n')
    output = io.StringIO()
    with redirect_stdout(output):
        markers = print_profile([SimpleNamespace(data=raw)])
    expected = {'installed', 'browser-end', 'navigation-end', 'bridge-listener-stop-begin', 'probe-error'}
    if markers != expected or len(output.getvalue().splitlines()) != len(expected):
        raise AssertionError('profile marker framing/type comparison failed')
    if 'secret' in output.getvalue() or 'private-fixture-canary' in output.getvalue():
        raise AssertionError('unknown diagnostic content was printed')
    print('Verified ASCII marker comparisons and bounded allowlisted profile output; no native claim.')


if __name__ == '__main__':
    main()
