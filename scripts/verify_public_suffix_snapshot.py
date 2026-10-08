"""Verify the selected immutable official PSL; network access requires --fetch."""

import argparse
from pathlib import Path
import sys
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scanner.public_suffix import MAX_PSL_BYTES, PinnedPublicSuffixList

PSL_COMMIT = '3929462652695bad04f0a27afb600974014a3c8b'
PSL_SHA256 = '2919eb9803c91a3f73a507cc6fedc934de005543c22c4016f72e3343de5dd6e7'
PSL_URL = 'https://raw.githubusercontent.com/publicsuffix/list/' + PSL_COMMIT + '/public_suffix_list.dat'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument('--snapshot', type=Path)
    source.add_argument('--fetch', action='store_true')
    options = parser.parse_args()
    if options.fetch:
        with urllib.request.urlopen(PSL_URL, timeout=10) as response:
            raw = response.read(MAX_PSL_BYTES + 1)
    else:
        with options.snapshot.open('rb') as stream:
            raw = stream.read(MAX_PSL_BYTES + 1)
    rules = PinnedPublicSuffixList(raw, PSL_SHA256)
    if (len(rules.exact), len(rules.wildcard), len(rules.exceptions)) != (10018, 310, 8):
        raise AssertionError('selected PSL rule count changed')
    for host, expected in (
        ('www.example.co.uk', 'example.co.uk'), ('docs.alice.github.io', 'alice.github.io'),
        ('www.city.kawasaki.jp', 'city.kawasaki.jp'), ('食狮.公司.cn', 'xn--85x722f.xn--55qx5d.cn'),
    ):
        if rules.classify(host).registrable_domain != expected:
            raise AssertionError('selected PSL classification mismatch')
    print('Verified immutable full official PSL: 335389 bytes; 10018 exact, 310 wildcard, 8 exception rules.')
    print('Offline runtime, deployment packaging and shared URL-parser/capture adoption remain separate requirements.')


if __name__ == '__main__':
    main()
