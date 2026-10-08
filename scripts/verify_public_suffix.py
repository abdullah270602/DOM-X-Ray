"""Small explicit PSL fixture; not a full deployment snapshot certification."""

import hashlib
from pathlib import Path
import sys
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scanner.public_suffix import PinnedPublicSuffixList, MAX_PSL_BYTES

FIXTURE = '''// ===BEGIN ICANN DOMAINS===
com
uk
co.uk
jp
*.kawasaki.jp
!city.kawasaki.jp
*.foo.com
公司.cn
// ===END ICANN DOMAINS===
// ===BEGIN PRIVATE DOMAINS===
github.io
blogspot.com
// ===END PRIVATE DOMAINS===
'''.encode('utf-8')


def require(value):
    if not value:
        raise AssertionError('public suffix verifier failed')


def rejects(callback):
    try:
        callback()
    except ValueError:
        return
    raise AssertionError('invalid PSL/hostname accepted')


def make(raw):
    return PinnedPublicSuffixList(raw, hashlib.sha256(raw).hexdigest())


def main():
    rules = make(FIXTURE)
    cases = (
        ('www.example.com', 'com', 'example.com', False),
        ('www.example.co.uk', 'co.uk', 'example.co.uk', False),
        ('co.uk', 'co.uk', None, False),
        ('a.kawasaki.jp', 'a.kawasaki.jp', None, False),
        ('x.a.kawasaki.jp', 'a.kawasaki.jp', 'x.a.kawasaki.jp', False),
        ('www.city.kawasaki.jp', 'kawasaki.jp', 'city.kawasaki.jp', False),
        ('city.kawasaki.jp', 'kawasaki.jp', 'city.kawasaki.jp', False),
        ('foo.com', 'com', 'foo.com', False),
        ('bar.foo.com', 'bar.foo.com', None, False),
        ('x.bar.foo.com', 'bar.foo.com', 'x.bar.foo.com', False),
        ('docs.alice.github.io', 'github.io', 'alice.github.io', True),
        ('alice.blogspot.com', 'blogspot.com', 'alice.blogspot.com', True),
        ('github.io', 'github.io', None, True),
        ('a.unknown', 'unknown', 'a.unknown', False),
        ('unknown', 'unknown', None, False),
        ('WWW.EXAMPLE.COM', 'com', 'example.com', False),
        ('食狮.公司.cn', 'xn--55qx5d.cn', 'xn--85x722f.xn--55qx5d.cn', False),
        ('xn--85x722f.xn--55qx5d.cn', 'xn--55qx5d.cn', 'xn--85x722f.xn--55qx5d.cn', False),
        ('faß.com', 'com', 'xn--fa-hia.com', False),
    )
    for host, suffix, domain, private in cases:
        boundary = rules.classify(host)
        require((boundary.public_suffix, boundary.registrable_domain, boundary.private_rule) == (suffix, domain, private))
    require(rules.classify('alice.github.io').registrable_domain != rules.classify('bob.github.io').registrable_domain)
    explicit_default = make(FIXTURE.replace(b'github.io\nblogspot.com', b'*'))
    require(explicit_default.classify('example.unknown').private_rule is True
            and explicit_default.classify('example.com').private_rule is False)
    for host in ('127.0.0.1', '2001:db8::1', '8.8.8.8'):
        require(rules.classify(host).registrable_domain is None)
    print('exact/wildcard/exception/default rules, PRIVATE tenant separation, IDNA and IP distinction: verified')
    for host in ('', None, 'a..com', 'a.com.', 'https://example.com', 'a/b.com', 'x%20.com', 'x\0.com',
                 'x' * 254, 'a' * 64 + '.com', 'a。', '😀.com'):
        rejects(lambda: rules.classify(host))
    for raw in (b'', b'\xff', b'x' * (MAX_PSL_BYTES + 1), FIXTURE.replace(b'co.uk', b'co..uk'),
                FIXTURE.replace(b'*.foo.com', b'foo.*.com'), FIXTURE.replace(b'!city.kawasaki.jp', b'!city.com'),
                FIXTURE.replace(b'github.io', b'github.io\ngithub.io'),
                FIXTURE.replace(b'// ===END PRIVATE DOMAINS===', b''),
                FIXTURE.replace(b'// ===BEGIN ICANN DOMAINS===', b'// wrong marker')):
        rejects(lambda: make(raw))
    rejects(lambda: PinnedPublicSuffixList(FIXTURE, '0' * 64))
    with patch('scanner.public_suffix.idna.__version__', '3.11'):
        rejects(lambda: make(FIXTURE))
    print('bounded inputs, malformed list/host, missing markers, bad pin and wrong dependency version: rejected')
    print('Verified offline PSL rule primitive; full snapshot evidence has a separate verifier, shared URL/capture adoption remains open.')


if __name__ == '__main__':
    main()
