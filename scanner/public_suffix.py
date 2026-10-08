"""Offline, pinned domain grouping. Not a URL parser or destination grant."""

from dataclasses import dataclass
import hashlib
import ipaddress
import re
from types import MappingProxyType

import idna

MAX_PSL_BYTES = 1_048_576
MAX_PSL_LINES = 30000
MARKERS = ('// ===BEGIN ICANN DOMAINS===', '// ===END ICANN DOMAINS===',
           '// ===BEGIN PRIVATE DOMAINS===', '// ===END PRIVATE DOMAINS===')


def require(value):
    if not value:
        raise ValueError('public-suffix-invalid')


def canonical_host(value):
    require(isinstance(value, str) and 0 < len(value) <= 253
            and not value.endswith('.') and '%' not in value)
    try:
        result = idna.encode(value, uts46=True, std3_rules=True).decode('ascii').lower()
    except idna.IDNAError:
        raise ValueError('public-suffix-invalid') from None
    require(len(result) <= 253 and not result.endswith('.'))
    return result


@dataclass(frozen=True)
class DomainBoundary:
    hostname: str
    public_suffix: str | None
    registrable_domain: str | None
    matched_rule: str | None
    private_rule: bool


class PinnedPublicSuffixList:
    def __init__(self, raw, expected_sha256):
        require(idna.__version__ == '3.15')
        require(type(raw) is bytes and 0 < len(raw) <= MAX_PSL_BYTES
                and isinstance(expected_sha256, str) and re.fullmatch('[0-9a-f]{64}', expected_sha256)
                and hashlib.sha256(raw).hexdigest() == expected_sha256)
        try:
            lines = raw.decode('utf-8').split('\n')
        except UnicodeError:
            raise ValueError('public-suffix-invalid') from None
        require(len(lines) <= MAX_PSL_LINES)
        exact, wildcard, exceptions, seen = {}, {}, {}, set()
        phase, counts = 0, [0, 0]
        for source in lines:
            line = source.strip()
            if line in MARKERS:
                require(phase < 4 and line == MARKERS[phase])
                phase += 1
                continue
            if not line or line.startswith('//'):
                continue
            require(phase in (1, 3))
            rule = line.split()[0]
            require(len(rule) <= 255)
            kind = 'exception' if rule.startswith('!') else 'wildcard' if rule.startswith('*.') or rule == '*' else 'exact'
            body = rule[1:] if kind == 'exception' else rule[2:] if rule.startswith('*.') else rule
            body = '' if rule == '*' else canonical_host(body)
            require('*' not in body and '!' not in body)
            normalized = ('!' if kind == 'exception' else '*.' if kind == 'wildcard' and body else '') + body
            normalized = '*' if rule == '*' else normalized
            require(normalized not in seen)
            seen.add(normalized)
            private = phase == 3
            {'exact': exact, 'wildcard': wildcard, 'exception': exceptions}[kind][body] = private
            counts[int(private)] += 1
        require(phase == 4 and all(counts))
        require(all('.' in rule and rule.split('.', 1)[1] in wildcard for rule in exceptions))
        self.sha256 = expected_sha256
        self.exact, self.wildcard, self.exceptions = (MappingProxyType(value) for value in (exact, wildcard, exceptions))

    def classify(self, hostname):
        require(isinstance(hostname, str) and 0 < len(hostname) <= 253 and '%' not in hostname)
        try:
            address = ipaddress.ip_address(hostname)
        except ValueError:
            pass
        else:
            return DomainBoundary(address.compressed, None, None, None, False)
        host = canonical_host(hostname)
        labels = host.split('.')
        suffix_count, matched, private = 1, '*', self.wildcard.get('', False)
        exception = None
        for index in range(len(labels)):
            tail = '.'.join(labels[index:])
            count = len(labels) - index
            if tail in self.exceptions and (exception is None or count > exception[0]):
                exception = (count, tail, self.exceptions[tail])
            if tail in self.exact and count >= suffix_count:
                suffix_count, matched, private = count, tail, self.exact[tail]
            if index > 0 and tail in self.wildcard and count + 1 > suffix_count:
                suffix_count, matched, private = count + 1, '*.' + tail, self.wildcard[tail]
        if exception is not None:
            count, tail, private = exception
            suffix_count, matched = count - 1, '!' + tail
        suffix = '.'.join(labels[-suffix_count:])
        domain = '.'.join(labels[-suffix_count - 1:]) if len(labels) > suffix_count else None
        return DomainBoundary(host, suffix, domain, matched, private)
