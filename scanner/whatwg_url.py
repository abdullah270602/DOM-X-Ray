"""Operator-pinned, disposable Node parser. DNS/egress authorization stays separate."""

import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import time
from urllib.parse import urlsplit

from scanner.docker_worker_supervisor import _PipeProcess, _pairs, _invalid_constant
from scanner.destination_policy import DestinationPolicy, DestinationPolicyError

ROOT = Path(__file__).resolve().parents[1]


class WhatwgUrlParser:
    def __init__(self, node_executable, *, node_sha256, module_sha256, worker_sha256):
        self.node = Path(node_executable)
        self.module = ROOT / 'shared/public_url.mjs'
        self.worker = ROOT / 'scanner/public_url_worker.mjs'
        self.pins = (node_sha256, module_sha256, worker_sha256)
        try:
            self._guard()
        except Exception:
            raise ValueError('whatwg-parser-configuration') from None

    def _guard(self):
        for path, digest in zip((self.node, self.module, self.worker), self.pins):
            if (not path.is_absolute() or path.resolve(strict=True) != path or not path.is_file()
                    or not isinstance(digest, str) or not re.fullmatch('[0-9a-f]{64}', digest)
                    or path.stat().st_size > (268435456 if path == self.node else 65536)):
                raise ValueError('whatwg-parser-configuration')
            hasher = hashlib.sha256()
            with path.open('rb') as stream:
                total = 0
                while chunk := stream.read(1048576):
                    total += len(chunk)
                    if total > (268435456 if path == self.node else 65536):
                        raise ValueError('whatwg-parser-configuration')
                    hasher.update(chunk)
            if hasher.hexdigest() != digest:
                raise ValueError('whatwg-parser-configuration')

    def parse(self, url, *, purpose='initial'):
        if not isinstance(url, str) or not 0 < len(url) <= 2048 or purpose not in ('initial', 'redirect', 'subresource'):
            raise DestinationPolicyError('invalid-url')
        try:
            self._guard()
        except Exception:
            raise DestinationPolicyError('url-parser-unavailable') from None
        nonce = secrets.token_hex(16)
        payload = json.dumps({'url': url, 'purpose': purpose, 'nonce': nonce}, ensure_ascii=True).encode()
        if len(payload) > 16384:
            raise DestinationPolicyError('invalid-url')
        deadline = time.monotonic() + 2
        process = None
        try:
            environment = {'SystemRoot': os.environ['SystemRoot']} if os.name == 'nt' else {}
            process = _PipeProcess([str(self.node), str(self.worker)], payload, 16384, environment=environment)
            code, output = process.finish(deadline)
            if code != 0 or not output.endswith(b'\n') or output.count(b'\n') != 1:
                raise DestinationPolicyError('url-parser-unavailable')
            value = json.loads(output, object_pairs_hook=_pairs, parse_constant=_invalid_constant)
            if type(value) is not dict or set(value) != {'nonce', 'result'} or value['nonce'] != nonce:
                raise DestinationPolicyError('url-parser-unavailable')
            result = value['result']
            if type(result) is not dict or type(result.get('ok')) is not bool:
                raise DestinationPolicyError('url-parser-unavailable')
            if not result['ok']:
                allowed = {'invalid-url', 'credentials', 'malformed-authority', 'initial-target-data',
                           'unsupported-scheme', 'malformed-host', 'ambiguous-ipv4', 'disallowed-port'}
                if set(result) != {'ok', 'code'} or result['code'] not in allowed:
                    raise DestinationPolicyError('url-parser-unavailable')
                raise DestinationPolicyError(result['code'])
            if (set(result) != {'ok', 'policy', 'href', 'scheme', 'hostname', 'port'}
                    or result['policy'] != 'public-url-whatwg-v1' or result['scheme'] not in ('http', 'https')
                    or type(result['port']) is not int or result['port'] not in (80, 443)
                    or not isinstance(result['href'], str) or not 0 < len(result['href']) <= 2048
                    or not isinstance(result['hostname'], str) or not 0 < len(result['hostname']) <= 253):
                raise DestinationPolicyError('url-parser-unavailable')
            parsed = urlsplit(result['href'])
            port = parsed.port if parsed.port is not None else 443 if parsed.scheme == 'https' else 80
            if (not result['href'].isascii() or parsed.scheme != result['scheme']
                    or parsed.hostname != result['hostname'] or port != result['port']
                    or parsed.username is not None or parsed.password is not None
                    or '%' in parsed.netloc or (purpose == 'initial' and ('?' in result['href'] or '#' in result['href']))):
                raise DestinationPolicyError('url-parser-unavailable')
            return result
        except DestinationPolicyError:
            raise
        except Exception:
            raise DestinationPolicyError('url-parser-unavailable') from None
        finally:
            if process is not None:
                try:
                    process.stop(deadline)
                except Exception:
                    raise DestinationPolicyError('url-parser-unavailable') from None


class WhatwgDestinationPolicy(DestinationPolicy):
    """Opt-in trusted parser before independent legacy address authorization."""

    def __init__(self, resolver, *, parser, **options):
        if type(parser) is not WhatwgUrlParser:
            raise ValueError('whatwg-parser-configuration')
        super().__init__(resolver, **options)
        self.parser = parser

    def canonical_url(self, url, *, purpose):
        return self.parser.parse(url, purpose=purpose)['href']

    def validate(self, url, *, purpose):
        return super().validate(self.canonical_url(url, purpose=purpose), purpose=purpose)
