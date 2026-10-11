"""Test-only closed Docker read batch. Not a resource or cleanup supervisor."""
from dataclasses import dataclass
import http.client
from io import BytesIO
import json
import math
from pathlib import Path
import re
import time

from scanner.docker_worker_supervisor import LABEL, _PipeProcess, _pairs, _invalid_constant
from scripts.verify_docker_control_latency import BODY_LIMIT, HEADER_LIMIT, info_identity, require


@dataclass(frozen=True)
class ContainerRead:
    identifier: str
    name: str
    token: str


def validate_plan(reads):
    require(type(reads) is tuple and 1 <= len(reads) <= 3, 'invalid read plan')
    for item in reads:
        require(type(item) is ContainerRead
            and isinstance(item.identifier, str) and re.fullmatch('[0-9a-f]{64}', item.identifier)
            and isinstance(item.token, str) and re.fullmatch('[0-9a-f]{32}', item.token)
            and isinstance(item.name, str) and re.fullmatch('dom-x-ray-[a-z0-9-]{1,100}', item.name),
            'invalid exact-owned read target')
    require(len({item.identifier for item in reads}) == len(reads), 'duplicate read target')


def requests(reads):
    validate_plan(reads)
    paths = ['/v1.51/info', *('/v1.51/containers/' + item.identifier + '/json' for item in reads),
        '/v1.51/info']
    return b''.join(('GET ' + path + ' HTTP/1.1\r\nHost: docker\r\nConnection: '
        + ('close' if index == len(paths) - 1 else 'keep-alive') + '\r\n\r\n').encode('ascii')
        for index, path in enumerate(paths))


def decode(payload, reads):
    validate_plan(reads)
    limit = (len(reads) + 2) * (BODY_LIMIT + HEADER_LIMIT)
    require(type(payload) is bytes and 0 < len(payload) <= limit, 'read wire outside envelope')
    source = BytesIO(payload)
    class Reader:
        def read(self, size=-1):
            return source.read(size)
        def readline(self, size=-1):
            return source.readline(size)
        def close(self):
            pass
        def flush(self):
            pass
    class Socket:
        def makefile(self, *_):
            return Reader()
    identities, rows = [], []
    for index in range(len(reads) + 2):
        start = source.tell()
        response = http.client.HTTPResponse(Socket())
        response.begin()
        require(source.tell() - start <= HEADER_LIMIT and response.version == 11,
            'unexpected read response headers')
        lengths = response.headers.get_all('Content-Length', [])
        codings = response.headers.get_all('Transfer-Encoding', [])
        require((len(lengths) == 1 and not codings) or
            (not lengths and len(codings) == 1 and codings[0].strip().lower() == 'chunked'),
            'ambiguous read response framing')
        if lengths:
            value = lengths[0].strip(' \t')
            require(re.fullmatch('[0-9]+', value) is not None, 'invalid read response length')
            value = value.lstrip('0') or '0'
            require(len(value) <= len(str(BODY_LIMIT)) and int(value) <= BODY_LIMIT,
                'oversized read response')
        body = response.read(BODY_LIMIT + 1)
        require(response.isclosed() and 0 < len(body) <= BODY_LIMIT, 'incomplete read response')
        if index in (0, len(reads) + 1):
            require(response.status == 200, 'engine bookend failed')
            identities.append(info_identity(body))
            continue
        value = json.loads(body, object_pairs_hook=_pairs, parse_constant=_invalid_constant)
        require(type(value) is dict, 'invalid inspect object')
        if response.status == 404:
            require(set(value) == {'message'} and type(value['message']) is str
                and 0 < len(value['message']) <= 4096, 'invalid not-found response')
            rows.append(None)  # Observation only, never durable removal proof.
        else:
            require(response.status == 200, 'inspect status refused')
            item = reads[index - 1]
            require(value.get('Id') == item.identifier and value.get('Name') == '/' + item.name
                and type(value.get('Config')) is dict and type(value['Config'].get('Labels')) is dict
                and value['Config']['Labels'].get(LABEL) == item.token, 'inspect ownership refused')
            rows.append(value)  # Full policy/resource/state preflight remains the caller's obligation.
    require(source.tell() == len(payload) and identities[0] == identities[1],
        'extra output or engine identity changed')
    return identities[0], tuple(rows)


def run(docker, reads, deadline):
    """Caller MUST be an owned worker; no standalone subprocess containment here."""
    payload = requests(reads)  # Validate before opening the client.
    candidate = Path(docker)
    require(candidate.is_absolute() and candidate.is_file() and not candidate.is_symlink(),
        'invalid Docker executable')
    require(type(deadline) in (int, float) and math.isfinite(deadline)
        and 0 < deadline - time.monotonic() <= 12, 'invalid/exhausted read budget')
    pipe = _PipeProcess([str(candidate.resolve(strict=True)), '--context', 'desktop-linux',
        'system', 'dial-stdio'], payload, (len(reads) + 2) * (BODY_LIMIT + HEADER_LIMIT),
        keep_stdin=True)
    try:
        code, output = pipe.finish(deadline)
        require(code == 0, 'read client failed')
        return decode(output, reads)
    finally:
        pipe.stop(deadline)
