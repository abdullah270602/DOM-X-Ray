"""Real controlled Chromium PSL adoption; reserved hosts, not public egress."""

import copy
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sys
from threading import Thread
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from jsonschema import Draft202012Validator, FormatChecker
from playwright.sync_api import sync_playwright
from fixtures.browser.policy_proxy import run_policy_proxy
from scanner.browser_probe import probe_page
from scanner.public_suffix import PinnedPublicSuffixList
from scanner.scene_manifest import build_scene_manifest
from scanner.result_manifest import build_result_manifest
from scripts.validate_fixtures import ContractError, validate_semantics

PSL = b'''// ===BEGIN ICANN DOMAINS===
test
// ===END ICANN DOMAINS===
// ===BEGIN PRIVATE DOMAINS===
github.test
// ===END PRIVATE DOMAINS===
'''


def require(value, message):
    if not value:
        raise AssertionError(message)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass
    def do_GET(self):
        port = self.server.server_port
        if self.path == '/':
            body = (f'<!doctype html><html><head><title>Domain boundary fixture</title></head><body>'
                f'<main style="width:900px;height:500px"><h1>Independent tenants</h1>'
                f'<img width="120" height="80" src="http://cdn.alice.github.test:{port}/same.svg">'
                f'<img width="120" height="80" src="http://cdn.bob.github.test:{port}/other.svg">'
                f'<script src="http://bob.github.test:{port}/script.js"></script></main></body></html>').encode()
            content_type = 'text/html'
        elif self.path.endswith('.svg'):
            body = b'<svg xmlns="http://www.w3.org/2000/svg" width="120" height="80"><rect width="120" height="80" fill="red"/></svg>'
            content_type = 'image/svg+xml'
        else:
            body, content_type = b'void 0;', 'text/javascript'
        self.send_response(200)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(body)


def main():
    classifier = PinnedPublicSuffixList(PSL, hashlib.sha256(PSL).hexdigest())
    schema = Draft202012Validator(json.loads((ROOT / 'docs/SCAN_RECORD.schema.json').read_text()), format_checker=FormatChecker())
    scene_schema = Draft202012Validator(json.loads((ROOT / 'docs/SCENE_MANIFEST.schema.json').read_text()), format_checker=FormatChecker())
    result_schema = Draft202012Validator(json.loads((ROOT / 'docs/RESULT_MANIFEST.schema.json').read_text()), format_checker=FormatChecker())
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    server.daemon_threads = True
    serving = Thread(target=lambda: server.serve_forever(poll_interval=0.05))
    serving.start()
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True, args=['--proxy-bypass-list=<-loopback>'])
            print('Controlled Chromium version: ' + browser.version)
            try:
                records = []
                for host, grouping in (('alice.github.test', classifier), ('github.test', classifier),
                                       ('alice.github.test', None)):
                    with run_policy_proxy(server.server_port) as proxy:
                        record = probe_page(browser, f'http://{host}:{server.server_port}/',
                            proxy_server=f'http://127.0.0.1:{proxy.server_address[1]}', policy_block_log=proxy.blocked,
                            egress_observation_snapshot=proxy.snapshot_observations,
                            egress_correlation_key=proxy.correlation_key,
                            domain_classifier=grouping).record
                        schema.validate(record)
                        validate_semantics(record, label='domain-grouping-capture', validator=schema)
                        scene_schema.validate(build_scene_manifest(record))
                        result = build_result_manifest(record, result_id='r_' + 'a' * 32)
                        result_schema.validate(result)
                        if record['page']['registrableDomain'] is None:
                            require(result['pageIdentity'] == {'label': host, 'recordRef': '#/finalUrl',
                                    'derivation': 'url-hostname-v1'}, 'unknown page identity invented a registrable domain')
                        records.append(record)
                known, unknown, legacy = records
                by_host = {urlsplit(row['displayUrl']).hostname: row for row in known['resources']}
                require(known['page']['registrableDomain'] == 'alice.github.test', 'page tenant boundary collapsed')
                require(by_host['cdn.alice.github.test']['party'] == 'first'
                        and by_host['cdn.bob.github.test']['party'] == 'third'
                        and by_host['bob.github.test']['party'] == 'third', 'resource tenant parties incorrect')
                require(known['capture']['domainGrouping']['pslSha256'] == hashlib.sha256(PSL).hexdigest(),
                        'capture lost exact grouping snapshot')
                require(unknown['page']['registrableDomain'] is None
                        and all(row['party'] == 'unknown' for row in unknown['resources'])
                        and not any(item['kind'] == 'third-party' for item in unknown['insights']),
                        'suffix-only page fabricated third-party attribution')
                require(legacy['page']['registrableDomain'] == 'github.test'
                        and 'domainGrouping' not in legacy['capture'], 'legacy fixture mode silently changed')
                for mutation in ('missing-provenance', 'known-party', 'resource-rule'):
                    changed = copy.deepcopy(unknown)
                    if mutation == 'missing-provenance':
                        del changed['capture']['domainGrouping']
                    elif mutation == 'known-party':
                        changed['resources'][0]['party'] = 'third'
                    else:
                        changed['resources'][0]['partyRule'] = 'registrable-domain-v1-fixture'
                    try:
                        validate_semantics(changed, label='forged-grouping', validator=schema)
                    except ContractError:
                        pass
                    else:
                        raise AssertionError('forged grouping provenance/party accepted')
                print('Tenant separation, null/unknown page domain, exact provenance, scene admission and legacy mode: verified')
                print('Three forged provenance/party records: rejected')
            finally:
                browser.close()
    finally:
        server.shutdown()
        server.server_close()
        serving.join(timeout=2)
        require(not serving.is_alive(), 'fixture server did not stop')
    print('Verified real reserved-host Chromium domain grouping; public parser/egress/runtime adoption remains open.')


if __name__ == '__main__':
    main()
