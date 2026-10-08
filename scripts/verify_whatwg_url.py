"""Actual Node/Chromium shared policy comparison and no-network destination seam."""

import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from playwright.sync_api import sync_playwright
from scanner.destination_policy import DestinationPolicy, DestinationPolicyError
from scanner.whatwg_url import WhatwgUrlParser
from scanner.docker_worker_supervisor import _PipeProcess


def require(value, message):
    if not value:
        raise AssertionError(message)


def main():
    node = Path(shutil.which('node')).resolve(strict=True)
    module, worker = ROOT / 'shared/public_url.mjs', ROOT / 'scanner/public_url_worker.mjs'
    pins = {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in
            (('node_sha256', node), ('module_sha256', module), ('worker_sha256', worker))}
    parser = WhatwgUrlParser(node, **pins)
    cases = [
        'https://EXAMPLE.com:443/a/../b', 'https://bücher.example/', 'https://faß.example/',
        'https://食狮.公司.cn/', 'https://مثال.إختبار/', 'http://[2606:4700:4700::1111]/',
        'https://example.com/%2e%2e/b', 'https://example.com/😀',
        'https://example.com/?', 'https://example.com/#', 'https://@example.com/',
        'https://user:secret-canary@example.com/', 'https://%65xample.com/', 'https://example.com:8443/',
        'http://2130706433/', 'http://127.1/', 'http://0177.0.0.1/', 'http://0x7f.0.0.1/',
        'https://example.com./', 'https://foo_bar.example/', 'https://example.com/\\private',
        ' https://example.com/', 'https://example.com/\ud800', 'http://127.0.0.1/',
        'http://１２７.０.０.１/', 'https://example.com/' + 'x' * 2048,
    ]
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        try:
            page = browser.new_page()
            page.add_script_tag(type='module', content=module.read_text() + '\nwindow.domXRayParser = parsePublicUrl;')
            page.wait_for_function('typeof window.domXRayParser === "function"')
            for url in cases:
                browser_result = page.evaluate('(value) => window.domXRayParser(value)', url)
                try:
                    node_result = parser.parse(url)
                except DestinationPolicyError as error:
                    require(browser_result == {'ok': False, 'code': error.reason}, 'Node/browser rejection differed')
                else:
                    require(node_result == browser_result, 'Node/browser canonicalization differed')
            print('Actual Chromium ' + browser.version + ': 26 shared-policy Node/browser cases agree.')
        finally:
            browser.close()
    calls = []
    policy = DestinationPolicy(lambda host, port: calls.append((host, port)) or ['8.8.8.8'])
    result = parser.parse('https://bücher.example/./a/../')
    destination = policy.validate(result['href'], purpose='initial')
    require(destination.hostname == 'xn--bcher-kva.example' and calls == [('xn--bcher-kva.example', 443)],
            'canonical Unicode host did not reach independent destination policy')
    for url in ('http://127.0.0.1/', 'http://１２７.０.０.１/', 'http://[::1]/'):
        before = len(calls)
        try:
            policy.validate(parser.parse(url)['href'], purpose='initial')
        except DestinationPolicyError as error:
            require(error.reason == 'forbidden-address' and len(calls) == before, 'literal bypass contacted DNS')
        else:
            raise AssertionError('canonical private literal authorized')
    require(parser.parse('https://example.com/script?v=1', purpose='subresource')['href'].endswith('?v=1'),
            'subresource query was removed')
    print('Canonical DNS grant and normalized private-literal denial before resolver contact: verified')
    for pin in pins:
        bad = {**pins, pin: '0' * 64}
        try:
            WhatwgUrlParser(node, **bad)
        except ValueError:
            pass
        else:
            raise AssertionError('wrong parser pin accepted')
    with patch.object(parser, '_guard', side_effect=OSError('private-path-canary')):
        try:
            parser.parse('https://example.com/')
        except DestinationPolicyError as error:
            require(str(error) == 'url-parser-unavailable', 'configuration fault leaked raw error')
        else:
            raise AssertionError('configuration drift ignored')
    print('Executable/module/worker pins and content-free configuration faults: verified')
    class Reply:
        def __init__(self, payload, mutate):
            self.nonce = json.loads(payload)['nonce']
            self.mutate = mutate
        def finish(self, _deadline):
            value = {'nonce': self.nonce, 'result': {'ok': True, 'policy': 'public-url-whatwg-v1',
                'href': 'https://example.com/', 'scheme': 'https', 'hostname': 'example.com', 'port': 443}}
            self.mutate(value)
            return 0, json.dumps(value).encode() + b'\n'
        def stop(self, _deadline):
            pass
    mutations = (
        lambda value: value.update(nonce='0' * 32),
        lambda value: value['result'].update(ok=1),
        lambda value: value['result'].update(hostname='different.example'),
        lambda value: value['result'].update(href='https://user:secret@example.com/'),
        lambda value: value['result'].update(href='https://example.com/?'),
        lambda value: value['result'].update(port=True),
    )
    with patch.object(parser, '_guard'):
        for mutation in mutations:
            with patch('scanner.whatwg_url._PipeProcess', side_effect=lambda _cmd, payload, _limit, **_kwargs: Reply(payload, mutation)):
                try:
                    parser.parse('https://example.com/')
                except DestinationPolicyError as error:
                    require(error.reason == 'url-parser-unavailable', 'malformed reply exposed a provider error')
                else:
                    raise AssertionError('malformed/inconsistent parser reply admitted')
    hanging = []
    def hang(_command, payload, limit, **kwargs):
        process = _PipeProcess([str(node), '-e', 'setInterval(()=>{},1000)'], payload, limit, **kwargs)
        hanging.append(process)
        return process
    with patch.object(parser, '_guard'), patch('scanner.whatwg_url._PipeProcess', side_effect=hang):
        try:
            parser.parse('https://example.com/')
        except DestinationPolicyError as error:
            require(error.reason == 'url-parser-unavailable', 'hung parser did not fail closed')
        else:
            raise AssertionError('hung parser admitted a URL')
    require(len(hanging) == 1 and hanging[0].process.wait(timeout=1) != 0, 'owned hanging parser did not terminate')
    print('Six malformed/inconsistent replies and actual hung Node process: rejected, owned process exited')
    with patch.dict(os.environ, {'NODE_OPTIONS': '--require=private-node-hook-canary'}):
        require(parser.parse('https://example.com/')['hostname'] == 'example.com',
                'host NODE_OPTIONS influenced the pinned parser')
    print('Host NODE_OPTIONS injection does not reach parser environment: verified')
    print('Verified shared structural URL seam; production parser isolation and broker/API/runtime adoption remain open.')


if __name__ == '__main__':
    main()
