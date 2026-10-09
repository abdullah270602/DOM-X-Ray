"""Pinned Node/Chromium relative resolution and independent destination denial."""

import hashlib
from pathlib import Path
import shutil
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from playwright.sync_api import sync_playwright
from scanner.destination_policy import DestinationPolicyError
from scanner.whatwg_url import WhatwgDestinationPolicy, WhatwgUrlParser
from scanner.origin_exchange import OriginExchange, OriginExchangeError
from scripts.verify_origin_exchange import Socket, response


def require(value, message):
    if not value:
        raise AssertionError(message)


def main():
    node = Path(shutil.which('node')).resolve(strict=True)
    module = ROOT / 'shared/public_url.mjs'
    parser = WhatwgUrlParser(node, **{name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in (('node_sha256', node), ('module_sha256', module),
                           ('worker_sha256', ROOT / 'scanner/public_url_worker.mjs'))})
    base = 'https://bücher.example/dir/page?q=base#old'
    accepted = ['../target', './%2e%2e/target', '?next=1', '?', '#', '', '#next',
        '//faß.example/a/../b', '/食狮', '../..//target', 'http://example.com:80/a/../b',
        'https://example.com/x%2fy', '../../../../../target']
    rejected = ['//user:secret-canary@example.com/', '//@example.com/', '//%65xample.com/',
        '//127.1/', '//0x7f.0.0.1/', '//0177.0.0.1/', '\t/path', '/\\evil.example/',
        'http:evil.example', '///example.com/', 'javascript:alert(1)', '/\ud800', '/x' + 'a' * 2048]
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        try:
            page = browser.new_page()
            page.add_script_tag(type='module', content=module.read_text() + '\nwindow.resolveDomXRay = resolvePublicUrl;')
            page.wait_for_function('typeof window.resolveDomXRay === "function"')
            for reference in accepted + rejected:
                observed = page.evaluate('([ref, base]) => window.resolveDomXRay(ref, base)', [reference, base])
                try:
                    result = parser.resolve(reference, base)
                except DestinationPolicyError as error:
                    require(reference in rejected and observed == {'ok': False, 'code': error.reason},
                            'Node/Chromium resolution rejection differed')
                else:
                    native = page.evaluate('([ref, base]) => new URL(ref, base).href', [reference, base])
                    require(reference in accepted and result == observed and result['href'] == native,
                            'Node/shared/native Chromium resolution differed')
            for bad_base in (None, '', 'https://user:secret-canary@example.com/', 'https://example.com./'):
                try:
                    parser.resolve('https://example.com/', bad_base)
                except DestinationPolicyError:
                    pass
                else:
                    raise AssertionError('invalid base ignored for absolute reference')
            print('Actual Chromium ' + browser.version + ': 13 admitted resolutions match native URL; 13 strict rejections agree with Node.')
        finally:
            browser.close()
    dns = []
    policy = WhatwgDestinationPolicy(lambda h, p: dns.append((h, p)) or ['8.8.8.8'], parser=parser)
    for reference in ('//１２７.０.０.１/private', 'http://[::1]/', '//metadata.google.internal/'):
        before = len(dns)
        try:
            policy.validate(policy.resolve_redirect(reference, base), purpose='redirect')
        except DestinationPolicyError as error:
            require(error.reason in ('forbidden-address', 'forbidden-hostname') and len(dns) == before,
                    'resolved forbidden authority contacted resolver')
        else:
            raise AssertionError('resolved forbidden authority granted')
    for location in (b'../%2e%2e/target?q=1', b'//127.0.0.1/private'):
        sock = Socket(response(headers=b'Location: ' + location + b'\r\n', status=b'302 Found'))
        exchange = OriginExchange(policy, user_agent='DOM-X-Ray-Relative-Proof/0.1',
            connector=lambda _grant, **_kwargs: sock)
        before = len(dns)
        try:
            result = exchange.fetch('https://example.com/dir/page', purpose='initial')
        except OriginExchangeError as error:
            require(location.startswith(b'//127.') and str(error) == 'destination-policy', 'wrong redirect rejection')
        else:
            require(result.status == 302 and dns[-1] == ('example.com', 443), 'relative redirect not revalidated')
        require(sock.closed and len(dns) == before + (1 if location.startswith(b'//127.') else 2),
                'redirect contacted forbidden DNS or leaked socket')
    print('Resolved private/local targets denied before DNS; OriginExchange relative redirect revalidation and cleanup verified.')


if __name__ == '__main__':
    main()
