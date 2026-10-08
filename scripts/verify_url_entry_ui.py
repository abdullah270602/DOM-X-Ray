"""One batched desktop/mobile check of existing URL-entry error presentation."""

import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from playwright.sync_api import sync_playwright


def main():
    output = ROOT / '.dom-xray-data'
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        try:
            for label, width, height in (('desktop', 1280, 900), ('mobile', 390, 844)):
                page = browser.new_page(viewport={'width': width, 'height': height})
                try:
                    page.goto('http://127.0.0.1:64020/?fixture=image-heavy&fallback=text')
                    field = page.get_by_role('textbox')
                    field.fill('https://example.com/?')
                    page.get_by_role('button', name='START X-RAY').click()
                    message = page.get_by_text('Remove query parameters and fragments before scanning.')
                    message.wait_for()
                    facts = message.evaluate('''el => ({
                        color: getComputedStyle(el).color,
                        background: getComputedStyle(document.body).backgroundColor,
                        right: el.getBoundingClientRect().right,
                        width: innerWidth,
                        overflow: document.documentElement.scrollWidth > innerWidth,
                    })''')
                    if facts['overflow'] or facts['right'] > width or field.input_value() != 'https://example.com/?':
                        raise AssertionError('URL error overflowed or erased input')
                    if not field.evaluate('el => document.activeElement === el'):
                        raise AssertionError('URL error failed to return focus')
                    page.screenshot(path=str(output / ('url-entry-' + label + '.png')), full_page=True)
                    print(label + ': ' + json.dumps(facts))
                finally:
                    page.close()
        finally:
            browser.close()


if __name__ == '__main__':
    main()
