# DOM X-Ray viewer

The React/Three.js viewer renders the same validated bundle whether it came from
a committed fixture or the local anonymous scan-job API. The local API currently
re-admits only these three seeded captures through the real supervised worker
transport:

- `https://clean.example/`
- `https://gallery.example/`
- `https://newsroom.example/`

It does not fetch or relabel arbitrary public URLs. Production public scanning
remains disabled until the containment requirements in `docs/THREAT_MODEL.md`
have deployment evidence.

From `viewer/`, start the API and viewer in separate terminals:

```powershell
npm run api
npm run dev
```

Open `http://127.0.0.1:5173/`. A submitted seeded URL moves through the pollable
job API and ends at an immutable `/r/{resultId}` route. The creating browser
mints and keeps a private deletion key; only its digest is submitted, and the
key never enters the share URL. Owner browsers see a subordinate **DELETE
RESULT** control. Reused submissions and other browsers can view the same result
without receiving deletion authority. Published results with a defensible hero
also expose **SHARE RESULT**: a protected preview, exact caption, stable link,
and a verified server-published 1080 × 1080 PNG poster. The poster is rendered
by no-network Chromium as strict 8-bit RGBA, non-interlaced PNG; its manifest
SHA/length binding is checked before use. The browser verifies same-origin
route, status/URL/type/ETag/length/SHA before preview, copy, or download and
falls back safely to the local export. Partial captures preserve their
exact limitation disclosure; neutral results stay link-only. Deterministic
fixture routes remain available offline and never expose public share controls:

- `?fixture=image-heavy&time=5000&mode=weight`
- `?fixture=third-party-heavy&time=5000&mode=origins`
- `?fixture=clean&motion=reduced`
- `?fixture=clean&fallback=text&time=5000`

Verification:

```powershell
npm run typecheck
npm test
npm run build
python scripts/verify-ui.py http://127.0.0.1:5173/
python ../scripts/verify_local_scan_api.py
python ../scripts/verify_png_validation.py
python ../scripts/verify_poster_renderer.py
```

The Chromium UI verifier exercises complete and partial hosted poster previews,
compares each preview with the registered server bytes, downloads those exact
bytes twice, decodes each PNG, checks the 1080 × 1080 and 5 MB bounds, compares
repeated rendered-pixel digests, and proves neutral published results are
link-only. Unit tests separately reject forbidden poster inputs and exercise the
browser response-verification/fallback boundary. This remains a local
publication proof, not production artifact hosting or social-platform
compatibility evidence. The local API verifier also proves poster GET/HEAD,
conditional 304, exact-method 405 with `Allow: GET, HEAD`, content-free 404s for
missing/ineligible/deleted/expired/corrupt artifacts, and refusal of client pixel
uploads.

The fixture sync step copies the repository-owned contracts and fixtures, then
precompiles the JSON Schema validators. The local API's built viewer shell retains a
Content Security Policy with no inline scripts or inline style elements; only
style attributes required by the React Three Fiber canvas wrapper and blob image
URLs for verified poster previews remain allowed. Remote bundles are admitted only after their exact bytes match the
API's strong ETag, their schemas pass, and their route/document identities
agree. Browser-held deletion keys use origin-local storage, while the server
persists only a keyed digest and tombstones retired result IDs. The Vite server
is a development convenience, not the production
security boundary; use the local API's static shell on port `8787` for CSP and
immutable-cache verification.
