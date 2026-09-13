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
and a browser-local 1080 × 1080 PNG poster. Partial captures preserve their
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
```

The Chromium UI verifier exercises complete and partial poster previews, downloads
and decodes each PNG, checks the 1080 × 1080 and 5 MB bounds, compares repeated
rendered-pixel digests, proves neutral published results are link-only, and scans
the preview source for forbidden target URLs, titles, selectors, resource URLs,
raw object IDs, and secrets. This remains a local renderer proof, not durable
artifact hosting or social-platform compatibility evidence.

The fixture sync step copies the repository-owned contracts and fixtures, then
precompiles the JSON Schema validators. Production pages therefore retain a
Content Security Policy with no inline scripts or inline style elements; only
style attributes required by the React Three Fiber canvas wrapper remain
allowed. Remote bundles are admitted only after their exact bytes match the
API's strong ETag, their schemas pass, and their route/document identities
agree. Browser-held deletion keys use origin-local storage, while the server
persists only a keyed digest and tombstones retired result IDs. The Vite server
is a development convenience, not the production
security boundary; use the local API's static shell on port `8787` for CSP and
immutable-cache verification.
