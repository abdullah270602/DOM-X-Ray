# DOM X-Ray viewer

Gate 1 is a local, fixture-driven proof of the public DOM X-Ray experience. It
does not fetch the URL typed into the form. Instead, the URL selects one of the
three committed scan bundles so the 3D renderer, evidence UI, fallbacks, and
reveal can be verified before a public scanner API is connected.

```powershell
npm install
npm run dev
```

Open `http://127.0.0.1:5173/`. Useful deterministic routes are:

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
```

The fixture sync step copies the repository-owned schemas, mapping registry,
scan records, scene manifests, result manifests, and runtime manifests into a
generated viewer directory before development, tests, and production builds.
