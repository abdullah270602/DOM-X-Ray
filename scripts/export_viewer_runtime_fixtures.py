"""Generate renderer-neutral viewer-runtime models from committed sources."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scanner.viewer_runtime import build_viewer_runtime  # noqa: E402


SCAN_DIR = ROOT / "fixtures" / "scan"
SCENE_DIR = ROOT / "fixtures" / "scene-manifest"
RESULT_DIR = ROOT / "fixtures" / "result-manifest"
RUNTIME_DIR = ROOT / "fixtures" / "viewer-runtime"
FIXTURE_NAMES = ("clean.json", "image-heavy.json", "third-party-heavy.json")


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def rendered(name: str) -> str:
    model = build_viewer_runtime(
        load_json(SCAN_DIR / name),
        load_json(SCENE_DIR / name),
        load_json(RESULT_DIR / name),
    )
    return json.dumps(model, ensure_ascii=False, indent=2) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.check:
        stale = [
            name
            for name in FIXTURE_NAMES
            if not (RUNTIME_DIR / name).is_file()
            or (RUNTIME_DIR / name).read_text(encoding="utf-8") != rendered(name)
        ]
        if stale:
            raise SystemExit(f"stale viewer-runtime fixtures: {', '.join(stale)}")
        print(f"Verified {len(FIXTURE_NAMES)} committed viewer-runtime fixtures are current.")
        return

    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    for name in FIXTURE_NAMES:
        (RUNTIME_DIR / name).write_text(rendered(name), encoding="utf-8")
    print(f"Wrote {len(FIXTURE_NAMES)} viewer-runtime fixtures to {RUNTIME_DIR}.")


if __name__ == "__main__":
    main()
