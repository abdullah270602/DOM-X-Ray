"""Regenerate or verify committed renderer-neutral scene-manifest fixtures."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scanner.scene_manifest import build_scene_manifest  # noqa: E402


SOURCE_DIR = ROOT / "fixtures" / "scan"
OUTPUT_DIR = ROOT / "fixtures" / "scene-manifest"
FIXTURE_NAMES = ("clean.json", "image-heavy.json", "third-party-heavy.json")


def rendered_fixture(name: str) -> str:
    record = json.loads((SOURCE_DIR / name).read_text(encoding="utf-8"))
    return json.dumps(
        build_scene_manifest(record),
        ensure_ascii=False,
        indent=2,
    ) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--check",
        action="store_true",
        help="Fail if a committed manifest is absent or differs from regenerated output.",
    )
    args = parser.parse_args()

    if args.check:
        stale = [
            name
            for name in FIXTURE_NAMES
            if not (OUTPUT_DIR / name).is_file()
            or (OUTPUT_DIR / name).read_text(encoding="utf-8") != rendered_fixture(name)
        ]
        if stale:
            raise SystemExit(f"Scene-manifest fixtures are stale or missing: {', '.join(stale)}")
        print(f"Verified {len(FIXTURE_NAMES)} committed scene-manifest fixtures are current.")
        return

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    for name in FIXTURE_NAMES:
        (OUTPUT_DIR / name).write_text(rendered_fixture(name), encoding="utf-8")
    print(f"Wrote {len(FIXTURE_NAMES)} scene-manifest fixtures to {OUTPUT_DIR}.")


if __name__ == "__main__":
    main()
