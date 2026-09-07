"""Generate immutable result-manifest viewer/export inputs from scan fixtures."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scanner.result_manifest import build_result_manifest  # noqa: E402


SCAN_DIR = ROOT / "fixtures" / "scan"
RESULT_DIR = ROOT / "fixtures" / "result-manifest"
RESULT_IDS = {
    "clean.json": "r_1cfe0f4e9ea34cb2a1d518237e721d30",
    "image-heavy.json": "r_572950dc9af4494cb2e382f30872b175",
    "third-party-heavy.json": "r_a67e06bb119a4384bd31793f594be064",
}


def rendered(name: str) -> str:
    record = json.loads((SCAN_DIR / name).read_text(encoding="utf-8"))
    manifest = build_result_manifest(record, result_id=RESULT_IDS[name])
    return json.dumps(manifest, ensure_ascii=False, indent=2) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.check:
        stale = [
            name
            for name in RESULT_IDS
            if not (RESULT_DIR / name).is_file()
            or (RESULT_DIR / name).read_text(encoding="utf-8") != rendered(name)
        ]
        if stale:
            raise SystemExit(f"stale result-manifest fixtures: {', '.join(stale)}")
        print(f"Verified {len(RESULT_IDS)} committed result-manifest fixtures are current.")
        return

    RESULT_DIR.mkdir(parents=True, exist_ok=True)
    for name in RESULT_IDS:
        (RESULT_DIR / name).write_text(rendered(name), encoding="utf-8")
    print(f"Wrote {len(RESULT_IDS)} result-manifest fixtures to {RESULT_DIR}.")


if __name__ == "__main__":
    main()
