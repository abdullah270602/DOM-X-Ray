"""Install Linux trust-test Python/browser dependencies only inside this repo.

Requires a pip 25.3 wheel downloaded through pip. Does not install OS libraries,
change the user's Python environment, or change any certificate store.
"""

import argparse
import os
from pathlib import Path
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bootstrap-wheel", type=Path, required=True)
    options = parser.parse_args()
    if sys.platform != "linux":
        raise RuntimeError("Linux test preparation requires Linux")
    wheel = options.bootstrap_wheel.resolve(strict=True)
    if wheel.name != "pip-25.3-py3-none-any.whl":
        raise ValueError("use the pinned pip bootstrap wheel")
    root = Path(__file__).resolve().parents[1]
    runtime = root / ".dom-xray-data" / "linux-trust"
    runtime.mkdir(parents=True, exist_ok=True)
    packages, browsers, temporary, cache = (runtime / name for name in ("python", "browsers", "tmp", "pip-cache"))
    temporary.mkdir(exist_ok=True)
    environment = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "TMPDIR": str(temporary),
                   "PLAYWRIGHT_BROWSERS_PATH": str(browsers)}
    bootstrap = "import sys,runpy; sys.path.insert(0,sys.argv.pop(1)); runpy.run_module('pip',run_name='__main__')"
    subprocess.run([sys.executable, "-I", "-S", "-c", bootstrap, str(wheel), "--isolated", "install",
        "--index-url", "https://pypi.org/simple", "--cache-dir", str(cache), "--only-binary=:all:",
        "--target", str(packages), "playwright==1.55.0", "jsonschema==4.25.1",
        "pyee==13.0.1", "greenlet==3.5.6", "attrs==26.1.0", "jsonschema-specifications==2025.9.1",
        "referencing==0.37.0", "rpds-py==2026.9.1", "typing-extensions==4.16.0"],
        cwd=root, env=environment, check=True, timeout=180)
    playwright = "import sys,runpy; sys.path.insert(0,sys.argv.pop(1)); runpy.run_module('playwright',run_name='__main__')"
    subprocess.run([sys.executable, "-I", "-S", "-c", playwright, str(packages), "install", "chromium"],
        cwd=root, env=environment, check=True, timeout=180)
    print("Prepared project-local Linux Python/Chromium test dependencies; no OS packages or trust stores changed.")


if __name__ == "__main__":
    main()
