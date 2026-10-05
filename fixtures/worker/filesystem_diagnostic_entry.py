"""Trusted test entrypoint with local-only setup diagnostics, not stock capture."""

import os
from pathlib import Path
import sys
import traceback

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
import scanner.browser_namespace as namespace

namespace.__file__ = __file__
try:
    if sys.argv[1] == "--launch":
        namespace.launch_namespace()
    else:
        namespace.main()
except Exception:
    Path(os.environ["DXR_FILESYSTEM_DIAGNOSTIC"]).write_text(traceback.format_exc())
    raise SystemExit(2) from None
