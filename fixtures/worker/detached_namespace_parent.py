"""Trusted fixture: mimic Playwright's detached executable launch."""

import subprocess
import sys

child = subprocess.Popen(sys.argv[1:], start_new_session=True, close_fds=True)
raise SystemExit(child.wait())
