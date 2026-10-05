"""Trusted fixture: mimic Playwright's detached executable launch."""

import subprocess
import sys
import os

arguments = sys.argv[1:]
leak = bool(arguments and arguments[0] == "--leak-directory")
if leak:
    descriptor = os.open(arguments[1], os.O_RDONLY | os.O_DIRECTORY)
    os.set_inheritable(descriptor, True)
    arguments = arguments[2:]
child = subprocess.Popen(arguments, start_new_session=True, close_fds=not leak)
raise SystemExit(child.wait())
