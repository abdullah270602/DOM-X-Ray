# Diagnostic-only overlay. Verify the local base tag's immutable ID before build.
# Does not refresh OS packages, Python wheels or Chromium.
FROM dom-x-ray-runtime-candidate:gate3
COPY scanner scanner
USER 0:0
RUN chmod 0555 scanner/browser_launcher.py
COPY scripts scripts
COPY fixtures fixtures
USER 10001:10001
