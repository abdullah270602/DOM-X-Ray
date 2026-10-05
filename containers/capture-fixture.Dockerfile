# Deterministic reserved-origin integration only. NOT a public scanner image:
# the historical Chromium pin must be updated/audited before public deployment.
FROM ubuntu:24.04@sha256:534baea6a22c03a63003dbc8dbe78fe34bc0d7e595d9a9dc9834884ff530eb55

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 openssl libnss3-tools iproute2 util-linux ca-certificates \
    libglib2.0-0t64 libnss3 libnspr4 libatk1.0-0t64 libatk-bridge2.0-0t64 \
    libcups2t64 libdrm2 libdbus-1-3 libxcb1 libxkbcommon0 libx11-6 \
    libxcomposite1 libxdamage1 libxext6 libxfixes3 libxrandr2 libgbm1 \
    libpango-1.0-0 libcairo2 libasound2t64 fonts-liberation \
    && rm -rf /var/lib/apt/lists/*

# Named context supplies only the already-prepared trusted fixture dependencies.
# They are baked into the image, never mounted from the host at execution time.
COPY --from=fixture-runtime /python /opt/runtime/python
COPY --from=fixture-runtime /browsers/chromium_headless_shell-1187 /opt/runtime/browsers/chromium_headless_shell-1187
RUN mkdir -p /opt/runtime/root/usr/bin /opt/runtime/root/usr/lib/x86_64-linux-gnu \
    && ln -s /usr/bin/certutil /opt/runtime/root/usr/bin/certutil \
    && chmod -R a+rX /opt/runtime \
    && chmod a+x /opt/runtime/browsers/chromium_headless_shell-1187/chrome-linux/headless_shell \
    && chmod a+x /opt/runtime/python/playwright/driver/node

WORKDIR /opt/dom-xray
COPY scanner scanner
RUN chmod 0555 scanner/browser_launcher.py
COPY scripts scripts
COPY fixtures fixtures
COPY docs docs
ENV PYTHONPATH=/opt/runtime/python
USER 10001:10001
CMD ["python3", "scripts/verify_egress_capture_worker.py", "--runtime-root", "/opt/runtime", "--container-limits"]
