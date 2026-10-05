# Current browser candidate. Still reserved-origin only, not production approved.
FROM ubuntu:24.04@sha256:534baea6a22c03a63003dbc8dbe78fe34bc0d7e595d9a9dc9834884ff530eb55
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-venv openssl libnss3-tools iproute2 util-linux ca-certificates \
    libglib2.0-0t64 libnss3 libnspr4 libatk1.0-0t64 libatk-bridge2.0-0t64 \
    libcups2t64 libdrm2 libdbus-1-3 libxcb1 libxkbcommon0 libx11-6 \
    libxcomposite1 libxdamage1 libxext6 libxfixes3 libxrandr2 libgbm1 \
    libpango-1.0-0 libcairo2 libasound2t64 fonts-liberation \
    && rm -rf /var/lib/apt/lists/*
COPY --from=candidate-wheels / /opt/wheels/
COPY containers/runtime-candidate.requirements.txt /opt/runtime/requirements.txt
RUN python3 -m venv /opt/build-venv \
    && /opt/build-venv/bin/python -m pip --isolated install --no-index --find-links=/opt/wheels \
       --require-hashes --only-binary=:all: --target=/opt/runtime/python -r /opt/runtime/requirements.txt
ENV PYTHONPATH=/opt/runtime/python PLAYWRIGHT_BROWSERS_PATH=/opt/runtime/browsers
RUN python3 -m playwright install --only-shell chromium
COPY containers/runtime-candidate.json /opt/runtime/capture-runtime.json
RUN mkdir -p /opt/runtime/root/usr/bin /opt/runtime/root/usr/lib/x86_64-linux-gnu \
    && ln -s /usr/bin/certutil /opt/runtime/root/usr/bin/certutil \
    && chmod -R a+rX /opt/runtime \
    && chmod a+x /opt/runtime/browsers/chromium_headless_shell-1243/chrome-headless-shell-linux64/chrome-headless-shell \
    && chmod a+x /opt/runtime/python/playwright/driver/node \
    && dpkg-query -W > /opt/runtime/os-packages.txt
WORKDIR /opt/dom-xray
COPY scanner scanner
RUN chmod 0555 scanner/browser_launcher.py
COPY scripts scripts
COPY fixtures fixtures
COPY docs docs
USER 10001:10001
CMD ["python3", "scripts/verify_egress_capture_worker.py", "--runtime-root", "/opt/runtime", "--container-limits"]
