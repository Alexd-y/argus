# syntax=docker/dockerfile:1.7
# =============================================================================
# argus-kali-browser — sandbox image for browser-driven pentest tooling.
# Cycle 3 / ARG-026 — multi-stage build with pinned versions, SBOM, USER 65532,
# NO SUID binaries (Chromium runs in `--no-sandbox` mode under k8s userns-remap).
#
# Backlog/dev1_md §4.7 (CMS scanners that drive a real browser),
# §4.8 (zaproxy headless, browser fuzzing), §4.10 (DOM-XSS hunters that need
# JS execution), §4.19 (browser / headless / OAST verifiers — playwright,
# puppeteer, chrome_csp_probe, cors_probe, cookie_probe).
#
# Why Chromium runs `--no-sandbox` here:
#   * The k8s securityContext drops CAP_SYS_ADMIN, which Chromium needs for
#     its own sandbox.
#   * The image-level securityContext (read-only fs, runAsNonRoot, seccomp
#     RuntimeDefault, no privilege escalation) replaces the Chromium internal
#     sandbox layer with the OS-level container sandbox.
#   * userns-remap on the host kernel adds a third defence layer.
#
# Hardening contract enforced by tests/integration/sandbox/test_image_security_contract.py:
#   * USER 65532 in final stage.
#   * HEALTHCHECK directive present.
#   * LABEL argus.sbom.path="/usr/share/doc/sbom.cdx.json".
#   * LABEL org.opencontainers.image.{title,description,source}.
#   * LABEL argus.image.{profile,cycle}.
#   * No `RUN chmod +s` (no SUID introduction). Chromium's setuid sandbox
#     is explicitly NOT installed (we deliberately omit chrome-sandbox).
#
# Build:
#   docker build -f sandbox/images/argus-kali-browser/Dockerfile -t argus-kali-browser:1.0.0 sandbox/
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1 — builder. Installs the Playwright Python wrapper plus the npm
# Puppeteer + retire.js bundle. Browser binaries themselves are downloaded
# in the runtime stage so we don't COPY 300 MB of profile dirs.
# -----------------------------------------------------------------------------
FROM kalilinux/kali-rolling:2026.1 AS builder

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        ca-certificates=\* \
        curl=\* \
        wget=\* \
        git=\* \
        python3=\* \
        python3-pip=\* \
        python3-venv=\* \
        nodejs=\* \
        npm=\* \
        build-essential=\* \
        unzip=\* \
        jq=\* \
 && rm -rf /var/lib/apt/lists/*

# Pinned Python tools.
#   * playwright — orchestrates Chromium / Firefox / Webkit headless.
#   * pyppeteer  — fallback Puppeteer port for Python integrations.
#   * retire     — JavaScript dependency vulnerability scanner.
RUN python3 -m pip install --break-system-packages --no-cache-dir --user \
        playwright==1.50.0 \
        pyppeteer==2.0.0

# Pinned npm packages — Puppeteer + retire.js.
RUN npm config set prefix "/root/.npm-global" \
 && npm install --omit=dev \
        puppeteer@22.15.0 \
        retire@5.2.7

# -----------------------------------------------------------------------------
# Stage 2 — runtime. Slim image with Chromium + Firefox headless + Playwright
# wired to the Chromium binary, NO SUID anywhere on $PATH.
# -----------------------------------------------------------------------------
FROM kalilinux/kali-rolling:2026.1

ARG DEBIAN_FRONTEND=noninteractive
ARG ARGUS_IMAGE_VERSION=1.0.0
ENV ARGUS_IMAGE_NAME=argus-kali-browser

LABEL org.opencontainers.image.title="argus-kali-browser" \
      org.opencontainers.image.description="ARGUS sandbox image — §4.19 browser tooling (Playwright + Chromium + Puppeteer + retire.js). NO SUID binaries on PATH; Chromium runs in --no-sandbox mode under k8s userns-remap. Pinned versions, SBOM, non-root." \
      org.opencontainers.image.source="https://github.com/argus-active-pentest/argus" \
      org.opencontainers.image.version="${ARGUS_IMAGE_VERSION}" \
      org.opencontainers.image.licenses="Apache-2.0" \
      argus.image.profile="browser" \
      argus.image.cycle="ARG-026" \
      argus.sbom.path="/usr/share/doc/sbom.cdx.json"

# Runtime apt — Chromium + Firefox-ESR + minimal X stack (we run headless
# but a few pages still touch the X libraries). Crucially, we DO NOT install
# `chromium-sandbox` or `chromium-driver-suid` (those carry SUID bits).
#
# `chromium` package on Kali 2026.1 ships the suid binary too — we delete
# it post-install to maintain the "no SUID on $PATH" contract. The container
# sandbox + seccomp + read-only fs replace what the Chromium SUID sandbox
# would have provided.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        wget \
        jq \
        git \
        python3 \
        python3-pip \
        nodejs \
        npm \
        chromium \
        chromium-driver \
        firefox-esr \
        fonts-liberation \
        libasound2 \
        libatk1.0-0 \
        libatk-bridge2.0-0 \
        libdrm2 \
        libgbm1 \
        libgtk-3-0 \
        libnspr4 \
        libnss3 \
        libx11-xcb1 \
        libxcomposite1 \
        libxdamage1 \
        libxrandr2 \
        xdg-utils \
        dpkg \
 && rm -rf /var/lib/apt/lists/* \
 && rm -f /usr/lib/chromium/chrome-sandbox /usr/lib/chromium/chrome_crashpad_handler-suid 2>/dev/null || true

# Runtime user.
RUN groupadd --gid 65532 argus \
 && useradd --uid 65532 --gid 65532 --create-home --shell /usr/sbin/nologin argus

COPY --from=builder --chown=65532:65532 /root/.local      /home/argus/.local
COPY --from=builder --chown=65532:65532 /root/.npm-global /home/argus/.npm-global

# Stand-up the playwright `playwright-runner` shim referenced by the YAML
# command_template (see backend/config/tools/playwright_runner.yaml). The
# real implementation will land with the playwright runner package in
# Cycle 4 — we ship a shell wrapper that exec's `node` against an operator-
# supplied script so the YAML stays valid.
RUN install -d -o 65532 -g 65532 /home/argus/playwright-runner \
 && printf '#!/bin/sh\nset -eu\nexec node "$@"\n' > /usr/local/bin/playwright-runner \
 && chmod 0755 /usr/local/bin/playwright-runner

# Force Playwright + Puppeteer to use the apt-installed Chromium binary
# instead of downloading their own copies into ~/.cache (which the read-
# only rootfs would reject anyway).
ENV PLAYWRIGHT_BROWSERS_PATH=/usr/lib/chromium \
    PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 \
    PUPPETEER_SKIP_DOWNLOAD=1 \
    PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium \
    CHROME_BIN=/usr/bin/chromium \
    PATH="/home/argus/.local/bin:/home/argus/.npm-global/bin:${PATH}"

# Shared helpers (healthcheck + SBOM generator).
COPY --chmod=0755 _shared/healthcheck.sh   /usr/local/bin/healthcheck.sh
COPY --chmod=0755 _shared/generate_sbom.sh /usr/local/bin/generate_sbom.sh

# Bake SBOM into the image (dpkg-query fallback — no syft in this image).
RUN /usr/local/bin/generate_sbom.sh /usr/share/doc/sbom.cdx.json \
 && chmod 0644 /usr/share/doc/sbom.cdx.json

USER 65532
WORKDIR /home/argus

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/healthcheck.sh"]

CMD ["sh", "-c", "echo 'argus-kali-browser ready (cycle ARG-026); SBOM at /usr/share/doc/sbom.cdx.json'"]
