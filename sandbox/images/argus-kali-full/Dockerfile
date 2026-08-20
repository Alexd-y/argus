# syntax=docker/dockerfile:1.7
# =============================================================================
# argus-kali-full — fallback monolithic sandbox image (superset).
# Cycle 3 / ARG-026 — multi-stage build with USER 65532 + healthcheck +
# SBOM. Pinning is INTENTIONALLY relaxed here vs. the slim images: the full
# image is the safety-net for tools whose slim image is not yet populated
# (e.g. §4.18 binary / mobile / firmware analysis: apktool, jadx, binwalk,
# radare2_info, mobsf_api), so we pull whatever apt-get currently has and
# accept the resulting CVE surface in exchange for completeness.
#
# Operators MUST justify routing a YAML to argus-kali-full (vs. one of the
# slim images) in the YAML's `description` field — see ToolRegistry audit
# in backend/tests/integration/sandbox/test_tool_catalog_load.py.
#
# Hardening contract enforced by tests/integration/sandbox/test_image_security_contract.py:
#   * USER 65532 in final stage.
#   * HEALTHCHECK directive present.
#   * LABEL argus.sbom.path="/usr/share/doc/sbom.cdx.json".
#   * LABEL org.opencontainers.image.{title,description,source}.
#   * LABEL argus.image.{profile,cycle}.
#   * No `RUN chmod +s` (no SUID introduction).
#   * Multi-stage: ≥1 `FROM ... AS builder` + final `FROM`.
#
# Build:
#   docker build -f sandbox/images/argus-kali-full/Dockerfile -t argus-kali-full:1.0.0 sandbox/
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1 — builder. Compiles the same Go binaries we ship in slim images
# plus a few extras the full image needs (radare2 build deps).
# -----------------------------------------------------------------------------
# Base image tag is overridable for reproducible pinning (--build-arg KALI_TAG=…);
# default `latest` because Kali publishes no date-stamped `kali-rolling` tag on Docker Hub.
ARG KALI_TAG=latest
FROM kalilinux/kali-rolling:${KALI_TAG} AS builder

ARG DEBIAN_FRONTEND=noninteractive

# Pin apt mirror to HTTPS (AV middleboxes block Kali security-tool .debs over
# cleartext HTTP, 499). Deterministic overwrite; first package step of the stage.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && printf 'deb https://http.kali.org/kali kali-rolling main contrib non-free non-free-firmware\n' > /etc/apt/sources.list \
 && rm -rf /var/lib/apt/lists/*

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        ca-certificates=\* \
        curl=\* \
        wget=\* \
        git=\* \
        golang-go=\* \
        python3=\* \
        python3-pip=\* \
        python3-venv=\* \
        nodejs=\* \
        npm=\* \
        build-essential=\* \
        unzip=\* \
        jq=\* \
 && rm -rf /var/lib/apt/lists/*

# Pinned Python tools — superset of web + cloud + browser plus the §4.18
# binary / mobile / firmware tools that have no slim image of their own
# (mobsf_api, plus support packages).
# Best-effort PER PACKAGE (`|| true`): PyPI availability / interpreter compat
# drifts on the rolling base; a stale pin must not fail the image (jarm→0.1.0,
# XSStrike→3.2.2 corrected; crackmapexec removed from PyPI → skipped). Missing
# tools guarded at runtime.
RUN set -u; \
    for spec in \
        "jarm==0.1.0" \
        "arjun==2.2.2" \
        "sqlmap==1.9" \
        "XSStrike==3.2.2" \
        "impacket==0.12.0" \
        "bloodhound==1.7.2" \
        "crackmapexec==5.4.0" \
        "prowler==5.20.0" \
        "scoutsuite==5.14.0" \
        "semgrep==1.99.0" \
        "bandit==1.8.0" \
        "checkov==3.2.382" \
        "detect-secrets==1.5.0" \
        "playwright==1.50.0" \
    ; do \
        python3 -m pip install --break-system-packages --no-cache-dir --user "$spec" \
          || echo "WARN: pip install failed (best-effort, guarded at runtime): $spec"; \
    done

# Pinned Go binaries — flagship tools used across phases.
ENV GOPATH=/root/go GOBIN=/root/go/bin
ENV PATH="${GOBIN}:${PATH}"
RUN set -u; \
    for mod in \
        "github.com/projectdiscovery/httpx/cmd/httpx@v1.6.10" \
        "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.7.1" \
        "github.com/projectdiscovery/katana/cmd/katana@v1.1.2" \
        "github.com/ffuf/ffuf/v2@v2.1.0" \
        "github.com/OJ/gobuster/v3@v3.6.0" \
        "github.com/aquasecurity/trivy/cmd/trivy@v0.70.0" \
        "github.com/anchore/syft/cmd/syft@v1.42.4" \
        "github.com/anchore/grype/cmd/grype@v0.92.0" \
        "github.com/zricethezav/gitleaks/v8@v8.21.4" \
    ; do \
        go install -ldflags="-s -w" "$mod" \
          || echo "WARN: go install failed (best-effort, guarded at runtime): $mod"; \
    done

# -----------------------------------------------------------------------------
# Stage 2 — runtime. The big monolithic image. apt-get without strict
# pinning is OK here per the task spec; what's NOT OK is dropping USER 65532
# or skipping the SBOM. Both are mandatory.
# -----------------------------------------------------------------------------
FROM kalilinux/kali-rolling:${KALI_TAG}

ARG DEBIAN_FRONTEND=noninteractive
ARG ARGUS_IMAGE_VERSION=1.0.0
ENV ARGUS_IMAGE_NAME=argus-kali-full

LABEL org.opencontainers.image.title="argus-kali-full" \
      org.opencontainers.image.description="ARGUS fallback monolithic sandbox image — superset of web + cloud + browser plus §4.18 binary/mobile/firmware (apktool, jadx, binwalk, radare2_info, mobsf_api). Apt pins relaxed for breadth; USER 65532 + SBOM + healthcheck mandatory." \
      org.opencontainers.image.source="https://github.com/argus-active-pentest/argus" \
      org.opencontainers.image.version="${ARGUS_IMAGE_VERSION}" \
      org.opencontainers.image.licenses="Apache-2.0" \
      argus.image.profile="full" \
      argus.image.cycle="ARG-026" \
      argus.sbom.path="/usr/share/doc/sbom.cdx.json"

# Runtime apt — relaxed pinning, broad surface. We deliberately do NOT
# install awscli / gcloud / az SDKs (cloud creds story in §10/§18).
# Pin apt mirror to HTTPS first: broad §4.x tool .debs (nikto/responder/impacket/
# …) are blocked by AV middleboxes over cleartext HTTP (499).
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && printf 'deb https://http.kali.org/kali kali-rolling main contrib non-free non-free-firmware\n' > /etc/apt/sources.list \
 && rm -rf /var/lib/apt/lists/*
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        wget \
        jq \
        git \
        python3 \
        python3-pip \
        ruby \
        ruby-dev \
        nodejs \
        npm \
        whatweb \
        nikto \
        wapiti \
        skipfish \
        xsser \
        sqlmap \
        hydra \
        medusa \
        ncrack \
        john \
        hashcat \
        hashid \
        ophcrack \
        smbclient \
        snmp \
        ldap-utils \
        ike-scan \
        onesixtyone \
        responder \
        impacket-scripts \
        chromium \
        chromium-driver \
        firefox-esr \
        fonts-liberation \
        apktool \
        binwalk \
        radare2 \
        default-jre-headless \
        sslscan \
        sslyze \
        testssl.sh \
        dnsutils \
        openssl \
        unzip \
        dpkg \
 && rm -rf /var/lib/apt/lists/*
# Chromium's own Depends pull the correct GTK/NSS/ALSA libs (incl. t64-renamed
# ones). SUID sandbox cleanup is a SEPARATE step so its `|| true` cannot mask an
# apt-get failure (which previously produced a silently-incomplete image).
RUN rm -f /usr/lib/chromium/chrome-sandbox /usr/lib/chromium/chrome_crashpad_handler-suid 2>/dev/null || true

# wpscan via gem. Best-effort + unpinned: the old 3.8.27 pin fails its native
# extension against current Kali ruby; missing wpscan is guarded at runtime.
RUN gem install --no-document wpscan \
 || echo "WARN: wpscan gem install failed (best-effort; guarded at runtime)"

# Runtime user.
RUN groupadd --gid 65532 argus \
 && useradd --uid 65532 --gid 65532 --create-home --shell /usr/sbin/nologin argus

COPY --from=builder --chown=65532:65532 /root/.local /home/argus/.local
COPY --from=builder --chown=65532:65532 /root/go/bin /home/argus/go/bin

ENV PATH="/home/argus/.local/bin:/home/argus/go/bin:${PATH}" \
    PLAYWRIGHT_BROWSERS_PATH=/usr/lib/chromium \
    PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 \
    PUPPETEER_SKIP_DOWNLOAD=1 \
    PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium \
    CHROME_BIN=/usr/bin/chromium

# Shared helpers (healthcheck + SBOM generator). Owned by root, executable
# for everyone — no SUID, no group write.
COPY --chmod=0755 _shared/healthcheck.sh   /usr/local/bin/healthcheck.sh
COPY --chmod=0755 _shared/generate_sbom.sh /usr/local/bin/generate_sbom.sh

# Bake SBOM at build time using the syft binary we copied across from the
# builder stage (full image carries syft).
RUN /usr/local/bin/generate_sbom.sh /usr/share/doc/sbom.cdx.json \
 && chmod 0644 /usr/share/doc/sbom.cdx.json

USER 65532
WORKDIR /home/argus

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/healthcheck.sh"]

CMD ["sh", "-c", "echo 'argus-kali-full ready (cycle ARG-026); SBOM at /usr/share/doc/sbom.cdx.json'"]
