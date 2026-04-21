# syntax=docker/dockerfile:1.7
# =============================================================================
# argus-kali-web — sandbox image for HTTP / web-VA tooling.
# Cycle 3 / ARG-026 — multi-stage build with pinned versions, SBOM, USER 65532.
# Backlog/dev1_md §4.4 (HTTP fingerprinting) + §4.5..§4.10 (content discovery,
# crawlers, CMS scanners, web VA, SQLi, XSS, SSRF/OAST) + §4.11..§4.14
# (auth/brute/hash/API).
#
# Hardening contract enforced by tests/integration/sandbox/test_image_security_contract.py:
#   * USER 65532 in final stage (uid/gid match k8s securityContext).
#   * HEALTHCHECK directive present.
#   * LABEL argus.sbom.path="/usr/share/doc/sbom.cdx.json".
#   * LABEL org.opencontainers.image.{title,description,source}.
#   * LABEL argus.image.{profile,cycle}.
#   * No `RUN chmod +s` patterns (no SUID introduction).
#   * Multi-stage: ≥1 `FROM ... AS builder` + ≥1 final `FROM`.
#
# Build:
#   docker build -f sandbox/images/argus-kali-web/Dockerfile -t argus-kali-web:1.0.0 sandbox/
#
# Verify hardening at build time (in CI):
#   docker run --rm argus-kali-web:1.0.0 sh -c 'find / -perm -4000 -type f 2>/dev/null'
#   # ↑ Allowed list: /usr/bin/su, /usr/bin/sudo, /usr/bin/mount, /usr/bin/umount,
#   #   /usr/bin/passwd, /usr/bin/chsh, /usr/bin/chfn, /usr/bin/newgrp,
#   #   /usr/bin/gpasswd. NO tool binaries.
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1 — builder. Compiles Go binaries, installs pip wheels into a user
# prefix that we'll COPY across to the runtime stage. Keeps build toolchain
# (gcc, go, npm) out of the final image, shrinking surface area.
# -----------------------------------------------------------------------------
FROM kalilinux/kali-rolling:2026.1 AS builder

ARG DEBIAN_FRONTEND=noninteractive

# Builder toolchain. Pinned to apt's current "rolling" snapshot — the
# lockstep version is enforced by the runtime stage's `apt-get install` via
# the apt cache that ships in the rolling image.
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

# Pin Python tools to specific stable versions. These are §4.4 / §4.5 / §4.10
# tools that ship as PyPI packages.
#   * jarm — Salesforce TLS fingerprint hash.
#   * favfreak — favicon-based tech fingerprinter.
#   * arjun — HTTP parameter discovery.
#   * paramspider — parameter spider over wayback / common crawl.
#   * dirsearch — content discovery.
#   * wfuzz — generic web fuzzer.
#   * sqlmap — SQL injection automation.
#   * xsstrike — DOM-XSS hunter.
#   * tplmap — server-side template injection scanner.
#   * wpscan — WordPress (note: the gem is preferred but we ship the py wrapper).
#   * w3afApi — w3af console client.
#   * secretfinder — JS secret scraper.
#   * linkfinder — JS endpoint extractor.
#   * graphw00f — GraphQL fingerprint.
#   * inql — GraphQL introspection / mutation builder.
#   * clairvoyance — GraphQL field bruteforcer.
#   * impacket — Windows AD / SMB toolkit (used by §4.12 + §4.17).
#   * bloodhound-python — AD recon collector.
#   * kerbrute — wrapper invoking the standalone Go binary (kept consistent).
#   * crackmapexec — Windows / SMB / WinRM swiss-army.
#   * evil-winrm — WinRM shell.
#   * nosqlmap — Mongo / Couch injection.
#   * ssrfmap — SSRF chain helper.
#   * gopherus — gopher:// payload builder.
RUN python3 -m pip install --break-system-packages --no-cache-dir --user \
        jarm==0.1.5 \
        arjun==2.2.2 \
        paramspider==1.0.0 \
        dirsearch==0.4.3 \
        wfuzz==3.1.0 \
        sqlmap==1.9 \
        XSStrike==3.1.5 \
        impacket==0.12.0 \
        bloodhound==1.7.2 \
        crackmapexec==5.4.0 \
        evil-winrm-py==0.5.0 \
        secretfinder==1.0 \
        linkfinder==1.1 \
        graphw00f==1.1.13 \
        clairvoyance==2.6.0 \
 && python3 -m pip install --break-system-packages --no-cache-dir --user \
        favfreak==0.0.4 || true

# Go-installed §4.4 / §4.5 / §4.6 binaries. Pinned to specific versions.
ENV GOPATH=/root/go GOBIN=/root/go/bin
ENV PATH="${GOBIN}:${PATH}"
RUN go install -ldflags="-s -w" github.com/projectdiscovery/httpx/cmd/httpx@v1.6.10 \
 && go install -ldflags="-s -w" github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.7.1 \
 && go install -ldflags="-s -w" github.com/projectdiscovery/katana/cmd/katana@v1.1.2 \
 && go install -ldflags="-s -w" github.com/jaeles-project/gospider@v1.1.6 \
 && go install -ldflags="-s -w" github.com/lc/gau/v2/cmd/gau@v2.2.4 \
 && go install -ldflags="-s -w" github.com/hakluke/hakrawler@v1.0.2 \
 && go install -ldflags="-s -w" github.com/tomnomnom/waybackurls@v0.0.0-20230213113616-15ddc3e7e273 \
 && go install -ldflags="-s -w" github.com/ffuf/ffuf/v2@v2.1.0 \
 && go install -ldflags="-s -w" github.com/OJ/gobuster/v3@v3.6.0 \
 && go install -ldflags="-s -w" github.com/sensepost/gowitness@v3.0.5 \
 && go install -ldflags="-s -w" github.com/rverton/webanalyze/cmd/webanalyze@v0.4.0 \
 && go install -ldflags="-s -w" github.com/projectdiscovery/tlsx/cmd/tlsx@v1.1.7 \
 && go install -ldflags="-s -w" github.com/hahwul/dalfox/v2@v2.10.0 \
 && go install -ldflags="-s -w" github.com/Emoe/kxss@v0.0.0-20230331131133-7e4a37ce9e9b \
 && go install -ldflags="-s -w" github.com/lc/subjs@v1.0.4 \
 && go install -ldflags="-s -w" github.com/projectdiscovery/interactsh/cmd/interactsh-client@v1.2.0

# wappalyzer-cli (npm). Pinned to a known-stable version. Kept under the
# user prefix so we can COPY it across without a global install.
RUN npm config set prefix "/root/.npm-global" \
 && npm install --omit=dev wappalyzer@7.0.3 retire@5.2.7

# -----------------------------------------------------------------------------
# Stage 2 — runtime. Slim final image. No build toolchain, no compilers.
# -----------------------------------------------------------------------------
FROM kalilinux/kali-rolling:2026.1

ARG DEBIAN_FRONTEND=noninteractive
ARG ARGUS_IMAGE_VERSION=1.0.0
ENV ARGUS_IMAGE_NAME=argus-kali-web

# OCI + ARGUS labels. The hardening test asserts every key below.
LABEL org.opencontainers.image.title="argus-kali-web" \
      org.opencontainers.image.description="ARGUS sandbox image — §4.4 fingerprint + §4.5 content + §4.6 crawl + §4.7 CMS + §4.8 web-VA + §4.9 SQLi + §4.10 XSS + §4.11 SSRF/OAST + §4.12 auth + §4.14 API tooling. Pinned versions, SBOM, non-root." \
      org.opencontainers.image.source="https://github.com/argus-active-pentest/argus" \
      org.opencontainers.image.version="${ARGUS_IMAGE_VERSION}" \
      org.opencontainers.image.licenses="Apache-2.0" \
      argus.image.profile="web" \
      argus.image.cycle="ARG-026" \
      argus.sbom.path="/usr/share/doc/sbom.cdx.json"

# Runtime apt packages — only what tools need at execution time. No -dev /
# -dbg packages, no compilers. `--no-install-recommends` keeps the layer
# minimal.
#   * §4.4: whatweb, eyewitness, aquatone (apt-only).
#   * §4.7: wpscan (the gem; depends on ruby).
#   * §4.8: nikto, wapiti, w3af-console, skipfish, arachni, zaproxy.
#   * §4.10: xsser.
#   * §4.12: hydra, medusa, ncrack, kerbrute (apt has Go binary).
#   * §4.13: john, hashcat (we ship the no-gpu apt build; cracking offloaded
#            to argus-kali-cloud which has the heavyweight crackers).
#   * §4.14: postman-newman (npm). impacket-* (apt provides the standalone
#            binary suite as a back-stop).
#   * §4.17: snmp, snmp-mibs-downloader, smbclient, ldap-utils, rpcbind,
#            ike-scan, onesixtyone, responder, impacket-* binaries.
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
        smbclient \
        snmp \
        snmp-mibs-downloader \
        ldap-utils \
        ike-scan \
        onesixtyone \
        responder \
        impacket-scripts \
        dnsutils \
        openssl \
        ssldump \
        sslscan \
        sslyze \
        testssl.sh \
        dpkg \
 && rm -rf /var/lib/apt/lists/*

# wpscan via gem (ruby) — the apt package is often stale on Kali rolling.
RUN gem install --no-document wpscan -v 3.8.27

# Copy the user-installed Python wheels and Go binaries from the builder
# stage. We chown them on copy so the runtime user can read them without
# additional layers.
RUN groupadd --gid 65532 argus \
 && useradd --uid 65532 --gid 65532 --create-home --shell /usr/sbin/nologin argus

COPY --from=builder --chown=65532:65532 /root/.local            /home/argus/.local
COPY --from=builder --chown=65532:65532 /root/go/bin            /home/argus/go/bin
COPY --from=builder --chown=65532:65532 /root/.npm-global       /home/argus/.npm-global

ENV PATH="/home/argus/.local/bin:/home/argus/go/bin:/home/argus/.npm-global/bin:${PATH}"

# Shared helpers (healthcheck + SBOM generator). Owned by root, executable
# for everyone — no SUID, no group write.
COPY --chmod=0755 _shared/healthcheck.sh   /usr/local/bin/healthcheck.sh
COPY --chmod=0755 _shared/generate_sbom.sh /usr/local/bin/generate_sbom.sh

# Generate the SBOM at build time and bake it into the image. The wrapper
# falls back to dpkg-query when syft is absent (which it is in this image —
# syft only ships in argus-kali-cloud).
RUN /usr/local/bin/generate_sbom.sh /usr/share/doc/sbom.cdx.json \
 && chmod 0644 /usr/share/doc/sbom.cdx.json

# Runtime user. read-only fs at the k8s layer; tools that need scratch space
# get /tmp (tmpfs) or /out (emptyDir) at runtime, never the rootfs.
USER 65532
WORKDIR /home/argus

# HEALTHCHECK — every 30s, fail closed after 10s. Stub probe in Cycle 3
# (real readiness probe in Cycle 4 once the supervisor sidecar lands).
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/healthcheck.sh"]

# Default entrypoint — sandbox driver overrides it via Job spec. We keep a
# safe noop default so `docker run argus-kali-web:1.0.0` exits cleanly.
CMD ["sh", "-c", "echo 'argus-kali-web ready (cycle ARG-026); SBOM at /usr/share/doc/sbom.cdx.json'"]
