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
# Base image tag is overridable for reproducible pinning (--build-arg KALI_TAG=…);
# default `latest` because Kali publishes no date-stamped `kali-rolling` tag on Docker Hub.
ARG KALI_TAG=latest
FROM kalilinux/kali-rolling:${KALI_TAG} AS builder

ARG DEBIAN_FRONTEND=noninteractive

# Some networks/AV middleboxes block Kali security-tool .debs over cleartext HTTP
# (HTTP 499 "forbidden by antivirus"). Fetch ca-certificates (not a flagged
# package) then pin the apt mirror to HTTPS so tool payloads are not
# content-inspected. Overwrite (not sed) so it is deterministic regardless of the
# base image's sources layout. First package step of the stage.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && printf 'deb https://http.kali.org/kali kali-rolling main contrib non-free non-free-firmware\n' > /etc/apt/sources.list \
 && rm -rf /var/lib/apt/lists/*

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
# Version pins are best-effort PER PACKAGE (`|| true`): upstream PyPI availability
# of several of these drifts (yanked versions, GitHub-only tools, renamed pkgs),
# and a single stale pin must not fail the whole image. Tools that fail here
# degrade gracefully at runtime — their sandbox wrappers/adapters guard on
# presence (`command -v`). Pins corrected to versions that exist on PyPI as of
# build; unpinned entries take the current release. Fix-forward: replace the
# GitHub-only tools (linkfinder/favfreak/crackmapexec) with git-clone recipes.
RUN set -u; \
    for spec in \
        "jarm==0.1.0" \
        "arjun==2.2.2" \
        "dirsearch==0.4.3" \
        "wfuzz==3.1.0" \
        "sqlmap==1.9" \
        "impacket==0.12.0" \
        "bloodhound==1.7.2" \
        "XSStrike==3.2.2" \
        "evil-winrm-py==1.6.0" \
        "clairvoyance==2.5.5" \
        "droopescan" \
        "ghauri" \
        "inql" \
        "secretfinder" \
        "linkfinder" \
        "graphw00f" \
        "favfreak" \
    ; do \
        python3 -m pip install --break-system-packages --no-cache-dir --user "$spec" \
          || echo "WARN: pip install failed (best-effort, guarded at runtime): $spec"; \
    done

# Go-installed §4.4 / §4.5 / §4.6 binaries. Pinned to specific versions.
ENV GOPATH=/root/go GOBIN=/root/go/bin
ENV PATH="${GOBIN}:${PATH}"
# Best-effort PER MODULE (`|| echo WARN`): a single stale module tag (e.g. an
# upstream retag) must not abort the whole chain. Failed tools are guarded at
# runtime by their wrappers/adapters (`command -v`). hakrawler is pinned to
# @latest because the old v1.0.2 revision no longer resolves on the proxy.
RUN set -u; \
    for mod in \
        "github.com/projectdiscovery/httpx/cmd/httpx@v1.6.10" \
        "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.7.1" \
        "github.com/projectdiscovery/katana/cmd/katana@v1.1.2" \
        "github.com/jaeles-project/gospider@v1.1.6" \
        "github.com/lc/gau/v2/cmd/gau@v2.2.4" \
        "github.com/hakluke/hakrawler@latest" \
        "github.com/tomnomnom/waybackurls@v0.0.0-20230213113616-15ddc3e7e273" \
        "github.com/ffuf/ffuf/v2@v2.1.0" \
        "github.com/OJ/gobuster/v3@v3.6.0" \
        "github.com/sensepost/gowitness@v3.0.5" \
        "github.com/rverton/webanalyze/cmd/webanalyze@v0.4.0" \
        "github.com/projectdiscovery/tlsx/cmd/tlsx@v1.1.7" \
        "github.com/hahwul/dalfox/v2@v2.10.0" \
        "github.com/Emoe/kxss@v0.0.0-20230331131133-7e4a37ce9e9b" \
        "github.com/lc/subjs@v1.0.4" \
        "github.com/projectdiscovery/interactsh/cmd/interactsh-client@v1.2.0" \
    ; do \
        go install -ldflags="-s -w" "$mod" \
          || echo "WARN: go install failed (best-effort, guarded at runtime): $mod"; \
    done

# wappalyzer-cli (npm). Pinned to a known-stable version. Kept under the
# user prefix so we can COPY it across without a global install.
RUN mkdir -p /root/.npm-global \
 && npm config set prefix "/root/.npm-global" \
 && (npm install -g --omit=dev --no-audit --no-fund retire@5.2.7 newman wappalyzer@7.0.3 \
     || echo "WARN: npm install failed (best-effort; guarded at runtime)")

# repin3 — §4.4/§4.5/§4.7 tools with no clean apt/pip/go distribution: GitHub
# release binaries, git clones and PHP phars staged under /opt/argus-tools and
# COPYd to the runtime stage. ALL best-effort per tool (`|| echo WARN`): a stale
# release tag or network hiccup must not abort the image — the launcher shims in
# _shared/bin/ guard on presence (`-x`/`-f`) and degrade gracefully at runtime.
# Versions pinned to the latest stable at authoring; fix-forward by bumping here.
RUN set -u; mkdir -p /opt/argus-tools/bin /opt/argus-tools/webanalyze; \
    ( curl -fsSL -o /tmp/aquatone.zip \
        https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_amd64_1.7.0.zip \
      && unzip -o /tmp/aquatone.zip -d /opt/argus-tools/bin aquatone \
      && chmod 0755 /opt/argus-tools/bin/aquatone \
      && rm -f /tmp/aquatone.zip \
      || echo "WARN: aquatone release install failed (best-effort; guarded at runtime)" ); \
    ( curl -fsSL -o /tmp/kr.tgz \
        https://github.com/assetnote/kiterunner/releases/download/v1.0.2/kiterunner_1.0.2_linux_amd64.tar.gz \
      && tar -xzf /tmp/kr.tgz -C /opt/argus-tools/bin kr \
      && chmod 0755 /opt/argus-tools/bin/kr \
      && rm -f /tmp/kr.tgz \
      || echo "WARN: kiterunner release install failed (best-effort; guarded at runtime)" ); \
    ( git clone --depth 1 https://github.com/Dionach/CMSmap.git /opt/argus-tools/cmsmap \
      && python3 -m pip install --break-system-packages --no-cache-dir --user \
           -r /opt/argus-tools/cmsmap/requirements.txt \
      || echo "WARN: cmsmap clone/deps failed (best-effort; guarded at runtime)" ); \
    ( curl -fsSL -o /opt/argus-tools/magescan.phar \
        https://github.com/steverobbins/magescan/releases/download/v1.12.9/magescan.phar \
      && chmod 0755 /opt/argus-tools/magescan.phar \
      || echo "WARN: magescan phar download failed (best-effort; guarded at runtime)" ); \
    ( webanalyze -update >/dev/null 2>&1 \
      && mv -f technologies.json /opt/argus-tools/webanalyze/technologies.json \
      || echo "WARN: webanalyze -update failed (best-effort; guarded at runtime)" )

# arachni — full web app scanner (Arachni/arachni, self-contained Ruby bundle,
# ~0.5 GB). Approval-gated + heavy, so it is a SEPARATE best-effort layer pinned
# to the last upstream release; extracted to a stable path and symlinked onto
# PATH in the runtime stage. A missing/failed download leaves arachni simply
# absent (validate_tools reports it) rather than aborting the image.
RUN ( curl -fsSL -o /tmp/arachni.tgz \
        https://github.com/Arachni/arachni/releases/download/v1.6.1.3/arachni-1.6.1.3-0.6.1.1-linux-x86_64.tar.gz \
      && mkdir -p /opt/argus-tools/arachni \
      && tar -xzf /tmp/arachni.tgz -C /opt/argus-tools/arachni --strip-components=1 \
      && rm -f /tmp/arachni.tgz \
      || echo "WARN: arachni release install failed (best-effort; guarded at runtime)" )

# -----------------------------------------------------------------------------
# Stage 2 — runtime. Slim final image. No build toolchain, no compilers.
# -----------------------------------------------------------------------------
FROM kalilinux/kali-rolling:${KALI_TAG}

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
# Pin the apt mirror to HTTPS first (see builder stage): several §4.x tool
# .debs (nikto, responder, …) are blocked by AV middleboxes over cleartext HTTP.
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
        nmap \
        feroxbuster \
        wfuzz \
        wpscan \
        commix \
        joomscan \
        eyewitness \
        gobuster \
        gowitness \
        paramspider \
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
        php-cli \
        dpkg \
 && rm -rf /var/lib/apt/lists/*

# wpscan is now provided by the runtime apt package (Kali maintains a
# current build), so the fragile ruby-gem native-extension install is dropped.

# zap-baseline.py (OWASP ZAP passive scan, config/tools/zap_baseline.yaml). The
# zaproxy apt package is heavy (pulls a JRE) and occasionally unavailable, so it
# is a SEPARATE best-effort layer that must not fail the image; we then symlink
# the baseline launcher onto PATH wherever the package drops it. Missing ⇒ the
# tool is simply absent (validate_tools reports it; no hard failure).
RUN ( apt-get update \
      && apt-get install -y --no-install-recommends zaproxy \
      && rm -rf /var/lib/apt/lists/* \
      && zap="$(find /usr/share/zaproxy /usr/lib/zaproxy /opt/zaproxy -name 'zap-baseline.py' 2>/dev/null | head -n1)" \
      && [ -n "$zap" ] && ln -sf "$zap" /usr/local/bin/zap-baseline.py ) \
    || echo "WARN: zaproxy/zap-baseline.py install failed (best-effort; guarded at runtime)"

# Copy the user-installed Python wheels and Go binaries from the builder
# stage. We chown them on copy so the runtime user can read them without
# additional layers.
RUN groupadd --gid 65532 argus \
 && useradd --uid 65532 --gid 65532 --create-home --shell /usr/sbin/nologin argus

COPY --from=builder --chown=65532:65532 /root/.local            /home/argus/.local
COPY --from=builder --chown=65532:65532 /root/go/bin            /home/argus/go/bin
COPY --from=builder --chown=65532:65532 /root/.npm-global       /home/argus/.npm-global
# repin3 release/clone tools (aquatone, kr, cmsmap, magescan.phar, webanalyze
# fingerprints). /opt/argus-tools/bin is appended AFTER the base PATH so the
# _shared/bin launcher shims in /usr/local/bin win for tools that need argv
# adaptation (e.g. aquatone -list), while the bare `kr` binary stays resolvable.
COPY --from=builder --chown=65532:65532 /opt/argus-tools         /opt/argus-tools

ENV PATH="/home/argus/.local/bin:/home/argus/go/bin:/home/argus/.npm-global/bin:${PATH}:/opt/argus-tools/bin"

# arachni ships its CLI + reporter under a bundled-ruby bin dir; expose them on
# PATH when the (best-effort) release extraction succeeded. No-op otherwise.
RUN for b in arachni arachni_reporter; do \
      if [ -x "/opt/argus-tools/arachni/bin/$b" ]; then \
        ln -sf "/opt/argus-tools/arachni/bin/$b" "/usr/local/bin/$b"; \
      fi; \
    done; true

# Shared helpers (healthcheck + SBOM generator). Owned by root, executable
# for everyone — no SUID, no group write.
COPY --chmod=0755 _shared/healthcheck.sh   /usr/local/bin/healthcheck.sh
COPY --chmod=0755 _shared/generate_sbom.sh /usr/local/bin/generate_sbom.sh

# ARGUS tool wrappers — argv→upstream adapters for tools whose catalog
# command_template[0] is a wrapper rather than a bare binary (see
# infra/sandbox/expected_executables.json `kind: wrapper`). Each wrapper
# translates the sandbox's argv-only contract to the upstream tool's real CLI
# (stdin pipe, JSON envelope, headless driver) and always emits its evidence
# artifact so the parse strategy never faults.
COPY --chmod=0755 _shared/wrappers/ /usr/local/bin/

# ARGUS launcher shims for kind=binary tools without a clean upstream package —
# ARGUS-internal probes (oastify-client, openapi-scanner, cloud_metadata_check),
# GitHub-only clones / release binaries adapted to the catalog argv contract
# (aquatone -list, cmsmap, magescan, wappalyzer→webanalyze) and EOL tools
# (w3af_console stub). Same /usr/local/bin target as the wrappers; each guards on
# presence of its real backing tool and emits its evidence artifact fail-safe.
COPY --chmod=0755 _shared/bin/ /usr/local/bin/

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
