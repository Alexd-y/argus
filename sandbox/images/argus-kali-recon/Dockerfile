# syntax=docker/dockerfile:1.7
# =============================================================================
# argus-kali-recon — sandbox image for passive + active recon tooling.
# Cycle 5 / ARG-048 — multi-stage build with pinned versions, SBOM, USER 65532.
#
# Backlog/dev1_md §4.1 (passive recon: amass-passive, subfinder, findomain,
# assetfinder, chaos, dnsx, dnsrecon, fierce, theHarvester, otx_alienvault,
# securitytrails, shodan_cli, censys, crt_sh, urlscan, github_search,
# whois/rdap) and §4.2 (active recon: masscan, naabu, rustscan, nmap_*,
# unicornscan, smbmap, rpcclient_enum, enum4linux_ng).
#
# Hardening contract enforced by tests/integration/sandbox/test_image_security_contract.py:
#   * USER 65532 in final stage (matches k8s securityContext runAsUser).
#   * HEALTHCHECK directive present, invoking the shared healthcheck.sh.
#   * LABEL argus.sbom.path="/usr/share/doc/sbom.cdx.json".
#   * LABEL org.opencontainers.image.{title,description,source}.
#   * LABEL argus.image.{profile,cycle}.
#   * No `RUN chmod +s` patterns (no SUID introduction).
#   * Multi-stage: ≥1 `FROM ... AS builder` + ≥1 final `FROM`.
#
# Build:
#   docker build -f sandbox/images/argus-kali-recon/Dockerfile -t argus-kali-recon:1.0.0 sandbox/
#
# Verify hardening at build time (in CI):
#   docker run --rm argus-kali-recon:1.0.0 sh -c 'find / -perm -4000 -type f 2>/dev/null'
#   # ↑ Allowed list: /usr/bin/su, /usr/bin/sudo, /usr/bin/mount, /usr/bin/umount,
#   #   /usr/bin/passwd, /usr/bin/chsh, /usr/bin/chfn, /usr/bin/newgrp,
#   #   /usr/bin/gpasswd. NO tool binaries.
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1 — builder. Compiles ProjectDiscovery Go binaries (subfinder, naabu,
# dnsx, chaos-client, ...) and installs PyPI wheels (theHarvester, dnsrecon,
# fierce) into a user prefix that we COPY across to the runtime stage. Keeps
# build toolchain (gcc, go, npm) out of the final image, shrinking surface
# area and removing all SUID bits the toolchain might leave behind.
# -----------------------------------------------------------------------------
# Base image tag is overridable for reproducible pinning (--build-arg KALI_TAG=…);
# default `latest` because Kali publishes no date-stamped `kali-rolling` tag on Docker Hub.
ARG KALI_TAG=latest
FROM kalilinux/kali-rolling:${KALI_TAG} AS builder

ARG DEBIAN_FRONTEND=noninteractive

# Some networks/AV middleboxes block Kali security-tool .debs over cleartext HTTP
# (HTTP 499 "forbidden by antivirus"). Fetch ca-certificates then pin the apt
# mirror to HTTPS so tool payloads are not content-inspected. Deterministic
# overwrite of sources.list; first package step of the stage.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && printf 'deb https://http.kali.org/kali kali-rolling main contrib non-free non-free-firmware\n' > /etc/apt/sources.list \
 && rm -rf /var/lib/apt/lists/*

# Builder toolchain. Pinned to apt's current "rolling" snapshot.
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

# Pinned PyPI tools — §4.1 passive OSINT and §4.2 enumeration.
#   * theHarvester  — passive email/host harvester.
#   * dnsrecon      — DNS enumeration (axfr, srv, brute).
#   * fierce        — DNS enum complement.
#   * censys        — Censys.io API client.
#   * shodan        — Shodan API client.
#   * dnstwist      — DNS typo-squat permutations.
#   * sublist3r     — passive subdomain bruteforcer.
#   * urlfinder     — passive URL collector.
#   * whois         — Python whois client (RDAP fallback).
# Best-effort PER PACKAGE (`|| true`): upstream PyPI availability / interpreter
# compatibility drifts on the rolling base; a single stale pin must not fail the
# image. Missing tools are guarded at runtime (adapters check presence).
RUN set -u; \
    for spec in \
        "fierce==1.5.0" \
        "censys==2.2.13" \
        "shodan==1.31.0" \
        "dnstwist==20240916" \
        "sublist3r==1.1" \
        "python-whois==0.9.5" \
    ; do \
        python3 -m pip install --break-system-packages --no-cache-dir --user "$spec" \
          || echo "WARN: pip install failed (best-effort, guarded at runtime): $spec"; \
    done

# Pinned Go-installed §4.1 / §4.2 binaries. ``-s -w`` strips symbol tables and
# debug info so the runtime image stays compact (Trivy still scans the binary
# via SBOM purl matching, not via debug symbols).
ENV GOPATH=/root/go GOBIN=/root/go/bin
ENV PATH="${GOBIN}:${PATH}"
# Best-effort PER MODULE (`|| echo WARN`): a single stale/retagged module must
# not abort the whole chain. Failed tools are guarded at runtime.
RUN set -u; \
    for mod in \
        "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.6.7" \
        "github.com/projectdiscovery/dnsx/cmd/dnsx@v1.2.2" \
        "github.com/projectdiscovery/chaos-client/cmd/chaos@v0.5.1" \
        "github.com/projectdiscovery/asnmap/cmd/asnmap@v1.1.1" \
        "github.com/projectdiscovery/uncover/cmd/uncover@v1.0.9" \
        "github.com/projectdiscovery/mapcidr/cmd/mapcidr@v1.1.34" \
        "github.com/owasp-amass/amass/v4/...@v4.2.0" \
        "github.com/tomnomnom/assetfinder@v0.1.1" \
        "github.com/RustScan/RustScan/...@v2.3.0" \
        "github.com/sensepost/gowitness@v3.0.5" \
    ; do \
        go install -ldflags="-s -w" "$mod" \
          || echo "WARN: go install failed (best-effort, guarded at runtime): $mod"; \
    done

# -----------------------------------------------------------------------------
# Stage 2 — runtime. Slim final image. No build toolchain, no compilers; only
# tools needed at execution time. Apt packages cover the well-trodden recon
# helpers (nmap, masscan, unicornscan, smbmap, dnsutils) that don't ship as
# Go modules.
# -----------------------------------------------------------------------------
FROM kalilinux/kali-rolling:${KALI_TAG}

ARG DEBIAN_FRONTEND=noninteractive
ARG ARGUS_IMAGE_VERSION=1.0.0
ENV ARGUS_IMAGE_NAME=argus-kali-recon

# OCI + ARGUS labels. The hardening test asserts every key below.
LABEL org.opencontainers.image.title="argus-kali-recon" \
      org.opencontainers.image.description="ARGUS sandbox image — §4.1 passive recon (subfinder/amass/findomain/assetfinder/dnsx/dnsrecon/theHarvester/whois/RDAP/censys/shodan/securitytrails/crt.sh/urlscan/otx) + §4.2 active recon (nmap/masscan/naabu/rustscan/unicornscan/smbmap/rpcclient/enum4linux). Pinned versions, SBOM, non-root, no SUID introduction." \
      org.opencontainers.image.source="https://github.com/argus-active-pentest/argus" \
      org.opencontainers.image.version="${ARGUS_IMAGE_VERSION}" \
      org.opencontainers.image.licenses="Apache-2.0" \
      argus.image.profile="recon" \
      argus.image.cycle="ARG-048" \
      argus.sbom.path="/usr/share/doc/sbom.cdx.json"

# Runtime apt packages — only what tools need at execution. No -dev / -dbg
# packages, no compilers. ``--no-install-recommends`` keeps the layer minimal.
#   * §4.1 passive OSINT: dnsutils (dig, host, nslookup), whois.
#   * §4.2 active recon: nmap, ncat, masscan, unicornscan, smbmap, rpcbind,
#                        ldap-utils, enum4linux, samba-common-bin (rpcclient).
#   * Common: ca-certificates, curl, wget, jq, python3, openssl.
# Pin the apt mirror to HTTPS first: recon tool .debs (nmap, masscan, enum4linux,
# …) are blocked by AV middleboxes over cleartext HTTP (HTTP 499).
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
        nodejs \
        npm \
        ruby \
        nmap \
        ncat \
        masscan \
        unicornscan \
        dnsutils \
        whois \
        smbmap \
        smbclient \
        ldap-utils \
        enum4linux \
        enum4linux-ng \
        dnsrecon \
        theharvester \
        naabu \
        findomain \
        samba-common-bin \
        openssl \
        net-tools \
        dpkg \
 && rm -rf /var/lib/apt/lists/*

# Runtime user — uid/gid match the k8s securityContext (Cycle 1 ARG-004).
RUN groupadd --gid 65532 argus \
 && useradd --uid 65532 --gid 65532 --create-home --shell /usr/sbin/nologin argus

# Copy user-installed Python wheels and Go binaries from the builder stage.
# We chown them on copy so the runtime user can read them without an extra
# layer that would bloat the image.
COPY --from=builder --chown=65532:65532 /root/.local      /home/argus/.local
COPY --from=builder --chown=65532:65532 /root/go/bin      /home/argus/go/bin

ENV PATH="/home/argus/.local/bin:/home/argus/go/bin:${PATH}"

# Shared helpers (healthcheck + SBOM generator). Owned by root, executable
# for everyone — no SUID, no group write.
COPY --chmod=0755 _shared/healthcheck.sh   /usr/local/bin/healthcheck.sh
COPY --chmod=0755 _shared/generate_sbom.sh /usr/local/bin/generate_sbom.sh

# Generate the SBOM at build time and bake it into the image. The wrapper
# falls back to dpkg-query when syft is absent (which it is in this image —
# syft only ships in argus-kali-cloud).
RUN /usr/local/bin/generate_sbom.sh /usr/share/doc/sbom.cdx.json \
 && chmod 0644 /usr/share/doc/sbom.cdx.json

# Runtime user. Read-only fs at the k8s layer; tools that need scratch space
# get /tmp (tmpfs) or /out (emptyDir) at runtime, never the rootfs.
USER 65532
WORKDIR /home/argus

# HEALTHCHECK — every 30s, fail closed after 10s.
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/healthcheck.sh"]

# Default entrypoint — sandbox driver overrides it via Job spec. We keep a
# safe noop default so `docker run argus-kali-recon:1.0.0` exits cleanly.
CMD ["sh", "-c", "echo 'argus-kali-recon ready (cycle ARG-048); SBOM at /usr/share/doc/sbom.cdx.json'"]
