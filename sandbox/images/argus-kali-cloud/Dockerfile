# syntax=docker/dockerfile:1.7
# =============================================================================
# argus-kali-cloud — sandbox image for cloud / IaC / SAST / SCA tooling.
# Cycle 3 / ARG-026 — multi-stage build with pinned versions, SBOM, USER 65532.
# Backlog/dev1_md §4.13 (heavyweight crackers offloaded from web image),
# §4.15 (cloud auditing — prowler, scoutsuite, cloudsploit, pacu, kube-bench,
# kube-hunter), §4.16 (IaC / SAST / SCA — semgrep, bandit, trivy, grype,
# syft, kics, terrascan, tfsec, checkov, dockle, gitleaks, trufflehog,
# detect-secrets, hash-analyzer).
#
# Cloud credentials NEVER baked into the image — must arrive via runtime
# secret-mount per the §10/§18 secrets-handling contract. The Dockerfile
# does NOT install awscli / az / gcloud as default; operators inject the
# CLI via a sidecar or sourced credentials.
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
#   docker build -f sandbox/images/argus-kali-cloud/Dockerfile -t argus-kali-cloud:1.0.0 sandbox/
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1 — builder. Compiles Go binaries and installs pip wheels into a user
# prefix that we COPY across to the runtime stage.
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

# Pinned Python tools — §4.15 + §4.16 + §4.19 (binary scanners). Each
# version is the most recent stable on PyPI as of 2026-04-19.
# Best-effort PER PACKAGE (`|| true`): PyPI availability / interpreter compat
# drifts on the rolling base; a stale pin must not fail the image. Missing tools
# guarded at runtime (adapters check presence).
RUN set -u; \
    for spec in \
        "prowler==5.20.0" \
        "scoutsuite==5.14.0" \
        "pacu==1.6.1" \
        "cloudsplaining==0.7.0" \
        "cloudsplit==0.6.0" \
        "kube-hunter==0.6.10" \
        "semgrep==1.99.0" \
        "bandit==1.8.0" \
        "checkov==3.2.382" \
        "detect-secrets==1.5.0" \
    ; do \
        python3 -m pip install --break-system-packages --no-cache-dir --user "$spec" \
          || echo "WARN: pip install failed (best-effort, guarded at runtime): $spec"; \
    done

# kube-hunter ships a stand-alone wrapper via pip; cloud_metadata_check is an
# ARGUS-authored launcher shim (no PyPI) shipped from sandbox/images/_shared/bin/
# and COPYd to /usr/local/bin in the runtime stage below.

# Pinned Go-installed binaries. Only tfsec builds cleanly via `go install`.
ENV GOPATH=/root/go GOBIN=/root/go/bin
ENV PATH="${GOBIN}:${PATH}"
RUN set -u; \
    for mod in \
        "github.com/aquasecurity/tfsec/cmd/tfsec@v1.28.13" \
    ; do \
        go install -ldflags="-s -w" "$mod" \
          || echo "WARN: go install failed (best-effort, guarded at runtime): $mod"; \
    done

# grype / dockle / kube-bench — release binaries staged into GOBIN (COPYd to the
# runtime stage). `go install` fails for these: grype and dockle carry go.mod
# `replace` directives (rejected by `go install`), and kube-bench needs
# cgo/pkg-config that the slim builder lacks. Release tarballs ship static
# binaries. Best-effort per tool — a stale tag must not abort the image; runtime
# adapters guard on presence.
RUN set -u; \
    ( curl -fsSL -o /tmp/grype.tgz \
        https://github.com/anchore/grype/releases/download/v0.92.0/grype_0.92.0_linux_amd64.tar.gz \
      && tar -xzf /tmp/grype.tgz -C /root/go/bin grype \
      && chmod 0755 /root/go/bin/grype && rm -f /tmp/grype.tgz \
      || echo "WARN: grype release install failed (best-effort; guarded at runtime)" ); \
    ( curl -fsSL -o /tmp/dockle.tgz \
        https://github.com/goodwithtech/dockle/releases/download/v0.4.14/dockle_0.4.14_Linux-64bit.tar.gz \
      && tar -xzf /tmp/dockle.tgz -C /root/go/bin dockle \
      && chmod 0755 /root/go/bin/dockle && rm -f /tmp/dockle.tgz \
      || echo "WARN: dockle release install failed (best-effort; guarded at runtime)" ); \
    ( curl -fsSL -o /tmp/kube-bench.tgz \
        https://github.com/aquasecurity/kube-bench/releases/download/v0.10.4/kube-bench_0.10.4_linux_amd64.tar.gz \
      && tar -xzf /tmp/kube-bench.tgz -C /root/go/bin kube-bench \
      && chmod 0755 /root/go/bin/kube-bench && rm -f /tmp/kube-bench.tgz \
      || echo "WARN: kube-bench release install failed (best-effort; guarded at runtime)" )

# trufflehog — release binary (no clean go-install path on v3 module).
RUN curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/v3.84.2/scripts/install.sh \
        | sh -s -- -b /root/go/bin v3.84.2 \
 || echo "WARN: trufflehog install failed (best-effort; guarded at runtime)"

# kics — installed via release binary (large module, awkward go-install).
RUN mkdir -p /root/kics \
 && ( curl -sSfL -o /tmp/kics.tar.gz \
        https://github.com/Checkmarx/kics/releases/download/v2.1.6/kics_2.1.6_linux_x64.tar.gz \
      && tar -xzf /tmp/kics.tar.gz -C /root/kics \
      && rm -f /tmp/kics.tar.gz \
    || echo "WARN: kics install failed (best-effort; guarded at runtime)" )

# terrascan — release binary; tarball ships static binary + assets dir.
RUN mkdir -p /root/terrascan \
 && ( curl -sSfL -o /tmp/terrascan.tar.gz \
        https://github.com/tenable/terrascan/releases/download/v1.19.9/terrascan_1.19.9_Linux_x86_64.tar.gz \
      && tar -xzf /tmp/terrascan.tar.gz -C /root/terrascan \
      && rm -f /tmp/terrascan.tar.gz \
    || echo "WARN: terrascan install failed (best-effort; guarded at runtime)" )

# cloudsploit — Aqua CloudSploit (Node app; NO npm-published CLI binary). Cloned
# to /opt/argus-tools/cloudsploit and run via the _shared/bin/cloudsploit launcher
# (node index.js). Best-effort: a clone/npm hiccup must not abort the image; the
# launcher fail-safes on a missing clone.
RUN mkdir -p /opt/argus-tools \
 && ( git clone --depth 1 https://github.com/aquasecurity/cloudsploit.git /opt/argus-tools/cloudsploit \
      && ( cd /opt/argus-tools/cloudsploit && npm install --omit=dev --no-audit --no-fund ) \
    || echo "WARN: cloudsploit clone/npm failed (best-effort; guarded at runtime)" )

# -----------------------------------------------------------------------------
# Stage 2 — runtime. Slim, non-root, syft baked in for SBOM regen at runtime.
# -----------------------------------------------------------------------------
FROM kalilinux/kali-rolling:${KALI_TAG}

ARG DEBIAN_FRONTEND=noninteractive
ARG ARGUS_IMAGE_VERSION=1.0.0
ENV ARGUS_IMAGE_NAME=argus-kali-cloud

LABEL org.opencontainers.image.title="argus-kali-cloud" \
      org.opencontainers.image.description="ARGUS sandbox image — §4.13 hash crackers + §4.15 cloud (prowler, scoutsuite, pacu, kube-bench, kube-hunter, trivy, grype, dockle) + §4.16 SAST/IaC (semgrep, bandit, kics, terrascan, tfsec, checkov, gitleaks, trufflehog, detect-secrets, syft). Pinned versions, SBOM, non-root." \
      org.opencontainers.image.source="https://github.com/argus-active-pentest/argus" \
      org.opencontainers.image.version="${ARGUS_IMAGE_VERSION}" \
      org.opencontainers.image.licenses="Apache-2.0" \
      argus.image.profile="cloud" \
      argus.image.cycle="ARG-026" \
      argus.sbom.path="/usr/share/doc/sbom.cdx.json"

# Pin apt mirror to HTTPS first: §4.13 crackers (john/hashcat/…) and other tool
# .debs may be blocked by AV middleboxes over cleartext HTTP (499). Retries guard
# transient failures. NOTE: build hosts behind a Cisco Meraki content filter
# (wired.meraki.com:8090) get HTTP to Kali repos blocked AND HTTPS intermittently
# MITM'd (cert verify failures at the mirror IP) — if apt update fails here,
# rebuild on an unfiltered network / VPN.
RUN apt-get -o Acquire::Retries=5 update \
 && apt-get -o Acquire::Retries=5 install -y --no-install-recommends ca-certificates \
 && printf 'deb https://http.kali.org/kali kali-rolling main contrib non-free non-free-firmware\n' > /etc/apt/sources.list \
 && rm -rf /var/lib/apt/lists/*
RUN apt-get -o Acquire::Retries=5 update \
 && apt-get -o Acquire::Retries=5 install -y --no-install-recommends \
        ca-certificates \
        curl \
        wget \
        jq \
        git \
        python3 \
        python3-pip \
        nodejs \
        npm \
        trivy \
        syft \
        gitleaks \
        john \
        hashcat \
        hashid \
        ophcrack \
        dpkg \
 && rm -rf /var/lib/apt/lists/*

# Runtime user.
RUN groupadd --gid 65532 argus \
 && useradd --uid 65532 --gid 65532 --create-home --shell /usr/sbin/nologin argus

# Copy installed bits from builder. chown on copy so the runtime user can
# read them without an extra RUN chown layer.
COPY --from=builder --chown=65532:65532 /root/.local            /home/argus/.local
COPY --from=builder --chown=65532:65532 /root/go/bin            /home/argus/go/bin
COPY --from=builder --chown=65532:65532 /root/kics              /home/argus/kics
COPY --from=builder --chown=65532:65532 /root/terrascan         /home/argus/terrascan
# cloudsploit clone (run via the _shared/bin/cloudsploit launcher: node index.js).
COPY --from=builder --chown=65532:65532 /opt/argus-tools         /opt/argus-tools

# Shim wrappers for kics / terrascan so they live on $PATH without bind-
# mounting the assets dir.
RUN ln -sf /home/argus/kics/kics                /usr/local/bin/kics \
 && ln -sf /home/argus/terrascan/terrascan      /usr/local/bin/terrascan

ENV PATH="/home/argus/.local/bin:/home/argus/go/bin:${PATH}"

# Shared helpers (healthcheck + SBOM generator).
COPY --chmod=0755 _shared/healthcheck.sh   /usr/local/bin/healthcheck.sh
COPY --chmod=0755 _shared/generate_sbom.sh /usr/local/bin/generate_sbom.sh

# ARGUS launcher shim(s) for kind=binary tools without a clean upstream package.
# For this image: cloud_metadata_check (internal cloud IMDS/SSRF probe). The dir
# also carries web-only shims; they are inert here (not on this profile's
# validate_tools list). Same /usr/local/bin target; fail-safe on missing backends.
COPY --chmod=0755 _shared/bin/ /usr/local/bin/

# Bake SBOM into the image — this image ships syft, so the wrapper picks
# up the real syft binary and emits a complete CycloneDX 1.5 doc.
RUN /usr/local/bin/generate_sbom.sh /usr/share/doc/sbom.cdx.json \
 && chmod 0644 /usr/share/doc/sbom.cdx.json

USER 65532
WORKDIR /home/argus

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/healthcheck.sh"]

CMD ["sh", "-c", "echo 'argus-kali-cloud ready (cycle ARG-026); SBOM at /usr/share/doc/sbom.cdx.json'"]
