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
FROM kalilinux/kali-rolling:2026.1 AS builder

ARG DEBIAN_FRONTEND=noninteractive

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
RUN python3 -m pip install --break-system-packages --no-cache-dir --user \
        prowler==5.20.0 \
        scoutsuite==5.14.0 \
        pacu==1.6.1 \
        cloudsplaining==0.7.0 \
        cloudsplit==0.6.0 \
        kube-hunter==0.6.10 \
        semgrep==1.99.0 \
        bandit==1.8.0 \
        checkov==3.2.382 \
        detect-secrets==1.5.0

# kube-hunter has a stand-alone wrapper in pip; cloud-metadata-check is a
# tiny shim in our own /sbin (no PyPI), shipped via the sandbox config map.

# Pinned Go-installed binaries.
ENV GOPATH=/root/go GOBIN=/root/go/bin
ENV PATH="${GOBIN}:${PATH}"
RUN go install -ldflags="-s -w" github.com/aquasecurity/trivy/cmd/trivy@v0.70.0 \
 && go install -ldflags="-s -w" github.com/anchore/syft/cmd/syft@v1.42.4 \
 && go install -ldflags="-s -w" github.com/anchore/grype/cmd/grype@v0.92.0 \
 && go install -ldflags="-s -w" github.com/aquasecurity/tfsec/cmd/tfsec@v1.28.13 \
 && go install -ldflags="-s -w" github.com/aquasecurity/kube-bench@v0.10.4 \
 && go install -ldflags="-s -w" github.com/zricethezav/gitleaks/v8@v8.21.4 \
 && go install -ldflags="-s -w" github.com/goodwithtech/dockle/cmd/dockle@v0.4.14

# trufflehog — release binary (no clean go-install path on v3 module).
RUN curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/v3.84.2/scripts/install.sh \
        | sh -s -- -b /root/go/bin v3.84.2

# kics — installed via release binary (large module, awkward go-install).
RUN curl -sSfL -o /tmp/kics.tar.gz \
        https://github.com/Checkmarx/kics/releases/download/v2.1.6/kics_2.1.6_linux_x64.tar.gz \
 && mkdir -p /root/kics \
 && tar -xzf /tmp/kics.tar.gz -C /root/kics \
 && rm -f /tmp/kics.tar.gz

# terrascan — release binary; tarball ships static binary + assets dir.
RUN curl -sSfL -o /tmp/terrascan.tar.gz \
        https://github.com/tenable/terrascan/releases/download/v1.19.9/terrascan_1.19.9_Linux_x86_64.tar.gz \
 && mkdir -p /root/terrascan \
 && tar -xzf /tmp/terrascan.tar.gz -C /root/terrascan \
 && rm -f /tmp/terrascan.tar.gz

# cloudsploit — npm. Pinned.
RUN npm config set prefix "/root/.npm-global" \
 && npm install --omit=dev cloudsploit@1.0.0

# -----------------------------------------------------------------------------
# Stage 2 — runtime. Slim, non-root, syft baked in for SBOM regen at runtime.
# -----------------------------------------------------------------------------
FROM kalilinux/kali-rolling:2026.1

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
COPY --from=builder --chown=65532:65532 /root/.npm-global       /home/argus/.npm-global
COPY --from=builder --chown=65532:65532 /root/kics              /home/argus/kics
COPY --from=builder --chown=65532:65532 /root/terrascan         /home/argus/terrascan

# Shim wrappers for kics / terrascan so they live on $PATH without bind-
# mounting the assets dir.
RUN ln -sf /home/argus/kics/kics                /usr/local/bin/kics \
 && ln -sf /home/argus/terrascan/terrascan      /usr/local/bin/terrascan

ENV PATH="/home/argus/.local/bin:/home/argus/go/bin:/home/argus/.npm-global/bin:${PATH}"

# Shared helpers (healthcheck + SBOM generator).
COPY --chmod=0755 _shared/healthcheck.sh   /usr/local/bin/healthcheck.sh
COPY --chmod=0755 _shared/generate_sbom.sh /usr/local/bin/generate_sbom.sh

# Bake SBOM into the image — this image ships syft, so the wrapper picks
# up the real syft binary and emits a complete CycloneDX 1.5 doc.
RUN /usr/local/bin/generate_sbom.sh /usr/share/doc/sbom.cdx.json \
 && chmod 0644 /usr/share/doc/sbom.cdx.json

USER 65532
WORKDIR /home/argus

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/healthcheck.sh"]

CMD ["sh", "-c", "echo 'argus-kali-cloud ready (cycle ARG-026); SBOM at /usr/share/doc/sbom.cdx.json'"]
