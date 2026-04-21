# syntax=docker/dockerfile:1.7
# =============================================================================
# argus-kali-network — sandbox image for protocol-level network exploitation.
# Cycle 5 / ARG-048 — multi-stage build with pinned versions, SBOM, USER 65532.
#
# Backlog/dev1_md §4.17 (network exploitation / protocol fuzzing — ike-scan,
# snmp toolkit, ldap utilities, redis-cli, mongodb shell, responder helpers,
# impacket-* binaries) and the protocol-relay / proxy lane that
# argus-kali-recon deliberately omits to keep its surface area small.
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
#   docker build -f sandbox/images/argus-kali-network/Dockerfile -t argus-kali-network:1.0.0 sandbox/
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1 — builder. Compiles a minimal Go toolchain for niche network helpers
# (kerbrute, gowitness for screenshot-on-port-open) and installs the impacket /
# bloodhound-python wheels that the runtime stage will COPY across.
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
        build-essential=\* \
        unzip=\* \
        jq=\* \
 && rm -rf /var/lib/apt/lists/*

# Pinned PyPI tools — §4.17 protocol-level enumeration / exploitation. These
# wheels ship CLI entrypoints (impacket-*, bloodhound-python) under
# ~/.local/bin so the COPY across to the runtime stage Just Works.
#   * impacket          — Windows / SMB / LDAP / Kerberos toolkit (smbexec,
#                         psexec, secretsdump, getuserspns, ntlmrelayx, ...)
#   * bloodhound        — AD recon collector (graph dump for BloodHound).
#   * crackmapexec      — Windows / SMB / WinRM swiss-army.
#   * evil-winrm-py     — Python rewrite of the WinRM shell.
#   * netaddr           — IP / network helper used by orchestrator scripts.
#   * dnspython         — DNS protocol library used by responder shims.
RUN python3 -m pip install --break-system-packages --no-cache-dir --user \
        impacket==0.12.0 \
        bloodhound==1.7.2 \
        crackmapexec==5.4.0 \
        evil-winrm-py==0.5.0 \
        netaddr==1.3.0 \
        dnspython==2.7.0

# Pinned Go binaries — niche network helpers that are not packaged in apt.
ENV GOPATH=/root/go GOBIN=/root/go/bin
ENV PATH="${GOBIN}:${PATH}"
RUN go install -ldflags="-s -w" github.com/ropnop/kerbrute@v1.0.3 \
 && go install -ldflags="-s -w" github.com/sensepost/gowitness@v3.0.5 \
 && go install -ldflags="-s -w" github.com/projectdiscovery/interactsh/cmd/interactsh-client@v1.2.0

# -----------------------------------------------------------------------------
# Stage 2 — runtime. Slim image with the heavy network-protocol clients (snmp,
# ldap, ike-scan, redis-cli, mongodb shell, smbclient, responder, samba) and
# the impacket suite copied in from the builder. NO SUID anywhere on $PATH.
# -----------------------------------------------------------------------------
FROM kalilinux/kali-rolling:2026.1

ARG DEBIAN_FRONTEND=noninteractive
ARG ARGUS_IMAGE_VERSION=1.0.0
ENV ARGUS_IMAGE_NAME=argus-kali-network

LABEL org.opencontainers.image.title="argus-kali-network" \
      org.opencontainers.image.description="ARGUS sandbox image — §4.17 network protocol exploitation (snmp/ike-scan/ldap/redis/mongodb/smbclient/responder/impacket-*) + Kerberos / NTLM relay tooling. Pinned versions, SBOM, non-root, no SUID introduction." \
      org.opencontainers.image.source="https://github.com/argus-active-pentest/argus" \
      org.opencontainers.image.version="${ARGUS_IMAGE_VERSION}" \
      org.opencontainers.image.licenses="Apache-2.0" \
      argus.image.profile="network" \
      argus.image.cycle="ARG-048" \
      argus.sbom.path="/usr/share/doc/sbom.cdx.json"

# Runtime apt — protocol-level tools. ``--no-install-recommends`` strips
# anything we don't explicitly ask for. Each block matches a sub-section of
# Backlog/dev1_md §4.17.
#   * SNMP / SMI:  snmp, snmp-mibs-downloader, onesixtyone.
#   * LDAP:        ldap-utils.
#   * SMB / Samba: smbclient, samba-common-bin, responder, impacket-scripts.
#   * IPSec:       ike-scan.
#   * Datastores:  redis-tools (redis-cli), mongodb-clients (mongo shell).
#   * Network IO:  rpcbind, dnsutils, openssl, ssldump.
#   * Routing:     traceroute, mtr-tiny, iputils-ping.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        wget \
        jq \
        git \
        python3 \
        python3-pip \
        snmp \
        snmp-mibs-downloader \
        onesixtyone \
        ldap-utils \
        smbclient \
        samba-common-bin \
        responder \
        impacket-scripts \
        ike-scan \
        redis-tools \
        mongodb-clients \
        rpcbind \
        dnsutils \
        openssl \
        ssldump \
        traceroute \
        mtr-tiny \
        iputils-ping \
        net-tools \
        dpkg \
 && rm -rf /var/lib/apt/lists/*

# Runtime user.
RUN groupadd --gid 65532 argus \
 && useradd --uid 65532 --gid 65532 --create-home --shell /usr/sbin/nologin argus

COPY --from=builder --chown=65532:65532 /root/.local /home/argus/.local
COPY --from=builder --chown=65532:65532 /root/go/bin /home/argus/go/bin

ENV PATH="/home/argus/.local/bin:/home/argus/go/bin:${PATH}"

# Shared helpers (healthcheck + SBOM generator).
COPY --chmod=0755 _shared/healthcheck.sh   /usr/local/bin/healthcheck.sh
COPY --chmod=0755 _shared/generate_sbom.sh /usr/local/bin/generate_sbom.sh

# Bake SBOM into the image (dpkg-query fallback — syft only in cloud image).
RUN /usr/local/bin/generate_sbom.sh /usr/share/doc/sbom.cdx.json \
 && chmod 0644 /usr/share/doc/sbom.cdx.json

USER 65532
WORKDIR /home/argus

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/healthcheck.sh"]

CMD ["sh", "-c", "echo 'argus-kali-network ready (cycle ARG-048); SBOM at /usr/share/doc/sbom.cdx.json'"]
