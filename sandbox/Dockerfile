# ARGUS Sandbox — Kali-based container for pentest tool execution
#
# =============================================================================
# Image size & profiles (KAL-001)
# =============================================================================
# We intentionally avoid kali-linux-large (full desktop-oriented metapackage).
# Base stack: kalilinux/kali-rolling + kali-linux-headless + curated kali-tools-*
# metapackages. That keeps a defined “headless Kali” baseline without pulling
# the entire large distribution by default.
#
# SANDBOX_PROFILE=standard (default):
#   kali-tools-top10, kali-tools-web, kali-tools-information-gathering,
#   kali-tools-vulnerability — typically multi‑GB; still far smaller than
#   kali-linux-large + desktop chains.
#
# SANDBOX_PROFILE=extended:
#   additionally installs kali-tools-passwords (john/hashcat/medusa-heavy
#   dependency graph, wordlists/crypto tooling). Expect a noticeable image size
#   jump vs standard (often 1–3+ GB extra depending on rolling versions).
#
# Explicit apt packages below ensure PATH coverage even if metapackage contents
# shift between Kali releases.
#
# Fallbacks (if apt reports “no installation candidate” on a niche arch):
#   - testssl.sh: upstream https://github.com/drwetter/testssl.sh (clone + PATH)
#   - dirbuster: legacy Java UI; prefer feroxbuster/gobuster/ffuf (already present)
#   - nuclei: projectdiscovery releases (this image prefers apt `nuclei` from Kali)
#
# XSS / VA extras (not always in generic pentest lists):
#   dalfox: GitHub release binary; xsstrike: /opt/xsstrike + symlink on PATH.
#
# Metasploit (~1.5 GB+): optional INSTALL_MSF=true — exploitation pipeline
# degrades gracefully if msfconsole is absent.
#
# PATH sanity (example):
#   which nmap nuclei ffuf sqlmap searchsploit testssl.sh dalfox xsstrike

FROM kalilinux/kali-rolling:latest

ARG SANDBOX_PROFILE=standard
ARG INSTALL_MSF=false
ARG DALFOX_VERSION=2.12.0

RUN set -eux; \
    export DEBIAN_FRONTEND=noninteractive; \
    apt-get update; \
    case "${SANDBOX_PROFILE}" in \
      standard|extended) ;; \
      *) echo "SANDBOX_PROFILE must be 'standard' or 'extended', got: ${SANDBOX_PROFILE}" >&2; exit 1 ;; \
    esac; \
    EXT_META=""; \
    if [ "${SANDBOX_PROFILE}" = "extended" ]; then EXT_META="kali-tools-passwords"; fi; \
    apt-get install -y --no-install-recommends \
      kali-linux-headless \
      kali-tools-top10 \
      kali-tools-web \
      kali-tools-information-gathering \
      kali-tools-vulnerability \
      ${EXT_META} \
      ca-certificates \
      git \
      curl \
      wget \
      unzip \
      tar \
      net-tools \
      python3 \
      python3-pip \
      python3-venv \
      nmap \
      masscan \
      tcpdump \
      tshark \
      dnsutils \
      whois \
      jq \
      nuclei \
      ffuf \
      gobuster \
      wfuzz \
      sqlmap \
      commix \
      nikto \
      whatweb \
      sslscan \
      feroxbuster \
      hydra \
      medusa \
      john \
      hashcat \
      mitmproxy \
      dnsrecon \
      fierce \
      amass \
      subfinder \
      testssl.sh \
      dirb \
      wpscan \
      joomscan \
      exploitdb \
      dirbuster \
      trivy \
      theharvester \
      gospider \
      parsero \
    ; \
    rm -rf /var/lib/apt/lists/*

# DalFox — XSS scanner; no stable `dalfox` package in rolling at time of writing.
RUN ARCH=$(dpkg --print-architecture) && \
    if [ "$ARCH" = "amd64" ]; then DALFOX_ASSET="linux-amd64"; \
    elif [ "$ARCH" = "arm64" ]; then DALFOX_ASSET="linux-arm64"; \
    else DALFOX_ASSET="linux-amd64"; fi && \
    curl -fsSL "https://github.com/hahwul/dalfox/releases/download/v${DALFOX_VERSION}/dalfox-${DALFOX_ASSET}.tar.gz" \
      -o /tmp/dalfox.tgz && \
    mkdir -p /tmp/dalfox-extract && \
    tar -xzf /tmp/dalfox.tgz -C /tmp/dalfox-extract && \
    install -m 755 "/tmp/dalfox-extract/dalfox-${DALFOX_ASSET}" /usr/local/bin/dalfox && \
    rm -rf /tmp/dalfox.tgz /tmp/dalfox-extract

# XSStrike — VA pipeline; /opt/xsstrike matches backend xsstrike_adapter sandbox paths
RUN git clone --depth 1 https://github.com/s0md3v/XSStrike.git /opt/xsstrike \
    && pip3 install --no-cache-dir --break-system-packages \
        -r /opt/xsstrike/requirements.txt \
    && rm -rf /opt/xsstrike/.git \
    && chmod +x /opt/xsstrike/xsstrike.py \
    && ln -sf /opt/xsstrike/xsstrike.py /usr/local/bin/xsstrike

# VDF-009 — dirsearch CLI (not always packaged on rolling)
RUN pip3 install --no-cache-dir --break-system-packages dirsearch || true

RUN pip install playwright && playwright install chromium

RUN if [ "${INSTALL_MSF}" = "true" ]; then \
      export DEBIAN_FRONTEND=noninteractive; \
      apt-get update && apt-get install -y --no-install-recommends metasploit-framework \
      && rm -rf /var/lib/apt/lists/*; \
    fi

RUN mkdir -p /opt/exploit_scripts /tmp/argus-sandbox

RUN useradd -m -s /bin/bash argus

COPY backend/data/payloads/ /opt/argus-payloads/
COPY backend/data/sqli_all.txt /opt/argus-payloads/sqli_all.txt
COPY backend/data/xss_payloads.txt /opt/argus-payloads/xss_payloads.txt

RUN nuclei -update-templates 2>/dev/null || true && \
    chown -R argus:argus /opt/exploit_scripts /opt/xsstrike /tmp/argus-sandbox /opt/argus-payloads

# VDF-009 — smoke: testssl / trivy / gospider / parsero / dirsearch on PATH
RUN testssl.sh --version 2>/dev/null | head -n1 || which testssl.sh || true; \
    trivy --version 2>/dev/null | head -n1 || true; \
    gospider -h 2>/dev/null | head -n1 || which gospider || true; \
    parsero -h 2>/dev/null | head -n1 || which parsero || true; \
    dirsearch --version 2>/dev/null | head -n1 || which dirsearch || true

USER argus
WORKDIR /home/argus

CMD ["tail", "-f", "/dev/null"]
