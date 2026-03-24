# ARGUS Sandbox — Kali-based container for pentest tool execution
# Stages 1-3: nmap, dnsutils, whois
# Stage 4: sqlmap, hydra, nuclei (exploitation tools)
# VA active-scan (Kali rolling apt where packaged): ffuf, gobuster, wfuzz.
# dalfox: not in Kali apt as of rolling — pinned GitHub release tarball (~few MB) to avoid golang toolchain in image.
# commix: clone to /opt/commix + pip install (console_scripts → /usr/local/bin/commix); smaller than pulling duplicate apt + matches adapter PATH.

FROM kalilinux/kali-rolling:latest

# Base + Stage 1-3 tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    git \
    nmap \
    dnsutils \
    whois \
    curl \
    wget \
    net-tools \
    python3 \
    python3-pip \
    python3-venv \
    unzip \
    tar \
    # Stage 4: exploitation tools
    sqlmap \
    hydra \
    # VA scanners (OWASP pipeline): Kali package names match upstream binaries
    ffuf \
    gobuster \
    wfuzz \
    && rm -rf /var/lib/apt/lists/*

# DalFox — XSS scanner; upstream Go binary (apt-cache shows no `dalfox` package on kali-rolling).
# Release assets use names like dalfox-linux-amd64.tar.gz (not dalfox_${VER}_linux_amd64).
ARG DALFOX_VERSION=2.12.0
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

# Nuclei — binary release (not available in Kali repos by default)
ARG NUCLEI_VERSION=3.3.7
RUN ARCH=$(dpkg --print-architecture) && \
    if [ "$ARCH" = "amd64" ]; then NUCLEI_ARCH="linux_amd64"; \
    elif [ "$ARCH" = "arm64" ]; then NUCLEI_ARCH="linux_arm64"; \
    else NUCLEI_ARCH="linux_amd64"; fi && \
    curl -sSL "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_${NUCLEI_ARCH}.zip" \
      -o /tmp/nuclei.zip && \
    unzip -o /tmp/nuclei.zip -d /usr/local/bin/ && \
    chmod +x /usr/local/bin/nuclei && \
    rm -f /tmp/nuclei.zip

# XSStrike — XSS scanner (VA pipeline); /opt/xsstrike matches backend xsstrike_adapter sandbox paths
RUN git clone --depth 1 https://github.com/s0md3v/XSStrike.git /opt/xsstrike \
    && pip3 install --no-cache-dir --break-system-packages \
        -r /opt/xsstrike/requirements.txt \
    && rm -rf /opt/xsstrike/.git

# Commix — /opt/commix + setuptools entry (commix on PATH); apt has `commix` but duplicate tree avoided here
RUN git clone --depth 1 https://github.com/commixproject/commix.git /opt/commix \
    && pip3 install --no-cache-dir --break-system-packages /opt/commix \
    && rm -rf /opt/commix/.git

# Metasploit Framework — heavy (~1.5 GB), included only when INSTALL_MSF=true build arg is set.
# For minimal images or CI, omit --build-arg INSTALL_MSF=true.
# The exploitation pipeline gracefully degrades if msfconsole is not available.
ARG INSTALL_MSF=false
RUN if [ "$INSTALL_MSF" = "true" ]; then \
      apt-get update && apt-get install -y --no-install-recommends metasploit-framework \
      && rm -rf /var/lib/apt/lists/*; \
    fi

# Exploit scripts mount point
RUN mkdir -p /opt/exploit_scripts /tmp/argus-sandbox

RUN useradd -m -s /bin/bash argus

# Pre-download nuclei templates (as root, then chown)
RUN nuclei -update-templates 2>/dev/null || true && \
    chown -R argus:argus /opt/exploit_scripts /opt/xsstrike /opt/commix /tmp/argus-sandbox

USER argus
WORKDIR /home/argus

CMD ["tail", "-f", "/dev/null"]
