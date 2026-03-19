# ARGUS Sandbox — Kali-based container for pentest tool execution
# Stages 1-3: nmap, dnsutils, whois
# Stage 4: sqlmap, hydra, nuclei (exploitation tools)

FROM kalilinux/kali-rolling:latest

# Base + Stage 1-3 tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
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
    # Stage 4: exploitation tools
    sqlmap \
    hydra \
    && rm -rf /var/lib/apt/lists/*

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
    chown -R argus:argus /opt/exploit_scripts /tmp/argus-sandbox

USER argus
WORKDIR /home/argus

CMD ["tail", "-f", "/dev/null"]
