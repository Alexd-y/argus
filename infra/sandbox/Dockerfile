# ARGUS Sandbox — Kali-based pentest runner with fuzzing and symbolic execution tools.
#
# Profiles:
#   SANDBOX_PROFILE=standard  — web/network/cloud/browser (default, production)
#   SANDBOX_PROFILE=full      — all tools including MSF
#   SANDBOX_PROFILE=binary    — AFL++, angr, Z3, Jazzer (fuzzing + symbolic execution)
#
# Build:
#   docker compose -f infra/docker-compose.yml build sandbox
#   # Or standalone for binary profile:
#   docker build --build-arg SANDBOX_PROFILE=binary -t argus-sandbox -f infra/sandbox/Dockerfile .
#
# Security: runs as non-root user (argus:1000), no Docker socket mount,
#           read-only root filesystem except /workspace and /tmp.

ARG SANDBOX_PROFILE=standard
FROM kalilinux/kali-rolling:latest AS base

# Base: common packages shared across all profiles
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv python3-dev \
    git curl wget gdb strace ltrace \
    libssl-dev libffi-dev libxml2-dev libxslt1-dev \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user (matches ephemeral_worker.py ContainerSpec)
RUN groupadd -g 1000 argus && useradd -m -u 1000 -g 1000 -s /bin/bash argus

# ---- Standard profile: web/network/cloud/browser tools ----
FROM base AS standard
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    # Recon
    nmap masscan subfinder amass dnsrecon gobuster ffuf nuclei httpx \
    # Web VA
    sqlmap nikto wpscan dirsearch dalfox xsstrike \
    # Network
    hydra medusa crackmapexec impacket-scripts smbclient \
    # SSL/TLS
    sslscan testssl.sh \
    # Misc
    jq whois netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

# ---- Full profile: standard + metasploit ----
FROM standard AS full
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    metasploit-framework \
    && rm -rf /var/lib/apt/lists/*

# ---- Binary profile: AFL++, angr, Z3, Jazzer for fuzzing + symbolic execution ----
FROM base AS binary

# AFL++ — state-of-the-art fuzzer (C/C++/binary)
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    build-essential gcc g++ make cmake automake autoconf libtool \
    libgtk-3-dev wget flex bison \
    && git clone --depth=1 https://github.com/AFLplusplus/AFLplusplus /opt/aflplusplus \
    && cd /opt/aflplusplus && make distrib && make install \
    && rm -rf /opt/aflplusplus/.git \
    && apt-get purge -y libgtk-3-dev && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

# angr — binary analysis framework (Python)
RUN pip3 install --no-cache-dir angr z3-solver pyelftools lief

# Jazzer — JVM fuzzing (requires JDK)
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    default-jdk maven \
    && git clone --depth=1 https://github.com/CodeIntelligenceTesting/jazzer /opt/jazzer \
    && cd /opt/jazzer && mvn package -DskipTests -q \
    && rm -rf /opt/jazzer/.git /root/.m2/repository \
    && rm -rf /var/lib/apt/lists/*

# radare2 — reverse engineering
RUN git clone --depth=1 https://github.com/radareorg/radare2 /opt/radare2 \
    && cd /opt/radare2 && sys/install.sh \
    && rm -rf /opt/radare2/.git \
    && rm -rf /var/lib/apt/lists/*

# binwalk — firmware extraction
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    binwalk python3-binwalk \
    && rm -rf /var/lib/apt/lists/*

# libFuzzer harness support (clang with built-in fuzzer)
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    clang llvm \
    && rm -rf /var/lib/apt/lists/*

# Standard recon tools + web VA (shared with standard profile)
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    nmap nuclei httpx sqlmap nikto gobuster ffuf jq curl wget \
    && rm -rf /var/lib/apt/lists/*

# Verify all tools are available
RUN echo "#!/bin/sh" > /usr/local/bin/argus-tool-check && \
    echo "echo '=== ARGUS Sandbox Binary Profile ==='" >> /usr/local/bin/argus-tool-check && \
    echo "which afl-fuzz && echo 'AFL++: OK' || echo 'AFL++: MISSING'" >> /usr/local/bin/argus-tool-check && \
    echo "python3 -c 'import angr; print(\"angr: OK\")' 2>/dev/null || echo 'angr: MISSING'" >> /usr/local/bin/argus-tool-check && \
    echo "python3 -c 'import z3; print(\"z3: OK\")' 2>/dev/null || echo 'z3: MISSING'" >> /usr/local/bin/argus-tool-check && \
    echo "which r2 && echo 'radare2: OK' || echo 'radare2: MISSING'" >> /usr/local/bin/argus-tool-check && \
    echo "which binwalk && echo 'binwalk: OK' || echo 'binwalk: MISSING'" >> /usr/local/bin/argus-tool-check && \
    echo "which clang && echo 'libFuzzer: OK' || echo 'libFuzzer: MISSING'" >> /usr/local/bin/argus-tool-check && \
    echo "ls /opt/jazzer/target/jazzer-*.jar >/dev/null 2>&1 && echo 'Jazzer: OK' || echo 'Jazzer: MISSING'" >> /usr/local/bin/argus-tool-check && \
    echo "which nmap && echo 'nmap: OK' || echo 'nmap: MISSING'" >> /usr/local/bin/argus-tool-check && \
    echo "which sqlmap && echo 'sqlmap: OK' || echo 'sqlmap: MISSING'" >> /usr/local/bin/argus-tool-check && \
    chmod +x /usr/local/bin/argus-tool-check

# Final image selector
FROM ${SANDBOX_PROFILE} AS final

# Workspace mount point
RUN mkdir -p /workspace/artifacts /tmp/argus-sandbox && chown -R argus:argus /workspace /tmp/argus-sandbox

# Security hardening
RUN echo "argus ALL=(ALL) NOPASSWD: /usr/bin/argus-tool-check" > /etc/sudoers.d/argus

WORKDIR /workspace
USER argus

HEALTHCHECK CMD id argus || exit 1