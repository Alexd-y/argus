# ARGUS Sandbox — Kali-based container for pentest tool execution

FROM kalilinux/kali-rolling:latest

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    nmap \
    dnsutils \
    whois \
    curl \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash argus

USER argus
WORKDIR /home/argus

CMD ["tail", "-f", "/dev/null"]
