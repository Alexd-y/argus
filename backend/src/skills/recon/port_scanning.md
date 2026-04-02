---
name: port_scanning
description: Port scanning, service enumeration, version detection
applicable_contexts: [recon, infrastructure, network]
---

## Port Scanning Methodology

### Fast Discovery

```bash
# naabu — fast port scanner
naabu -host TARGET_IP -top-ports 1000 -o /workspace/ports.txt -json

# naabu — full port scan
naabu -host TARGET_IP -p - -rate 5000 -o /workspace/full-ports.txt
```

### Detailed Service Scanning

```bash
# nmap — service version detection
nmap -sV -sC -p PORTS TARGET_IP -oA /workspace/nmap-svc

# nmap — OS detection + scripts
nmap -A -T4 TARGET_IP -oA /workspace/nmap-full

# nmap — UDP scan (top 20 ports)
nmap -sU --top-ports 20 TARGET_IP -oA /workspace/nmap-udp

# nmap — vulnerability scripts
nmap --script=vuln -p PORTS TARGET_IP -oA /workspace/nmap-vuln
```

### NSE Scripts for Specific Services

```bash
# HTTP
nmap --script=http-enum,http-title,http-methods -p 80,443 TARGET_IP

# SMB
nmap --script=smb-enum-shares,smb-vuln-* -p 445 TARGET_IP

# SSL/TLS
nmap --script=ssl-enum-ciphers,ssl-cert -p 443 TARGET_IP

# DNS
nmap --script=dns-zone-transfer -p 53 TARGET_IP
```

### Service-Specific Enumeration

| Port | Service | Enumeration |
|------|---------|-------------|
| 21 | FTP | anonymous login, version exploits |
| 22 | SSH | version, auth methods, weak keys |
| 25 | SMTP | open relay, user enumeration |
| 53 | DNS | zone transfer, cache poisoning |
| 80/443 | HTTP(S) | web vulns, directory listing |
| 445 | SMB | share enumeration, EternalBlue |
| 3306 | MySQL | version, default creds |
| 5432 | PostgreSQL | version, default creds |
| 6379 | Redis | unauthenticated access |
| 8080 | HTTP Proxy | misconfig, open proxy |
| 9200 | Elasticsearch | unauthenticated access |
| 27017 | MongoDB | unauthenticated access |

### Output Analysis

- Cross-reference discovered services with known CVEs
- Identify services with default/no authentication
- Map internal services exposed externally
- Check SSL/TLS configuration (weak ciphers, expired certs)
