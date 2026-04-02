---
name: subdomain_enum
description: Subdomain enumeration and attack surface mapping
applicable_contexts: [recon, dns, infrastructure]
---

## Subdomain Enumeration

### Passive Enumeration

```bash
# subfinder — multi-source passive enumeration
subfinder -d TARGET_DOMAIN -all -o /workspace/subdomains.txt

# assetfinder
assetfinder --subs-only TARGET_DOMAIN >> /workspace/subdomains.txt

# amass (passive mode)
amass enum -passive -d TARGET_DOMAIN -o /workspace/amass.txt

# crt.sh — certificate transparency logs
curl -s "https://crt.sh/?q=%25.TARGET_DOMAIN&output=json" | \
  jq -r '.[].name_value' | sort -u >> /workspace/subdomains.txt

# Sort and deduplicate
sort -u /workspace/subdomains.txt -o /workspace/subdomains.txt
```

### Active Enumeration

```bash
# DNS brute-force with wordlist
ffuf -u "https://FUZZ.TARGET_DOMAIN" \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -mc 200,301,302,403 -o /workspace/ffuf-dns.json

# dnsgen — permutation-based
cat /workspace/subdomains.txt | dnsgen - | dnsx -silent -o /workspace/permuted.txt

# Virtual host discovery
ffuf -u "https://TARGET_IP" -H "Host: FUZZ.TARGET_DOMAIN" \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -fs DEFAULT_SIZE -mc 200
```

### HTTP Probing

```bash
# httpx — probe for live HTTP services
httpx -l /workspace/subdomains.txt -title -tech-detect \
  -status-code -json -o /workspace/httpx.json

# Filter interesting targets
cat /workspace/httpx.json | jq -r 'select(.status_code == 200) | .url'
```

### Port Scanning Discovered Subdomains

```bash
naabu -l /workspace/subdomains.txt -top-ports 1000 \
  -o /workspace/ports.txt -json
```

### Post-Enumeration Analysis

- Group subdomains by technology (httpx tech-detect)
- Identify dev/staging/internal environments
- Check for dangling CNAME records (subdomain takeover)
- Map IP ranges → identify shared infrastructure

### Validation Requirements

- Provide complete subdomain list with live/dead status
- Show technology stack per subdomain
- Identify high-value targets (admin panels, APIs, staging)
- Flag potential subdomain takeover candidates
