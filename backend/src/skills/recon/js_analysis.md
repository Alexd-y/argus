---
name: js_analysis
description: JavaScript file analysis for secrets, endpoints, and vulnerabilities
applicable_contexts: [recon, web, api]
---

## JavaScript Analysis Methodology

### JS File Discovery

```bash
# katana — comprehensive crawling with JS parsing
katana -u TARGET_URL -d 5 -jc -jsl -o /workspace/katana.txt

# gospider — concurrent crawling
gospider -s TARGET_URL -d 3 -c 10 --js -o /workspace/gospider/

# Extract JS URLs from crawl output
grep -E '\.js(\?|$)' /workspace/katana.txt | sort -u > /workspace/js-files.txt

# waybackurls — historical JS files
echo TARGET_DOMAIN | waybackurls | grep -E '\.js(\?|$)' | sort -u >> /workspace/js-files.txt
```

### Endpoint Extraction

```bash
# linkfinder — extract endpoints from JS
python3 linkfinder.py -i TARGET_URL -o /workspace/endpoints.html

# Manual regex patterns for API endpoints
grep -oE '["'"'"'](/api/[a-zA-Z0-9_/{}.-]+)["'"'"']' /workspace/js/*.js
grep -oE '["'"'"'](https?://[a-zA-Z0-9._/-]+)["'"'"']' /workspace/js/*.js
grep -oE 'fetch\(["'"'"']([^"'"'"']+)' /workspace/js/*.js
grep -oE 'axios\.[a-z]+\(["'"'"']([^"'"'"']+)' /workspace/js/*.js
```

### Secret Detection in JS

```bash
# trufflehog — secret detection
trufflehog filesystem /workspace/js/ --json > /workspace/js-secrets.json

# semgrep — pattern matching
semgrep --config=p/secrets /workspace/js/ --json > /workspace/semgrep-js.json

# Manual regex for common secrets
grep -iE '(api[_-]?key|secret|token|password|auth|bearer)[\s]*[=:][\s]*["'"'"'][^"'"'"']+' \
  /workspace/js/*.js
```

### Patterns to Search For

| Pattern | Regex |
|---------|-------|
| API keys | `['"](AIza[a-zA-Z0-9_-]{35}|AKIA[A-Z0-9]{16})['"']` |
| AWS keys | `AKIA[A-Z0-9]{16}` |
| JWT tokens | `eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+` |
| Internal URLs | `https?://(?:localhost\|127\.0\.0\.1\|10\.\|192\.168\.)` |
| Hardcoded passwords | `(?:password\|passwd\|pwd)\s*[=:]\s*['"][^'"]+` |
| Debug flags | `debug\s*[=:]\s*true` |

### Source Map Analysis

```bash
# Check for source maps
curl -s TARGET_URL/main.js.map
curl -s TARGET_URL/app.js.map

# If found: extract original source
# npm install -g source-map-explorer
source-map-explorer /workspace/js/main.js.map
```

Source maps reveal original TypeScript/JSX source code, comments, and internal paths.

### Webpack Chunk Analysis

Look for `webpackChunkName` comments revealing module names.
Check `manifest.json` or `asset-manifest.json` for complete file list.

### Validation Requirements

- Document all API endpoints found with HTTP method
- List all secrets/tokens with redacted values
- Identify admin/internal endpoints not linked from UI
- Check if source maps are accessible in production
