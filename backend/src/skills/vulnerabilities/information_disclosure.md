---
name: information_disclosure
description: Information disclosure and sensitive data exposure testing
applicable_contexts: [web, api, infrastructure]
---

## Information Disclosure Testing

### Error Message Analysis

- Trigger errors with malformed input, invalid types, boundary values
- Check: stack traces, framework versions, database queries, file paths
- API errors: check for internal field names, table names, query structures
- Debug mode: look for `DEBUG=True`, `FLASK_DEBUG`, `NODE_ENV=development`

### Common Exposed Endpoints

```
/.env
/.git/HEAD
/.git/config
/.svn/entries
/.DS_Store
/robots.txt
/sitemap.xml
/.well-known/
/server-status (Apache)
/server-info (Apache)
/elmah.axd (.NET)
/phpinfo.php
/info.php
/debug/pprof/ (Go)
/actuator/ (Spring Boot)
/actuator/env
/actuator/health
/actuator/beans
/swagger-ui.html
/api/swagger.json
/openapi.json
/graphql (introspection)
/__debug__/ (Django Debug Toolbar)
/trace (Spring Boot)
```

### Source Control Exposure

```bash
# .git directory disclosure
curl -s https://target.com/.git/HEAD
# If accessible: use git-dumper
git-dumper https://target.com/.git/ /workspace/git-dump/

# SVN
curl -s https://target.com/.svn/entries

# Backup files
TARGET_URL/index.php.bak
TARGET_URL/config.py.old
TARGET_URL/database.sql
TARGET_URL/backup.zip
```

### API Documentation Leak

```bash
# Swagger/OpenAPI
curl https://target.com/swagger.json
curl https://target.com/api-docs
curl https://target.com/openapi.yaml

# GraphQL introspection
curl -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ __schema { types { name fields { name type { name } } } } }"}'
```

### HTTP Header Analysis

Check response headers for:
- `Server: Apache/2.4.49` → version disclosure
- `X-Powered-By: PHP/7.4.3` → framework version
- `X-AspNet-Version: 4.0.30319` → .NET version
- Missing security headers: `X-Frame-Options`, `X-Content-Type-Options`, `Strict-Transport-Security`

### Directory Listing

```bash
# Check common directories
ffuf -u "https://target.com/FUZZ/" \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -mc 200,403 -ac -o /workspace/dirlist.json
```

### JavaScript Source Analysis

```bash
# Extract secrets from JS files
katana -u TARGET_URL -d 3 -jc | grep -E '\.js$' | while read url; do
  curl -s "$url" | grep -iE '(api[_-]?key|secret|token|password|auth).*[=:]'
done
```

### Validation Requirements

- Show specific sensitive data exposed (version, credentials, internal paths)
- Document how the information aids further attacks
- Rate severity based on what's disclosed (version info = Low, credentials = Critical)
- Check if information is accessible without authentication

### Business Impact

- Attack surface mapping (versions → known CVE exploitation)
- Credential theft (API keys, database passwords in config)
- Source code theft (intellectual property, business logic)
- Compliance violation (debug endpoints in production)
