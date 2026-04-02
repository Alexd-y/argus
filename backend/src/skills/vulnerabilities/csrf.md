---
name: csrf
description: CSRF discovery, token bypass, SameSite analysis
applicable_contexts: [web, api]
---

## CSRF Testing Methodology

### Discovery Checklist

1. Identify all state-changing requests (POST, PUT, DELETE, PATCH)
2. Check for CSRF token presence in forms and headers
3. Test token validation: remove token, use empty token, reuse old token, use another user's token
4. Check SameSite cookie attribute (None/Lax/Strict)
5. Verify Content-Type restrictions (JSON vs form-encoded)

### Token Bypass Techniques

- **Remove token entirely** — some backends only validate if present
- **Empty token** — `csrf_token=` may pass weak validation
- **Change HTTP method** — POST→GET may skip CSRF check
- **Change Content-Type** — `application/json` → `application/x-www-form-urlencoded`
- **Token fixation** — reuse a valid token across sessions
- **Predictable tokens** — check for timestamp or sequential patterns
- **Subdomain token sharing** — token from sub.target.com works on target.com

### Auto-Submit PoC

```html
<!-- Classic form auto-submit -->
<html>
<body onload="document.forms[0].submit()">
<form action="https://target.com/api/change-email" method="POST">
  <input type="hidden" name="email" value="attacker@evil.com">
</form>
</body>
</html>
```

### JSON CSRF (Content-Type bypass)

```html
<!-- JSON body via form — works if server accepts both -->
<form action="https://target.com/api/update" method="POST" enctype="text/plain">
  <input name='{"email":"attacker@evil.com","x":"' value='"}' type="hidden">
</form>

<!-- fetch-based CSRF (requires CORS misconfiguration) -->
<script>
fetch('https://target.com/api/update', {
  method: 'POST',
  credentials: 'include',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({email: 'attacker@evil.com'})
});
</script>
```

### SameSite Cookie Analysis

| SameSite | GET CSRF | POST CSRF | Notes |
|----------|----------|-----------|-------|
| None | Yes | Yes | Fully vulnerable (requires Secure flag) |
| Lax | GET only | No | Default in modern browsers; GET state-changes still vulnerable |
| Strict | No | No | Safe but breaks legitimate cross-site navigation |

### Login CSRF

Force victim to authenticate as attacker → victim performs actions in attacker's account → attacker later retrieves data.

### Validation Requirements

- Demonstrate state change via cross-origin request
- Show the auto-submit HTML PoC that triggers the action
- Document what state changed (email, password, settings, funds transfer)
- Test from different origin (file:// or attacker.com)
- Confirm no additional authentication step blocks the attack

### Business Impact

- Account takeover (email/password change)
- Unauthorized transactions (funds transfer, purchases)
- Privilege escalation (admin actions triggered by admin visiting attacker page)
- Data modification/deletion
