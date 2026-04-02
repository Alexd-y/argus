---
name: idor
description: Insecure Direct Object Reference discovery and exploitation
applicable_contexts: [web, api]
---

## IDOR Testing Methodology

### Discovery Phase

1. Map all endpoints that reference object identifiers (IDs, UUIDs, slugs)
2. Create two test accounts (UserA and UserB) for horizontal testing
3. Identify ID patterns: sequential integers, UUIDs, hashes, encoded values

### Parameter Locations to Test

- URL path: `/api/users/123/profile`, `/api/orders/456`
- Query string: `?user_id=123`, `?doc=report_789.pdf`
- Request body: `{"userId": 123, "orderId": 456}`
- Headers: `X-User-Id: 123`
- Cookies: `user=base64(id:123)`

### Horizontal Privilege Escalation

Access another user's resources at the same privilege level:
```
# As UserA (id=100), try accessing UserB (id=101)
GET /api/users/101/profile         # view UserB's profile
GET /api/users/101/orders          # view UserB's orders
PUT /api/users/101/email           # change UserB's email
DELETE /api/users/101/documents/5  # delete UserB's documents
```

### Vertical Privilege Escalation

Access admin-level resources as regular user:
```
GET /api/admin/users               # list all users
PUT /api/users/100/role            # body: {"role": "admin"}
GET /api/internal/metrics          # internal dashboard
POST /api/admin/impersonate/101    # impersonate another user
```

### ID Enumeration Techniques

```bash
# ffuf — sequential ID brute-force
ffuf -u "https://target.com/api/users/FUZZ/profile" \
  -w <(seq 1 10000) -H "Authorization: Bearer USER_TOKEN" \
  -mc 200 -o /workspace/idor-enum.json

# ffuf — UUID brute-force (if leaked elsewhere)
ffuf -u "https://target.com/api/docs/FUZZ" \
  -w /workspace/collected_uuids.txt -mc 200

# Burp Intruder — replace ID in request, iterate range
```

### Encoded/Hashed ID Bypass

- Base64 encoded IDs: decode, modify, re-encode
- MD5/SHA hashed IDs: if input is predictable (email, username), compute hash
- JWT-embedded IDs: modify claims (see authentication_jwt skill)
- Encrypted IDs: check for ECB mode (swap blocks)

### API-Specific IDOR

- GraphQL: query `user(id: "OTHER_ID") { email, address }`
- REST batch endpoints: `POST /api/batch` with array of IDs including unauthorized ones
- File download: `/api/download?file=../../other_user/report.pdf` (combine with path traversal)
- Export endpoints: `/api/export?userId=OTHER_ID`

### Validation Requirements

- Access resource belonging to a different user/tenant
- Show HTTP request with manipulated ID and successful response with unauthorized data
- Demonstrate both read (information disclosure) and write (data modification) if possible
- Document scope: how many records accessible via enumeration
- Test across different API versions if available

### Business Impact

- Mass data breach via enumeration (all user records)
- Financial fraud (accessing/modifying other users' transactions)
- Privacy violation (PII exposure — GDPR/CCPA implications)
- Account takeover when combined with other vulns
