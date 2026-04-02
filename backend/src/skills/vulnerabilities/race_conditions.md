---
name: race_conditions
description: Race condition and TOCTOU vulnerability testing
applicable_contexts: [web, api, backend]
---

## Race Condition Testing

### TOCTOU (Time-of-Check-to-Time-of-Use)

Attack window exists between the check and the action:
1. Check balance → sufficient
2. Initiate transfer → deduct
3. Concurrent transfer → deduct again (balance goes negative)

### HTTP Request Racing

```python
import asyncio
import aiohttp

async def spray_requests(url: str, method: str, payload: dict,
                         headers: dict, n_concurrent: int = 50) -> dict:
    """Send N simultaneous requests to trigger race condition."""
    async with aiohttp.ClientSession() as session:
        req = getattr(session, method.lower())
        tasks = [req(url, json=payload, headers=headers) for _ in range(n_concurrent)]
        responses = await asyncio.gather(*tasks, return_exceptions=True)

        results = {"success": 0, "error": 0, "bodies": []}
        for r in responses:
            if isinstance(r, Exception):
                results["error"] += 1
            elif r.status in (200, 201):
                results["success"] += 1
                results["bodies"].append(await r.text())
            else:
                results["error"] += 1
        return results
```

### Common Race Condition Targets

| Target | Expected | Exploited |
|--------|----------|-----------|
| Coupon redemption | 1 use | N uses |
| Like/vote | 1 per user | N per user |
| Funds transfer | Deduct once | Deduct once, credit N times |
| Inventory purchase | 1 unit left → 1 buyer | 1 unit left → N buyers |
| Account creation | 1 account per email | N accounts per email |
| File upload quota | 5 files max | 50 files |

### Database-Level Race Conditions

- Missing `SELECT ... FOR UPDATE` → concurrent reads get stale balance
- Missing unique constraints → duplicate records created
- Non-atomic read-modify-write patterns
- Optimistic locking without retry logic

### File System Race Conditions

- Symlink attacks: create symlink between check and use
- Temp file race: predictable temp filenames allow substitution
- Lock file bypass: delete lock file between check and action

### Detection Methodology

1. Identify endpoints that perform check-then-act
2. Send 20-100 concurrent identical requests
3. Count successful responses — more than expected = race condition
4. Verify side effects: check database state, balance, counters
5. Increase concurrency if initial test inconclusive

### Mitigation Verification

Test if mitigations are effective:
- Database locks (FOR UPDATE, advisory locks)
- Distributed locks (Redis SETNX)
- Idempotency keys
- Optimistic concurrency (version fields)

### Validation Requirements

- Show N successful operations where only 1 should be allowed
- Document database state before and after (e.g., balance, counters)
- Provide reproducible concurrent request script
- Calculate financial impact of unlimited exploitation

### Business Impact

- Financial fraud (double-spend, unlimited credits)
- Data integrity corruption
- Denial of service (resource exhaustion from duplicated operations)
- Privilege escalation (race in permission checks)
