---
name: business_logic
description: Business logic vulnerability testing — pricing, workflow, privilege
applicable_contexts: [web, api, e-commerce]
---

## Business Logic Testing

### Price/Quantity Manipulation

- Negative quantities: `{"qty": -5}` → refund issued?
- Zero price: `{"price": 0}` → free items?
- Floating point: `0.001 * 1000 ≠ 1.00` in some implementations
- Currency parameter: change `currency=USD` → `currency=VND` (lower denomination)
- Discount stacking: apply multiple coupons, combine employee + promo discount
- Integer overflow: quantity `2147483647` → wrap to negative?
- Price in client request: if price sent from frontend, modify it

### Race Conditions

```python
import asyncio
import aiohttp

async def race_test(url: str, payload: dict, n: int = 20):
    async with aiohttp.ClientSession() as session:
        tasks = [
            session.post(url, json=payload, headers={"Authorization": "Bearer TOKEN"})
            for _ in range(n)
        ]
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        successes = sum(1 for r in responses if hasattr(r, 'status') and r.status == 200)
        return successes > 1  # multiple successes = race condition
```

Test targets: coupon redemption, funds transfer, vote/like, stock purchase, limited-time offers.

### Workflow Bypass

- Skip steps: POST to step 3 directly without completing step 1/2
- Replay completed steps: re-submit an already processed order
- Modify workflow state: change `status=pending` → `status=approved`
- Access completed order edit: modify order after payment
- Double-submit: submit payment form twice quickly

### Privilege Escalation via Parameter

```
# Hidden parameter injection
POST /api/user/update
{"name": "John", "role": "admin"}       # mass assignment
{"name": "John", "isAdmin": true}        # boolean flag
{"name": "John", "subscription": "pro"}  # tier escalation

# HTTP verb tampering
DELETE /api/user/123   # may lack auth check on DELETE
PATCH /api/user/123    # different auth than PUT
```

### Multi-Step Logic Flaws

- Coupon abuse: use same code multiple times across sessions
- Referral abuse: self-referral with email aliases
- Trial abuse: re-register with same details to get new trial
- Feature gate bypass: access premium features by calling API directly
- Export limits: bypass pagination limits via direct API query

### Validation Requirements

- Demonstrate exact business impact: money gained, data accessed, actions unauthorized
- Show reproducible steps (not one-off)
- Calculate maximum potential damage (e.g., unlimited free items, unlimited funds transfer)
- Document: normal flow vs. exploited flow comparison

### Business Impact

- Direct financial loss (pricing manipulation, unauthorized transactions)
- Fraud at scale (automated coupon/referral abuse)
- Reputation damage (privilege escalation, unauthorized content)
- Regulatory fines (unauthorized data access, financial manipulation)
