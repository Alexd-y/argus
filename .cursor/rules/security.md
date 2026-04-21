---
description: Critical security rules that prevent disasters
globs: ["**/*.ts", "**/*.tsx", "**/*.js", "**/*.jsx", "**/*.py", "**/*.go"]
---

# Security Rules (Critical)

## NEVER

- ❌ Commit secrets/API keys/tokens to git
- ❌ Use `eval()` or `Function()` on user input
- ❌ Store passwords in plain text (use bcrypt/argon2)
- ❌ Concatenate SQL strings (use parameterized queries)
- ❌ Trust client-side validation alone

## ALWAYS

- ✅ Validate all user input on server
- ✅ Use HTTPS in production
- ✅ Add `.env` to `.gitignore`

## When to Read Security Skill

**MUST read `.cursor/skills/security-guidelines/SKILL.md` when:**

- Implementing authentication/authorization
- Creating API endpoints
- Handling user input or file uploads
- Working with sensitive data (passwords, PII, payment info, tokens)
- Using external APIs
- Implementing sessions or cookies
