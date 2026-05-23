---
description: Conventional Commits format for consistent commit messages
globs: []
---

# Commit Message Format

Use [Conventional Commits](https://www.conventionalcommits.org/) format.

## Structure

```
<type>(<scope>): <subject>

[optional body]
```

## Types

| Type | Description | Example |
|------|-------------|---------|
| `feat` | New feature | `feat(auth): add OAuth login` |
| `fix` | Bug fix | `fix(api): handle null response` |
| `docs` | Documentation | `docs: update API readme` |
| `refactor` | Code change (no feature/fix) | `refactor: extract validation` |
| `test` | Adding tests | `test: add auth unit tests` |
| `chore` | Maintenance | `chore: update dependencies` |
| `perf` | Performance improvement | `perf: cache user queries` |
| `style` | Formatting only | `style: fix indentation` |

## Rules

### Subject

- Lowercase, no period at end
- Imperative mood: "add" not "added" or "adds"
- Max 50 characters
- Complete the sentence: "This commit will..."

### Scope (optional)

- Feature area: `auth`, `api`, `ui`, `db`
- Component: `button`, `header`, `user-service`

## Examples

```bash
feat(cart): add quantity selector
fix(checkout): prevent double submission
refactor(db): extract query builders
docs(readme): update installation steps
```

## When to Use Git-Helper Skill

**Use `.cursor/skills/git-helper/SKILL.md` when:**

- User asks to generate commit message
- User asks to commit changes
- Need to analyze staged changes and create appropriate message
- Determining correct commit type based on code changes
