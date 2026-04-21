---
description: Git workflow standards for branch naming, commits, and PRs
globs: []
---

# Git Workflow

## Branch Naming

```
<type>/<short-description>
```

### Types

| Type | Purpose | Example |
|------|---------|---------|
| `feature/` | New functionality | `feature/user-auth` |
| `fix/` | Bug fixes | `fix/login-redirect` |
| `hotfix/` | Urgent production fix | `hotfix/payment-crash` |
| `refactor/` | Code improvement | `refactor/api-layer` |
| `docs/` | Documentation | `docs/api-readme` |
| `test/` | Test additions | `test/auth-coverage` |
| `chore/` | Maintenance | `chore/update-deps` |

### Rules

- Lowercase only
- Hyphens for spaces
- Short but descriptive
- Include ticket number if applicable: `feature/AUTH-123-oauth`

## Branch Strategy

- `main` — Production-ready code
- `develop` — Integration branch (optional)
- Feature branches merge to main via PR

## Commit Practices

### Atomic Commits

- One logical change per commit
- Compilable at every commit
- Tests pass at every commit

### Before Committing

1. Run tests
2. Run linter
3. Review changes: `git diff`

## Pull Request Guidelines

### Before Creating PR

- [ ] Tests pass
- [ ] Code reviewed by you
- [ ] Branch up to date with main
- [ ] No merge conflicts

### PR Size

- **Ideal**: < 400 lines
- **Max**: 1000 lines
- Split larger changes into multiple PRs

## Don't

- ❌ Force push to `main`
- ❌ Commit secrets or credentials
- ❌ Commit large binary files
- ❌ Create huge PRs
- ❌ Leave WIP commits in PR
- ❌ Merge without review

## Do

- ✅ Write meaningful commit messages
- ✅ Keep PRs focused
- ✅ Update branch before merge
- ✅ Delete branch after merge

## When to Use Git-Helper Skill

**Use `.cursor/skills/git-helper/SKILL.md` when:**

- Generating commit messages from staged changes
- Resolving merge conflicts
- Need specific git commands (cherry-pick, stash, bisect, rebase)
- Creating or managing branches
- Undoing operations (reset, revert, restore)
- Investigating history (blame, log, bisect)
