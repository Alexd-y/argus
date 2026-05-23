---
name: git-helper
description: Git operations helper. Use for commit message generation, branch management, conflict resolution, and git workflow guidance.
---

# Git Helper Skill

## Capabilities

### 1. Generate Commit Messages
Analyze staged changes and generate Conventional Commits message.

```bash
# Check staged changes
git diff --cached --stat
git diff --cached
```

**Conventional Commits format:**
```
<type>(<scope>): <subject>

<optional body>
```

**Types:**
- `feat` - New feature
- `fix` - Bug fix
- `refactor` - Code restructuring without behavior change
- `docs` - Documentation only
- `test` - Tests only
- `chore` - Tooling, configs, dependencies
- `perf` - Performance improvements

**Examples:**
```
feat(auth): add JWT token refresh
fix(api): handle null response in user endpoint
refactor(db): extract query builders to separate file
docs(readme): update installation steps
```

### 2. Branch Operations

**Create feature branch:**
```bash
git checkout main
git pull origin main
git checkout -b feature/description
```

**Clean up merged branches:**
```bash
git branch --merged | grep -v "main\|master" | xargs git branch -d
```

**Update branch with main:**
```bash
git fetch origin
git rebase origin/main
# OR
git merge origin/main
```

### 3. Conflict Resolution

When conflicts occur:
1. Identify conflicting files: `git status`
2. Open each file and look for conflict markers
3. Resolve by choosing correct code
4. Stage resolved files: `git add <file>`
5. Continue: `git rebase --continue` or `git commit`

### 4. Undo Operations

**Undo last commit (keep changes):**
```bash
git reset --soft HEAD~1
```

**Undo staged files:**
```bash
git restore --staged <file>
```

**Discard local changes:**
```bash
git restore <file>
```

**Undo pushed commit (creates new commit):**
```bash
git revert <commit-hash>
```

### 5. History Investigation

**Find when bug was introduced:**
```bash
git bisect start
git bisect bad          # current commit is bad
git bisect good <hash>  # known good commit
# Git will checkout middle commit
# Test and mark: git bisect good/bad
# Repeat until found
```

**Find who changed a line:**
```bash
git blame <file>
```

**Search commit messages:**
```bash
git log --grep="keyword"
```

**Search code changes:**
```bash
git log -p -S "function_name"
```

### 6. Stash Operations

**Save work temporarily:**
```bash
git stash push -m "description"
git stash list
git stash show stash@{0}
```

**Restore stashed work:**
```bash
git stash pop       # apply and remove
git stash apply     # apply and keep
git stash drop      # discard
```

### 7. Tags (Release Marking)

**Create and push tags:**
```bash
git tag -a v1.0.0 -m "Release 1.0.0"
git push origin v1.0.0
git push origin --tags  # push all tags
```

**List and delete tags:**
```bash
git tag -l
git tag -d v1.0.0                    # local
git push origin :refs/tags/v1.0.0    # remote
```

### 8. Cherry-pick

**Apply specific commit to current branch:**
```bash
git cherry-pick <commit-hash>
git cherry-pick <hash1> <hash2>  # multiple commits
```

## Commit Message Generation

When asked to generate commit message:

1. Run `git diff --cached --stat` to see changed files
2. Run `git diff --cached` to see actual changes
3. Determine type based on changes:
   - New file/feature added → `feat`
   - Bug fix in existing code → `fix`
   - Code restructuring without behavior change → `refactor`
   - Test-only changes → `test`
   - Documentation updates → `docs`
   - Dependencies, configs, tooling → `chore`
4. Identify scope (component/service/area affected)
5. Generate message following Conventional Commits format

## Common Scenarios

### "Create a PR"
```bash
git push -u origin HEAD
gh pr create --title "feat: description" --body "..."
# OR provide GitHub link
```

### "Squash my commits"
```bash
git rebase -i HEAD~<number>
# In editor: change 'pick' to 'squash' for commits to combine
```

**Warning:** Don't use interactive rebase on shared/public branches.

### "I committed to wrong branch"
```bash
# Save the commit
git log -1  # note the hash

# Go to correct branch
git checkout correct-branch
git cherry-pick <hash>

# Remove from wrong branch
git checkout wrong-branch
git reset --hard HEAD~1
```

### "Merge vs Rebase"
- **Merge**: Preserves history, creates merge commit
- **Rebase**: Linear history, rewrites commits

Use rebase for:
- Keeping feature branch up to date
- Cleaning up local commits

Use merge for:
- Integrating feature to main
- When branch is shared

## Safety Rules

- Never force push to `main`/`master`
- Never rebase public/shared branches
- Always backup before destructive operations
- Check `git status` before any operation

**Note:** Project may have git hooks in `.cursor/hooks/` for auto-linting/validation.
