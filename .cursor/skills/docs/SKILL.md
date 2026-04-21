---
name: docs
description: Skill for understanding project documentation structure. Apply when user asks about documentation or needs to see how docs are organized.
disable-model-invocation: false
---

# Documentation Structure Skill

## Configuration-Based Documentation

**IMPORTANT:** Documentation paths are configured in `.cursor/config.json`. Never hardcode `ai_docs/` or any specific paths.

### Reading Configuration

Always read documentation paths from config:

```javascript
config = readJSON(".cursor/config.json")
paths = config.documentation.paths

// paths.root = "ai_docs" (or user's custom path)
// paths.plans = "ai_docs/develop/plans"
// paths.reports = "ai_docs/develop/reports"
// etc.
```

## Default Documentation Structure

This is the default structure when using `ai_docs/` as root (users can customize all paths):

```
{configured-root}/               # From config: paths.root
├── design/                      # From config: paths.design
├── develop/
│   ├── api/                     # From config: paths.api
│   ├── architecture/            # From config: paths.architecture
│   ├── components/              # From config: paths.components
│   ├── features/                # From config: paths.features
│   ├── plans/                   # From config: paths.plans
│   ├── reports/                 # From config: paths.reports
│   └── issues/                  # From config: paths.issues
└── changelog/                   # From config: paths.changelog
```

## Directory Purpose

**plans/** - High-level: What to build (created by planner)
**reports/** - Summary: What was built (created by documenter)
**issues/** - Tech debt: What to fix later (created by any agent)
**features/** - Feature descriptions and implementation details
**api/** - API endpoints documentation
**components/** - Component documentation
**architecture/** - Architecture decisions and patterns
**design/** - UI/UX designs, style guides
**changelog/** - Version history

## When to Update Documentation

### Automatically (when orchestration completes)
- After feature implementation
- After bug fixes
- After architecture decisions

### Manually (when user requests)
- `/documenter update docs for [feature]`
- User asks "update documentation"
- User asks "document this change"

## How to Read Documentation

Documentation may be excluded from context by default (check .cursorignore).

To include specific docs (replace `{root}` with your configured path):
```
@{root}/develop/features/authentication.md
@{root}/develop/api/endpoints.md
```

To see all documentation:
```
@{root}
```

## Commands Available

- `/documenter` - Update documentation for recent changes
- `@{root}` - Include documentation in context (use your configured root path)

## Documentation Guidelines

1. **One topic per file** - Don't mix concerns
2. **Always date updates** - Include timestamps
3. **Link to code** - Reference actual files
4. **Keep it current** - Archive old/completed items
5. **Use markdown** - Standard formatting
6. **Cross-reference** - Link related docs

## File Naming

- Features: `feature-name.md` (kebab-case)
- Components: `ComponentName.md` (PascalCase)
- Issues: `issue-123.md` or descriptive name
- Tasks: `task-description.md`

## Useful Prompts

- "Document the authentication feature I just implemented"
- "Update API documentation with new endpoints"
- "Show me all pending tasks in documentation"
- "Archive completed issues in documentation"
- "Create ADR for switching to server components"

## Configuration Example

Example `.cursor/config.json`:

```json
{
  "documentation": {
    "paths": {
      "root": "ai_docs",
      "plans": "ai_docs/develop/plans",
      "reports": "ai_docs/develop/reports",
      "issues": "ai_docs/develop/issues",
      "architecture": "ai_docs/develop/architecture",
      "features": "ai_docs/develop/features",
      "api": "ai_docs/develop/api",
      "components": "ai_docs/develop/components",
      "design": "ai_docs/design",
      "changelog": "ai_docs/changelog"
    },
    "enabled": {
      "plans": true,
      "reports": true,
      "issues": true,
      "architecture": true,
      "features": true,
      "api": true,
      "components": true,
      "design": true,
      "changelog": true
    }
  }
}
```

Users can customize all paths to match their project structure (e.g., `docs/`, `documentation/`, etc.)
