---
name: simple-workflow
description: Simple implementation workflow - code, test, document. Use when user invokes /implement, wants to create code with automatic testing and documentation, or for simple single-purpose tasks that don't need planning.
---

# Simple Workflow Skill

**Purpose**: Run worker → test-writer → test-runner → documenter in sequence for simple tasks.

## How It Works

### Workflow: Code → Write Tests → (Auto-fix) → Lint + Test → Docs

```mermaid
flowchart LR
    Worker[Worker: writes code] --> TestWriter[Test-Writer: writes tests]
    TestWriter --> Hook[Hook: auto-fix formatting]
    Hook -.background.-> Test[Test-Runner: linter + tests]
    Test --> Docs[Documenter: creates documentation]
```

1. **Worker** creates the implementation code
2. **Test-Writer** writes comprehensive tests for the code (auto-detects stack)
3. **Hook** (automatic, background) auto-fixes formatting (prettier, eslint --fix)
4. **Test-Runner** runs linter checks + tests to verify it works
5. **Documenter** creates documentation in configured docs path

All agent steps visible in the same chat. Hook runs in background.

## Example Usage

User says: `/implement Create a Button component with onClick handler`

You should:

```markdown
I'll implement this in four steps: code, tests, verify, and document.

### Step 1: Implementation
[Call Task with subagent_type="worker"]

### Step 2: Test Creation
[After worker finishes, call Task with subagent_type="test-writer"]

### Step 3: Testing
[After tests are written, call Task with subagent_type="test-runner"]

### Step 4: Documentation
[After tests pass, call Task with subagent_type="documenter"]

### Summary
All steps completed!
- Worker created: [list files]
- Tests written: [list test files]
- Tests: [status]
- Documentation: [list docs]
```

## Important Rules

1. **Sequential execution**: Wait for each agent to complete before calling the next
2. **Always run all four steps**: worker → test-writer → test-runner → documenter
3. **Same chat**: All happens in current conversation, visible to user
4. **Pass context forward**: Tell each agent what the previous one did

## Code Pattern

```
Step 1: Call worker with task description
  → Wait for result
  → Extract files created

Step 2: Call test-writer
  → "Write tests for: [list from step 1]"
  → Wait for result
  → Extract test files created

Step 3: Call test-runner
  → "Run tests for files: [list from steps 1-2]"
  → Wait for result
  → Check if tests passed

Step 4: Call documenter
  → "Document the implementation: [details from step 1]"
  → Wait for result
  → Compile final summary
```

## Trigger Phrases

- `/implement [task]`
- "Implement [X]"
- "Create [Y] with tests and docs"

## When NOT to Use

- **Complex tasks**: Use `/orchestrate` instead (includes planning)
- **Multiple subtasks**: Use `/orchestrate` for task breakdown
- **Need review/refactor**: Use full cycle workflow

## Key Difference from Full Cycle

| Simple Workflow | Full Cycle (/orchestrate) |
|----------------|---------------------------|
| No planning | Starts with planner |
| Single pass | Multiple tasks from plan |
| No review | Includes code review |
| No debugger loops | Auto-fixes with debugger |
| Quick and simple | Comprehensive and thorough |

## Benefits

- ✅ Fast for simple tasks
- ✅ Always writes tests (test-writer)
- ✅ Always verifies tests pass (test-runner)
- ✅ Always creates documentation
- ✅ Everything visible in one chat
- ✅ No planning overhead

## Example Tasks

Good for `/implement`:
- Create a utility function
- Add a React component
- Implement an API endpoint
- Add a new feature to existing file

Not good for `/implement` (use `/orchestrate`):
- Build entire authentication system
- Refactor multiple modules
- Migrate database schema
- Implement complex feature with multiple parts
