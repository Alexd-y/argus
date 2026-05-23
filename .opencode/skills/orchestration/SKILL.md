---
name: orchestration
description: Full implementation cycle with planning, testing, review, and auto-fixing. Use when user invokes /orchestrate, for complex tasks requiring planning and breakdown, multi-step implementations, or tasks that need thorough testing and review.
---

# Orchestration Workflow Skill

**Purpose**: Orchestrate complete development cycle - from planning to documentation with automatic error fixing.

## Workflow Architecture

```mermaid
flowchart TD
    Planner[Planner: creates plan with tasks] --> Loop{Any tasks?}
    Loop -->|Yes| Worker[Worker: implements task]
    Worker --> TestWriter[Test-Writer: writes tests]
    TestWriter --> TestRunner[Test-Runner: runs tests & verifies]
    TestRunner -->|Tests fail or incomplete| Debugger1[Debugger: fixes bugs]
    Debugger1 --> TestRunner
    TestRunner -->|Tests pass & verified| Reviewer[Reviewer: checks quality]
    Reviewer -->|Issues found| Debugger2[Debugger: improves code]
    Debugger2 --> Reviewer
    Reviewer -->|Quality OK| NextTask[Move to next task]
    NextTask --> Loop
    Loop -->|No tasks| Documenter[Documenter: creates documentation]
    Documenter --> Done[Completed]
```

## How It Works

### Phase 1: Planning

1. Call **planner** with the full task description
2. Planner creates:
   - Workspace: `.cursor/workspace/active/orch-{id}/`
   - Plan file: `workspace/plan.md` OR uses user's file
   - Metadata: `progress.json`, `tasks.json`, `links.json`
3. Planner returns orchestration ID

### Phase 2: Load Orchestration

**Read configuration:**
```javascript
config = readJSON(".cursor/config.json") || defaultConfig
workspacePath = config.workspace.path
```

**Load orchestration state:**
```javascript
orchestrationId = userInput || findLatestActive()
workspaceDir = `${workspacePath}/active/${orchestrationId}`

progress = readJSON(`${workspaceDir}/progress.json`)
tasksState = readJSON(`${workspaceDir}/tasks.json`)
links = readJSON(`${workspaceDir}/links.json`)

// Read plan from documentation
planContent = read(links.plan)
taskIds = extractTaskIds(planContent)
```

### Phase 3: Task Loop

**CRITICAL**: Iterate through ALL tasks.

For EACH task ID from plan:

**Before starting task:**
```javascript
// Skip if already completed
if (tasksState[taskId]?.status === "completed") continue

// Update task status: pending → in-progress
tasksState[taskId] = {
  id: taskId,
  status: "in-progress",
  startedAt: now()
}
write(`${workspaceDir}/tasks.json`, tasksState)

// Update plan file
updateTaskInPlan(links.plan, taskId, "🔄 In Progress")

// Update orchestration progress
updateJSON(`${workspaceDir}/progress.json`, {
  currentTask: taskId,
  lastUpdated: now()
})
```

**During task:**

#### Step 1: Implementation
- Call **worker** with current subtask
- Wait for completion
- Extract what was created
- (Hook auto-fixes formatting in background)

#### Step 2: Test Creation
- Call **test-writer** to write comprehensive tests for the implemented code
- Test-writer auto-detects stack and follows project test conventions
- Wait for completion
- Extract test files created

#### Step 3: Linting + Testing + Verification
- Call **test-runner** to verify code quality, functionality, and completeness
- Test-runner checks:
  - Linter (code quality, style issues)
  - Tests (functionality verification)
  - Verification (acceptance criteria met, implementation complete)
- **If tests fail or verification incomplete**:
  - Call **debugger** to fix issues or complete missing parts
  - Re-run **test-runner**
  - Max 3 retry attempts

#### Step 4: Code Review
- Call **reviewer** to check code quality
- **If reviewer finds problems**:
  - Call **debugger** to improve code
  - Re-run **reviewer**
  - Max 3 retry attempts

#### Step 5: Update Task Status

**After test-runner verifies and reviewer approves:**

```javascript
// Update task status: in-progress → completed
tasksState[taskId] = {
  ...tasksState[taskId],
  status: "completed",
  completedAt: now(),
  filesChanged: result.filesChanged,
  testsRun: testResult.total,
  testsPassed: testResult.passed
}
write(`${workspaceDir}/tasks.json`, tasksState)

// Update plan file
updateTaskInPlan(links.plan, taskId, "✅ Completed")

// Update orchestration progress
updateJSON(`${workspaceDir}/progress.json`, {
  tasksCompleted: progress.tasksCompleted + 1,
  currentTask: null,
  lastUpdated: now()
})
```

### Phase 4: Finalization

**After all tasks complete:**

```javascript
// Update orchestration status
updateJSON(`${workspaceDir}/progress.json`, {
  status: "documenting",
  lastUpdated: now()
})

// Call documenter to create final report
reportFile = callDocumenter({
  orchestrationId: progress.id,
  planFile: links.plan,
  tasksState: tasksState
})

// Save report link
updateJSON(`${workspaceDir}/links.json`, {
  report: reportFile
})

// Mark orchestration as completed
updateJSON(`${workspaceDir}/progress.json`, {
  status: "completed",
  completedAt: now(),
  reportFile: reportFile
})

// Archive workspace
move(
  `${workspacePath}/active/${orchestrationId}`,
  `${workspacePath}/completed/${orchestrationId}`
)
```

## Important Rules

### Sequential Execution
- Wait for each agent to complete before calling next
- Pass context from previous agent to next
- Track state across the entire workflow

### Error Handling
- Automatic retry with debugger on failures
- **Max 3 retry attempts per stage** (test/review)
- If max attempts reached, report to user and ask for guidance

### Task Limits
- **Recommended max: 10 tasks per orchestration cycle**
- If Planner creates more than 10 tasks:
  - Complete first 10 tasks
  - Report progress to user
  - Ask if should continue with remaining tasks
- **Max task execution time: check context window usage**
- If approaching context limit, save progress and ask user

### Task Tracking
- Keep track of completed vs pending tasks
- Show progress after each task completion (e.g., "Task 3/7")
- Show estimated remaining tasks
- Final summary lists all accomplished work

### Context Management
- Each agent gets context about what previous agents did
- Debugger gets specific error details to fix
- Documenter gets full picture of all changes

## Example Usage

User says: `/orchestrate Build user authentication with email/password and OAuth`

Your response:

```markdown
I'll orchestrate the full development cycle for this complex task.

**Task**: Build user authentication with email/password and OAuth

### Phase 1: Planning
[Call planner to break down into subtasks]

[Wait for planner result - extract tasks]

**Plan created:**
1. Database schema for users
2. Email/password authentication
3. OAuth integration (Google, GitHub)
4. Session management
5. Protected routes middleware

### Phase 2: Implementation Cycle

**Task 1/5: Database schema for users**
- [Call worker to implement]
- [Call test-writer to create tests]
- [Call test-runner for tests & verification]
- [If failed: call debugger and retry]
- [Call reviewer]
- [If issues: call debugger and retry]
- ✅ Task 1 complete

**Task 2/5: Email/password authentication**
...

[Continue for all tasks]

### Phase 3: Documentation
[Call documenter with all changes]

### Summary
✅ All 5 tasks completed
✅ Tests passing
✅ Code reviewed
✅ Documentation created

Files changed: [list]
Documentation: [list]
```

## Retry Logic

### Test/Verification Failures
```
test-runner → FAIL → debugger → test-runner
  ↓ (max 3 attempts)
  ↓
  If still failing: report to user
```

### Review Issues
```
review → PROBLEMS → debugger → review
  ↓ (max 3 attempts)
  ↓
  If still issues: report to user
```

## Trigger Phrases

- `/orchestrate [task]`
- "Orchestrate [X]"
- "Full implementation of [Y]"

## When to Use This vs Simple Workflow

| Use `/implement` | Use `/orchestrate` |
|-----------------|---------------------|
| Single component | Full feature |
| One file change | Multiple modules |
| No planning needed | Needs breakdown |
| Quick task | Complex project |

## Key Features

1. **Automatic Planning**: Breaks complex tasks into manageable pieces
2. **Test Writing**: Test-writer creates tests for every implemented task (auto-detects stack)
3. **Auto-fixing**: Debugger automatically fixes test/review failures
4. **Quality Gates**: Every task goes through test-writer → test-runner (with verification) → reviewer
5. **Progress Tracking**: See which tasks are done, which are pending
6. **Comprehensive Docs**: Full documentation after all work complete

## Example Tasks

Good for `/orchestrate`:
- Build authentication system
- Create admin dashboard with CRUD
- Implement payment integration
- Migrate database schema
- Refactor major module with tests

Bad for `/orchestrate` (use `/implement`):
- Add one function
- Fix simple bug
- Create single component
- Update one file

## Success Criteria

Workflow is complete when:
- ✅ All planned tasks implemented
- ✅ All tests passing
- ✅ Code review approved
- ✅ All acceptance criteria verified (by test-runner)
- ✅ Documentation created

## Notes

- This skill replaces hook-based orchestration
- All execution happens in same chat, visible to user
- User can intervene at any point if needed
- Debugger is only called when there are actual errors/issues
- Max 3 retry attempts prevents infinite loops
