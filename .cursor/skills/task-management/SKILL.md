---
name: task-management
description: Task tracking and plan management. Used by planner to create plans and persist tasks, by orchestrator to read tasks and update progress, by documenter to create completion reports, and by any agent to log non-critical issues.
---

# Task Management Skill

**Purpose**: Manage implementation plans, detailed tasks, completion reports, and known issues using a hybrid workspace + documentation approach.

---

## Architecture

### Two-Tier System

**1. Workspace (Temporary) - `.cursor/workspace/`**
- Orchestration metadata and state
- Task statuses and progress tracking
- Automatically cleaned up after completion

**2. Documentation (Permanent) - Configurable paths**
- Plans, reports, architecture decisions
- Final documentation for features
- Persisted in user's documentation system

---

## Configuration

**Read configuration from:** `.cursor/config.json`

```json
{
  "workspace": {
    "path": ".cursor/workspace",
    "cleanup": {
      "autoCleanCompleted": true,
      "cleanupAfterDays": 7
    }
  },
  "documentation": {
    "paths": {
      "root": "docs",
      "reports": "docs/reports",
      "issues": "docs/issues",
      "architecture": "docs/architecture",
      "plans": "docs/plans"
    }
  }
}
```

**Note:** All paths are configurable. Example uses `docs/` but could be `ai_docs/`, `documentation/`, etc.

**Default values if config not found:**
- workspace: `.cursor/workspace`
- root: `ai_docs`
- reports: `ai_docs/develop/reports`
- issues: `ai_docs/develop/issues`
- architecture: `ai_docs/develop/architecture`
- plans: `ai_docs/develop/plans`

---

## Directory Structure

### Workspace (Temporary)

```
.cursor/workspace/
├── active/                          # Running orchestrations
│   └── orch-2026-02-10-15-30-auth/
│       ├── progress.json            # Status, timestamps, counters
│       ├── tasks.json               # Task statuses
│       └── links.json               # Links to docs files
├── completed/                       # Auto-cleanup after N days
└── failed/                          # Can be resumed
```

### Documentation (Permanent)

```
{configured-path}/                   # From config.json
├── plans/                           # High-level plans
│   └── 2026-02-10-auth-system.md
├── reports/                         # Completion reports
│   └── 2026-02-10-auth-implementation.md
└── issues/                          # Known problems
    └── ISS-001-token-race.md
```

---

## File Formats

### Workspace Files (Temporary)

#### progress.json
```json
{
  "id": "orch-2026-02-10-15-30-auth",
  "name": "Authentication System",
  "status": "in-progress",
  "started": "2026-02-10T15:30:00Z",
  "lastUpdated": "2026-02-10T15:45:00Z",
  "tasksTotal": 5,
  "tasksCompleted": 2,
  "currentTask": "AUTH-003"
}
```

#### tasks.json
```json
{
  "AUTH-001": {
    "id": "AUTH-001",
    "name": "User Model",
    "status": "completed",
    "startedAt": "2026-02-10T15:30:00Z",
    "completedAt": "2026-02-10T15:40:00Z",
    "filesChanged": ["src/models/User.ts"],
    "testsRun": 5,
    "testsPassed": 5
  },
  "AUTH-002": {
    "id": "AUTH-002",
    "status": "in-progress",
    "startedAt": "2026-02-10T15:40:00Z"
  }
}
```

#### links.json
```json
{
  "plan": "{configured-path}/plans/2026-02-10-auth-system.md",
  "report": null
}
```

**Note:** Path is from `.cursor/config.json` → `documentation.paths.plans`

---

### Documentation Files (Permanent)

#### plans/ - High-Level Plans
**Created by:** Planner  
**Location:** Workspace (temporary) or user's file

**Format:**
```markdown
# Plan: Authentication System

**Created:** 2026-02-10
**Orchestration:** orch-2026-02-10-15-30-auth
**Status:** 🔄 In Progress

## Goal
Implement JWT-based authentication with user management.

## Tasks
- [ ] AUTH-001: User Model (⏳ Pending)
- [ ] AUTH-002: JWT Utilities (⏳ Pending)
- [ ] AUTH-003: Auth Middleware (⏳ Pending)
- [ ] AUTH-004: API Endpoints (⏳ Pending)
- [ ] AUTH-005: Testing (⏳ Pending)

## Dependencies
- AUTH-002 requires AUTH-001
- AUTH-003 requires AUTH-002

## Architecture Decisions
- Using JWT with refresh tokens
- Password hashing with bcrypt
```

#### reports/ - Completion Reports
**Created by:** Documenter  
**Location:** `{config.documentation.paths.reports}/`

**Format:**
```markdown
# Report: Auth System Implementation

**Date:** 2026-02-10
**Orchestration:** orch-2026-02-10-15-30-auth
**Status:** ✅ Completed

## Summary
Implemented complete JWT-based authentication system with user management.

## What Was Built
- User model with password hashing
- JWT token generation and validation
- Auth middleware for protected routes
- Login/register API endpoints
- Comprehensive test coverage

## Completed Tasks
1. ✅ AUTH-001: User Model (25 min)
2. ✅ AUTH-002: JWT Utilities (30 min)
3. ✅ AUTH-003: Auth Middleware (20 min)
4. ✅ AUTH-004: API Endpoints (35 min)
5. ✅ AUTH-005: Testing (40 min)

## Metrics
- 8 files created
- 320 lines of code
- 15 tests (all passing)
- 0 linter errors

## Known Issues
- ISS-001: Token refresh race condition (Low priority)
```

#### issues/ - Known Problems
**Created by:** Any agent  
**Location:** `{config.documentation.paths.issues}/`

**Format:**
```markdown
# Issue: Token Refresh Race Condition

**ID:** ISS-001
**Created:** 2026-02-10
**Severity:** Low
**Status:** Open

## Description
Potential race condition when refreshing tokens concurrently.

## Impact
- Rare occurrence
- No security implications
- Minor UX issue

## Why Not Fixed Now
- Low priority
- Would require Redis for distributed locking
- Current implementation sufficient for MVP

## Proposed Solution
Implement distributed lock using Redis when scaling to multiple servers.

## Related
- Orchestration: orch-2026-02-10-15-30-auth
- Task: AUTH-002
```

---

## Workflows

### Helper: Read Configuration

**Always read config first:**

```javascript
config = readJSON(".cursor/config.json")
if (!config) {
  // Use defaults
  config = {
    workspace: { path: ".cursor/workspace" },
    documentation: {
      paths: {
        root: "ai_docs",
        plans: "ai_docs/develop/plans",
        reports: "ai_docs/develop/reports",
        issues: "ai_docs/develop/issues",
        architecture: "ai_docs/develop/architecture",
        features: "ai_docs/develop/features",
        api: "ai_docs/develop/api",
        components: "ai_docs/develop/components",
        design: "ai_docs/design",
        changelog: "ai_docs/changelog"
      }
    }
  }
}
}

workspacePath = config.workspace.path
docsReports = config.documentation.paths.reports  // null = disabled
docsIssues = config.documentation.paths.issues    // null = disabled
docsArchitecture = config.documentation.paths.architecture  // null = disabled
```

**Check before writing:**

```javascript
// Example: Create report only if enabled
if (docsReports !== null) {
  reportFile = `${docsReports}/2026-02-10-auth-report.md`
  write(reportFile, reportContent)
} else {
  // Reports disabled, only show in chat
  return "Report: [content in chat only]"
}

// Example: Create issue only if enabled
if (docsIssues !== null) {
  issueFile = `${docsIssues}/ISS-001-token-race.md`
  write(issueFile, issueContent)
} else {
  // Just log warning in chat
  warn("⚠️ Issue found: token race condition (low priority)")
}
```

---

## Planner Workflow

### Step 0: Detect Input Type

```javascript
// Check if user provided a task file
userInput = getUserInput()
taskFile = detectTaskFile(userInput) // e.g., @TODO.md, @roadmap.md

if (taskFile) {
  // Mode: Update existing file
  mode = "file"
  planFile = taskFile
} else {
  // Mode: Create temporary plan
  mode = "temporary"
  planFile = null
}
```

### Step 1: Initialize Orchestration

```javascript
// Generate orchestration ID
timestamp = formatDate(now(), "YYYY-MM-DD-HH-mm")
slug = slugify(taskName) // "auth-system" → "auth"
orchestrationId = `orch-${timestamp}-${slug}`

// Create workspace
workspaceDir = `${config.workspace.path}/active/${orchestrationId}`
createDirectory(workspaceDir)

// Initialize progress
write(`${workspaceDir}/progress.json`, {
  id: orchestrationId,
  name: taskName,
  status: "planning",
  started: now(),
  tasksTotal: 0,
  tasksCompleted: 0,
  mode: mode,  // "file" or "temporary"
  sourceFile: taskFile || null
})
```

### Step 2: Create or Use Plan

**Mode A: Temporary Plan (no file provided)**

```javascript
// Generate plan content
planContent = generatePlan(taskDescription)

// Save link in workspace (plan stays in workspace only)
write(`${workspaceDir}/links.json`, {
  plan: null,  // no permanent plan file
  report: null,
  temporary: true
})

// Save plan in workspace
write(`${workspaceDir}/plan.md`, planContent)

// Initialize tasks tracking
write(`${workspaceDir}/tasks.json`, {})
```

**Mode B: User's Task File (file provided)**

```javascript
// Read existing task file
taskFile = progress.sourceFile  // e.g., "TODO.md"
existingContent = read(taskFile)

// Parse tasks from file
tasks = parseTasks(existingContent)

// Save link in workspace
write(`${workspaceDir}/links.json`, {
  plan: taskFile,  // link to user's file
  report: null,
  temporary: false
})

// Initialize tasks tracking from file
write(`${workspaceDir}/tasks.json`, tasks)
```

**Common: Update progress**

```javascript
updateJSON(`${workspaceDir}/progress.json`, {
  status: "ready",
  tasksTotal: taskCount
})
```

### Step 3: Return to User

```markdown
✅ Plan created: {planFile}
🎯 Tasks: {taskCount} tasks ({taskIds})
📂 Orchestration: {orchestrationId}

Ready to start with /orchestrate execute {orchestrationId}
```

---

## Orchestrator Workflow

### Step 1: Load Orchestration

```javascript
// Find orchestration
orchestrationId = userInput || findLatestActive()
workspaceDir = `${config.workspace.path}/active/${orchestrationId}`

// Read metadata
progress = readJSON(`${workspaceDir}/progress.json`)
links = readJSON(`${workspaceDir}/links.json`)
tasksState = readJSON(`${workspaceDir}/tasks.json`)

// Read plan from documentation
planContent = read(links.plan)
taskIds = extractTaskIds(planContent)
```

### Step 2: Execute Tasks Loop

```javascript
for (taskId of taskIds) {
  // Skip if already completed
  if (tasksState[taskId]?.status === "completed") continue
  
  // Update task status: in-progress
  tasksState[taskId] = {
    id: taskId,
    status: "in-progress",
    startedAt: now()
  }
  write(`${workspaceDir}/tasks.json`, tasksState)
  
  // Update plan/task file
  if (links.plan) {
    // Mode B: Update user's task file
    updateTaskInFile(links.plan, taskId, "🔄 In Progress")
  } else {
    // Mode A: Update workspace plan
    updateTaskInFile(`${workspaceDir}/plan.md`, taskId, "🔄 In Progress")
  }
  
  // Execute task
  result = callWorker(taskId, taskDetails)

  // Write tests for implemented code
  testWriterResult = callTestWriter(result.filesChanged)

  // Run tests & verify
  testAndVerifyPassed = callTestRunner()
  reviewPassed = callReview()
  
  // Update task status: completed
  tasksState[taskId] = {
    ...tasksState[taskId],
    status: "completed",
    completedAt: now(),
    filesChanged: result.filesChanged,
    testsRun: testsPassed.total,
    testsPassed: testsPassed.passed
  }
  write(`${workspaceDir}/tasks.json`, tasksState)
  
  // Update plan/task file
  if (links.plan) {
    // Mode B: Update user's task file
    updateTaskInFile(links.plan, taskId, "✅ Completed")
  } else {
    // Mode A: Update workspace plan
    updateTaskInFile(`${workspaceDir}/plan.md`, taskId, "✅ Completed")
  }
  
  // Update progress
  updateJSON(`${workspaceDir}/progress.json`, {
    tasksCompleted: progress.tasksCompleted + 1,
    lastUpdated: now()
  })
}
```

### Step 3: Finalize

```javascript
// Update status
updateJSON(`${workspaceDir}/progress.json`, {
  status: "documenting"
})

// Call documenter to create report
reportFile = callDocumenter(orchestrationId, links.plan, tasksState)

// Save report link
updateJSON(`${workspaceDir}/links.json`, {
  report: reportFile
})

// Mark as completed
updateJSON(`${workspaceDir}/progress.json`, {
  status: "completed",
  completedAt: now(),
  reportFile: reportFile
})

// Move to completed
move(
  `${config.workspace.path}/active/${orchestrationId}`,
  `${config.workspace.path}/completed/${orchestrationId}`
)
```

---

## Documenter Workflow

### Create Completion Report

```javascript
// Read orchestration metadata
workspaceDir = `${config.workspace.path}/completed/${orchestrationId}`
progress = readJSON(`${workspaceDir}/progress.json`)
links = readJSON(`${workspaceDir}/links.json`)
tasksState = readJSON(`${workspaceDir}/tasks.json`)

// Read plan
planContent = read(links.plan)

// Generate report
reportContent = generateReport({
  orchestrationId: progress.id,
  name: progress.name,
  started: progress.started,
  completed: progress.completedAt,
  tasks: tasksState,
  planFile: links.plan
})

// Write to documentation (permanent)
reportFile = `${docsReports}/${formatDate(now(), "YYYY-MM-DD")}-${slug}-implementation.md`
write(reportFile, reportContent)

// Update links
updateJSON(`${workspaceDir}/links.json`, {
  report: reportFile
})
```

---

## Any Agent: Creating Issues

### When to Create Issue

**DO create issue when:**
- ✅ Non-critical problem found
- ✅ Enhancement idea
- ✅ Tech debt identified
- ✅ Don't want to block current work

**DON'T create issue when:**
- ❌ Critical bug (fix immediately via debugger)
- ❌ Blocks current task
- ❌ Simple fix (< 5 min)

### Issue Creation

```javascript
// Read config
config = readJSON(".cursor/config.json")
issuesPath = config.documentation.paths.issues || "ai_docs/develop/issues"

// Generate issue ID
lastIssueId = findLastIssueId(issuesPath) // ISS-003
nextIssueId = incrementId(lastIssueId) // ISS-004

// Create issue file
issueFile = `${issuesPath}/ISS-${nextIssueId}-${slug}.md`
write(issueFile, issueContent)

// Optionally: link to current orchestration
if (currentOrchestration) {
  // Add reference in issue content
  addReference(issueFile, {
    orchestration: currentOrchestration.id,
    task: currentTask.id
  })
}
```

---

## Naming Conventions

### Orchestration IDs
```
Format: orch-YYYY-MM-DD-HH-mm-{slug}

Examples:
- orch-2026-02-10-15-30-auth
- orch-2026-02-10-16-45-payments
- orch-2026-02-11-09-00-refactor
```

### Plans
```
Format: YYYY-MM-DD-feature-name.md
Location: workspace/active/orch-{id}/plan.md OR user's file

Examples:
- 2026-02-10-auth-system.md
- 2026-02-11-payment-integration.md
```

### Task IDs (in plan content)
```
Format: PREFIX-NNN

Prefixes:
- AUTH - Authentication
- PAY - Payments
- API - API changes
- UI - UI components
- DB - Database
- REF - Refactoring

Examples:
- AUTH-001, AUTH-002
- PAY-001, PAY-002
- API-001
```

### Reports
```
Format: YYYY-MM-DD-feature-implementation.md
Location: {config.documentation.paths.reports}/

Examples:
- 2026-02-10-auth-implementation.md
- 2026-02-11-payment-implementation.md
```

### Issues
```
Format: ISS-NNN-description.md
Location: {config.documentation.paths.issues}/

Examples:
- ISS-001-token-refresh-race.md
- ISS-002-add-2fa-support.md
```

---

## System Relationships

```
Orchestration (1) → Plan (1) → Tasks (N) → Report (1)

Workspace (temporary):
  .cursor/workspace/active/orch-2026-02-10-15-30-auth/
    ├── progress.json        [metadata]
    ├── tasks.json           [statuses]
    └── links.json           [references]
          ↓
Documentation (permanent):
  docs/plans/2026-02-10-auth-system.md      [plan content]
  docs/reports/2026-02-10-auth-report.md    [final report]
  docs/issues/ISS-001-token-race.md         [known issues]
```

---

## Example: Complete Cycle

### 1. Planning Phase
```
User: /orchestrate Build auth system

Planner:
→ Creates workspace: .cursor/workspace/active/orch-2026-02-10-15-30-auth/
→ Creates plan: docs/plans/2026-02-10-auth-system.md
→ Initializes: progress.json, tasks.json, links.json
→ Returns: "Ready to execute with 5 tasks"
```

### 2. Implementation Phase
```
Orchestrator:
→ Loads workspace: orch-2026-02-10-15-30-auth
→ Reads plan from: docs/plans/2026-02-10-auth-system.md
→ Processes AUTH-001:
  - Updates: workspace/tasks.json (in-progress)
  - Updates: docs/plans/...md (🔄 In Progress)
  - Calls worker
  - Updates: workspace/tasks.json (completed)
  - Updates: docs/plans/...md (✅ Completed)
→ Processes AUTH-002:
  - Review finds minor issue
  - Creates: docs/issues/ISS-001-token-refresh-race.md
  - Continues (doesn't block)
→ ... continues with remaining tasks
```

### 3. Documentation Phase
```
Documenter:
→ Reads: workspace metadata + docs/plans/
→ Creates: docs/reports/2026-02-10-auth-implementation.md
→ Archives workspace: active/ → completed/
→ Auto-cleanup after 7 days (configurable)
```

### 4. Issue Resolution (Later)
```
User: /orchestrate Fix known issues

Planner:
→ Reads: docs/issues/ISS-*.md (open issues)
→ Creates new orchestration: orch-2026-02-15-09-00-fixes
→ Creates: docs/plans/2026-02-15-fix-issues.md
```

---

## Benefits

### ✅ No Duplication
```
Workspace = metadata only
Documentation = actual content
```

### ✅ Parallel Orchestrations
```
.cursor/workspace/active/
  orch-auth-123/      [isolated]
  orch-payments-456/  [isolated]
```

### ✅ Crash Recovery
```
Workspace stores state → can resume
Documentation already written → no data loss
```

### ✅ Configurable Paths
```json
{
  "documentation": {
    "paths": {
      "plans": "specs/",           // GitHub Spec Kit
      "reports": "docs/adr/",      // ADR
      "issues": ".github/issues/"  // GitHub Issues
    }
  }
}
```

### ✅ Clean Separation
```
Temporary: Task management state (workspace)
Permanent: Feature documentation (configured paths)
```

---

## Status Indicators

### Orchestration Status
- 🔵 **planning** - Creating plan
- 🟢 **ready** - Plan created, ready to execute
- 🟡 **in-progress** - Executing tasks
- 🟠 **documenting** - Creating final report
- ✅ **completed** - All done
- ❌ **failed** - Interrupted/crashed

### Task Status
- ⏳ **pending** - Not started
- 🔄 **in-progress** - Being worked on
- ✅ **completed** - Done and verified
- 🚫 **blocked** - Waiting on dependency

### Issue Severity
- 🔴 **Critical** (P1) - Fix immediately
- 🟠 **High** (P2) - Fix this week
- 🟡 **Medium** (P3) - Fix this month
- 🟢 **Low** (P4) - Fix when possible
- 🔵 **Enhancement** (P5) - Nice to have

---

**Summary:** Two-tier system - temporary workspace for state tracking, permanent documentation for feature specs and reports.
