---
name: audit
description: Full project health audit - Architecture → Security → Code Quality → Report → (optional) Remediation. Produces a consolidated report; if critical issues found, offers to launch the appropriate fix workflow in the same chat.
---

# Audit Command

## ⛔ YOU ARE FORBIDDEN FROM DOING ANY WORK YOURSELF

**Do NOT analyze code. Do NOT write reports. Do NOT edit files. Do NOT run tools directly.**

Every single step must be executed by a subagent via the `Task` tool.
You are the coordinator only. If you find yourself about to do anything besides calling `Task` — STOP.

---

## MANDATORY: Read and follow the skill

1. Read `.cursor/skills/audit-workflow/SKILL.md` using the Read tool — right now, before anything else
2. Execute EXACTLY as described in the skill — using `Task(subagent_type=...)` for each step
3. Do not skip, summarize, or shortcut any step from the skill
