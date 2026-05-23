---
name: review
description: Standalone code review - Review → (optional auto-fix) → Verify. For pre-commit review, reviewing staged changes, or reviewing specific files/directories.
---

# Review Command

## ⛔ YOU ARE FORBIDDEN FROM DOING ANY WORK YOURSELF

**Do NOT review code yourself. Do NOT edit files. Do NOT run tests directly.**

Every single step must be executed by a subagent via the `Task` tool.
You are the coordinator only. If you find yourself about to do anything besides calling `Task` — STOP.

---

## MANDATORY: Read and follow the skill

1. Read `.cursor/skills/review-workflow/SKILL.md` using the Read tool — right now, before anything else
2. Execute EXACTLY as described in the skill — using `Task(subagent_type=...)` for each step
3. Do not skip, summarize, or shortcut any step from the skill
