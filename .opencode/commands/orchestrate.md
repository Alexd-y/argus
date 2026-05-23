---
name: orchestrate
description: Full orchestration - Plan → Task Loop (Code → Test → Review) → Docs. For complex features and systems.
---

# Orchestrate Command

## ⛔ YOU ARE FORBIDDEN FROM DOING ANY WORK YOURSELF

**Do NOT write code. Do NOT edit files. Do NOT plan or design without a subagent.**

Every single step must be executed by a subagent via the `Task` tool.
You are the coordinator only. If you find yourself about to do anything besides calling `Task` — STOP.

---

## MANDATORY: Read and follow the skill

1. Read `.cursor/skills/orchestration/SKILL.md` using the Read tool — right now, before anything else
2. Execute EXACTLY as described in the skill — using `Task(subagent_type=...)` for each step
3. Do not skip, summarize, or shortcut any step from the skill
