# Orchestration commit scripts

Atomic commit helpers for Batch 1 (and related) tasks. Each script stages an explicit allow-list and may perform one or two commits.

Orchestration workspace paths are not interchangeable. Batch 1 state for these scripts lives under `.cursor/workspace/active/orch-argus-20260420-1430` (paths embedded in each `commit_T*.ps1`). Batch 2 planning and META tracking live under `.cursor/workspace/active/orch-argus-batch2-20260422-1000`. When you run a commit helper, update only the workspace files that script references—do not edit Batch 2 `progress.json` (or other Batch 2 files) while committing Batch 1 work, and vice versa.

## Recommended run order

Apply pending work in this order to reduce merge/conflict risk with shared files (e.g. ISS notes):

**T02 → T03 → T06 → T07 → T08 → T01 → T04 → T09 → T10 → T05**

## Disable the Git pager (session)

Avoid interactive pager prompts (`:`) in automation and Cursor shells:

```powershell
$env:GIT_PAGER = 'cat'; $env:PAGER = 'cat'
```

Scripts also pass `git --no-pager` where applicable; still set the env vars for any direct `git` usage.

## Dry run first

Where a script supports **`-DryRun`**, run it once before a real commit to confirm paths and messages:

```powershell
.\scripts\orchestration\commit_T02.ps1 -DryRun
```

## Scripts

| Script | Typical flags |
|--------|----------------|
| `commit_T01.ps1` … `commit_T10.ps1` | `-DryRun`, `-KeepStaged` (where implemented), task-specific (e.g. T03 `-SignAfterCommit`) |
