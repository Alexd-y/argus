# ARGUS-015: Security Hardening P0 — Audit Checklist

## 1. Command Injection

| Check | Status | Notes |
|-------|--------|-------|
| No `shell=True` in subprocess | ✅ | `executor.py` uses `subprocess.run(..., shell=False)` |
| Parameterized command building | ✅ | `shlex.split` + `shlex.quote` for all tool commands |
| Allowlist for tools | ✅ | `command_parser.py` — only nmap, nuclei, nikto, gobuster, sqlmap |
| User input not passed to shell | ✅ | Target validated via `validate_target_for_tool` |

## 2. Traceback / Information Leak

| Check | Status | Notes |
|-------|--------|-------|
| No stack traces to user | ✅ | `exception_handlers.py` — generic 500 message |
| Structured logging only | ✅ | `logging_config.py` — JSON format |
| Executor stderr sanitized | ✅ | `executor.py` — generic "Command execution failed" on Exception |
| SSE error events generic | ✅ | `scans.py` — `_yield_error_event` uses generic message |

## 3. Path Traversal

| Check | Status | Notes |
|-------|--------|-------|
| Storage path validation | ✅ | `storage.py` — `_sanitize_path_component` rejects `..`, `/`, `\` |
| No direct file access with user paths | ✅ | S3/MinIO only; no `open()` with user input |

## 4. Security Headers

| Check | Status | Notes |
|-------|--------|-------|
| X-Content-Type-Options | ✅ | `nosniff` |
| X-Frame-Options | ✅ | `DENY` |
| X-XSS-Protection | ✅ | `1; mode=block` |
| Referrer-Policy | ✅ | `strict-origin-when-cross-origin` |
| Permissions-Policy | ✅ | Restricts geolocation, microphone, camera |

## 5. Static Analysis

| Check | Status | Notes |
|-------|--------|-------|
| Bandit (low/medium/high) | ✅ | 0 critical; 9 low (informational) |
| Safety (dependencies) | ⚠️ | 2 vulns in transitive `ecdsa` (python-jose); no fix planned by maintainer |

## 6. eval / exec

| Check | Status | Notes |
|-------|--------|-------|
| No eval() | ✅ | Grep: none |
| No exec() | ✅ | Grep: none |

## Files Changed (ARGUS-015)

- `src/core/security_headers.py` — new
- `src/core/exception_handlers.py` — new
- `src/tools/executor.py` — generic stderr on Exception
- `main.py` — register handlers, add SecurityHeadersMiddleware
- `tests/test_argus015_security_p0.py` — new
