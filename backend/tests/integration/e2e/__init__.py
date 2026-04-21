"""ARG-047 — End-to-end pytest suite for the Juice Shop capstone scan.

These tests run against the live ``infra/docker-compose.e2e.yml`` stack and
are skipped by default (``-m requires_docker_e2e`` opt-in). They document
the externally observable contract of the stack — health endpoints, scan
lifecycle, report generation — and form the second line of defence after
the bash / PowerShell wrapper. See ``docs/e2e-testing.md`` for the full
operator runbook.
"""
