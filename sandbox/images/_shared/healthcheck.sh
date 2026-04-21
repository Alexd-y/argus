#!/bin/sh
# =============================================================================
# ARGUS sandbox image — shared HEALTHCHECK script.
# Cycle 3 / ARG-026.
#
# Contract:
#   - MUST exit 0 for "healthy", non-zero for "unhealthy".
#   - MUST be deterministic (no network, no fs writes, no side effects).
#   - MUST run as the non-root container user (uid 65532 / argus) without
#     requiring any capability or read-write fs.
#   - MUST complete well under the 10s HEALTHCHECK timeout (target: <100ms).
#
# Why a script and not an inline `CMD echo ok`:
#   - The k8s liveness/readiness probe story (Cycle 4) will replace this
#     stub with a real readiness probe (e.g. checking the embedded supervisor
#     socket or syft SBOM presence). Keeping the script as a separate file
#     lets us evolve the probe without touching every Dockerfile.
# =============================================================================

set -eu

# Stub probe — Cycle 3 baseline. Replaced by a real readiness check in Cycle 4.
echo ok
exit 0
