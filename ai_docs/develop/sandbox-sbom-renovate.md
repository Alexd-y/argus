# Sandbox SBOM, Renovate, and drift checks (T09)

**Audience:** Operators and security engineers maintaining ARGUS sandbox images.  
**Last updated:** 2026-04-21 (Cycle 6, T09).  
**Related:** [`.github/workflows/sandbox-images.yml`](../../.github/workflows/sandbox-images.yml), [`renovate.json`](../../renovate.json), [`infra/scripts/sbom_drift_check.py`](../../infra/scripts/sbom_drift_check.py).

---

## Why this exists

Sandbox images bake a CycloneDX SBOM at `/usr/share/doc/sbom.cdx.json`. The SBOM is regenerated on every image build. Transitive package drift (for example after an `apt-get` layer change) is easy to miss until CI runs. T09 adds:

1. **Renovate** — scheduled, grouped dependency updates for the shared `kalilinux/kali-rolling` base across all six `sandbox/images/argus-kali-*/Dockerfile` files, with digest pinning and supply-chain labels.
2. **Advisory drift check** — each `build-images` matrix leg runs `infra/scripts/sbom_drift_check.py` against optional per-profile baselines (non-blocking in CI).

Committed stubs under `infra/sandbox/images/sbom-*.cdx.json` remain **placeholders** for offline tooling; they are not compared by the drift script.

---

## Renovate setup

1. Install the [Renovate GitHub App](https://github.com/apps/renovate) on the repository (or use the Mend-hosted service your org approves).
2. Configuration lives in **[`renovate.json`](../../renovate.json)** at the repo root (no floating `extends` presets — rules are inlined for a stable, reviewable contract).
3. **Managers:** `dockerfile` only, scoped with `fileMatch` to the six sandbox Dockerfiles.
4. **Schedule:** weekly (`before 4:00am on Monday`, `Etc/UTC`).
5. **Grouping:** all `kalilinux/kali-rolling` lines are updated in **one PR** (`groupName`: `sandbox kalilinux/kali-rolling`).
6. **Digest pinning:** `pinDigests: true` for that image so `FROM` lines move to immutable `name:tag@sha256:…` once Renovate has registry metadata.
7. **Labels on PRs:** `dependencies`, `supply-chain`, `sandbox`, `sbom-watch` (plus Renovate defaults if configured globally).
8. **`docker/dockerfile` syntax image** (`# syntax=docker/dockerfile:…`) is **ignored** by Renovate — bump it deliberately when BuildKit features require it.

### Operator review checklist for a Renovate sandbox PR

- Confirm the new digest/tag still matches org policy (Kali rolling expectations, size, licensing).
- Run or wait for **`sandbox-images`** workflow on the PR (path-filtered when Dockerfiles change).
- If SBOM component sets shift materially, consider updating **SBOM baselines** (next section) after merge to `main`.

---

## SBOM drift check (advisory)

**Script:** [`infra/scripts/sbom_drift_check.py`](../../infra/scripts/sbom_drift_check.py).

**Behaviour:**

- Reads the **built** CycloneDX document (same file CI extracts after `docker build`).
- Computes `fingerprint_sha256` = SHA-256 of the sorted list of component keys `type|name|version|purl`.
- Looks for `sandbox/images/sbom-baselines/<profile>.json` where `<profile>` is `web`, `cloud`, `browser`, `full`, `recon`, or `network`.

**If no baseline file:** prints `fingerprint_sha256` and `component_count`, exits **0** (advisory only).

**If baseline exists and matches:** exits **0**.

**If baseline exists and differs:** prints built vs baseline summary to stderr, exits **1** (CI step uses `continue-on-error: true`, so the workflow still passes but the step is visibly red).

### Baseline JSON shape

```json
{
  "profile": "web",
  "fingerprint_sha256": "<64-char hex>",
  "component_count": 123,
  "updated_at": "2026-04-21T12:00:00Z",
  "notes": "Optional free text; no secrets."
}
```

### How to bootstrap or refresh a baseline

1. Run a successful **`build-images`** leg (or build locally with `infra/scripts/build_images.sh` and extract `/usr/share/doc/sbom.cdx.json` from the container).
2. Run locally from repo root:

   ```bash
   python infra/scripts/sbom_drift_check.py --profile web --built-sbom /path/to/sbom.cdx.json
   ```

   When no baseline exists, the tool prints the fingerprint — copy `fingerprint_sha256` and `component_count` into a new `sandbox/images/sbom-baselines/web.json`.
3. Commit the JSON in the same PR as the intentional image change (or immediately after merge if CI is the source of truth).

**Policy:** Baselines are optional. Adding them for all six profiles turns the advisory step into a **soft ratchet**; omit them until the team wants explicit SBOM lockfiles without blocking merges.

---

## CI integration

The step **“SBOM fingerprint vs baseline (advisory, T09)”** in [`.github/workflows/sandbox-images.yml`](../../.github/workflows/sandbox-images.yml) runs in each profile leg after SBOM envelope validation. Failures do not block the job; they surface transitive drift for triage.

---

## References

- [`ai_docs/develop/ci-cd.md`](ci-cd.md) — workflow inventory and conventions.
- [`ai_docs/develop/issues/ISS-cycle6-carry-over.md`](issues/ISS-cycle6-carry-over.md) — carry-over item closed by T09.
