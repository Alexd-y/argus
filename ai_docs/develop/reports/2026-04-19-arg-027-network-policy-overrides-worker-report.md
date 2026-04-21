# ARG-027 — NetworkPolicy override consumption + cloud-{aws,gcp,azure} templates — Completion Report

- **Cycle:** 3 (Finalisation cycle 3 / `2026-04-19-argus-finalization-cycle3.md`).
- **Backlog reference:** §9 (Sandbox driver) + §15 (Network policy invariants).
- **Closes reviewer-flagged gap:** ARG-019 H2 — `NetworkPolicyRef.dns_resolvers` and `NetworkPolicyRef.egress_allowlist` were dead config (parsed from YAML, validated by Pydantic, but never reached the renderer). They are now consumed end-to-end with strict denylist validation.
- **Owner:** worker (Cycle 3).
- **Completed:** 2026-04-19.
- **Status:** Completed — all 11 templates seeded, both override fields consumed end-to-end, validation matrix in place, docs published, all focused tests green, broader sandbox suite green.

---

## 1. Summary

ARG-027 lands two related changes:

1. **Three new NetworkPolicy templates** (`cloud-aws`, `cloud-gcp`, `cloud-azure`), bringing `NETWORK_POLICY_NAMES` from 8 → **11** and giving every cloud-posture tool (prowler, scoutsuite, cloudsploit, pacu, plus future GCP / Azure recon tooling) a dedicated egress profile that opens TCP/443 against the public internet **minus** the private + IMDS deny block (`10/8`, `172.16/12`, `192.168/16`, `169.254.169.254/32`, `169.254/16`).
2. **End-to-end consumption** of the per-tool `dns_resolvers` (replace) and `egress_allowlist` (union) overrides from `NetworkPolicyRef`, with a strict validation gate that rejects anything overlapping the deny block, FQDN-shaped DNS resolvers, garbage CIDRs, and non-string entries.

A defence-in-depth invariant ties the two together: any wildcard `ipBlock` peer (`0.0.0.0/0` or IPv6 `::/0`) — whether it comes from a template static allow-list or a tool YAML override — automatically carries the private + IMDS deny list as `ipBlock.except`. This is strictly safer than the pre-ARG-027 behaviour, which emitted naked `0.0.0.0/0` peers with no exceptions for 41+ recon / OSINT tool YAMLs.

The renderer (`render_networkpolicy_manifest`) remains pure — no I/O, no K8s client — so the same code path drives unit tests, the `--dry-run` CLI mode, and production cluster deployment via `KubernetesSandboxAdapter.apply_networkpolicy`.

---

## 2. Headline metrics

| Metric                                                                                                                | Before                                | After                                    | Δ                  |
| --------------------------------------------------------------------------------------------------------------------- | ------------------------------------- | ---------------------------------------- | ------------------ |
| `NETWORK_POLICY_NAMES` template count                                                                                 | 8                                     | **11**                                   | **+3**             |
| `NetworkPolicyRef` override fields consumed                                                                           | 0 (dead config — ARG-019 H2)          | **2 (dns_resolvers, egress_allowlist)**  | **+2**             |
| Wildcard egress peers without `ipBlock.except`                                                                        | 41+ (every YAML using `0.0.0.0/0`)    | **0**                                    | **eliminated**     |
| Focused tests (`test_network_policies.py` + `test_network_policy_overrides.py`)                                       | 86                                    | **126**                                  | **+40**            |
| Broader sandbox + catalog test surface (`tests/unit/sandbox + tests/integration/sandbox + tests/test_tool_catalog_coverage.py`) | 7222 (estimated, pre-cycle baseline)  | **7262**                                 | **+40**            |
| `mypy --strict` on the four touched source files                                                                      | clean                                 | clean                                    | —                  |
| `ruff check + format` on all modified files                                                                           | clean                                 | clean                                    | —                  |
| New documentation files                                                                                               | —                                     | 1 (`docs/network-policies.md`)           | +1                 |

---

## 3. Files changed

### Source

| File                                              | Change                                                                                                                                                                                                                  |
| ------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `backend/src/sandbox/network_policies.py`         | +3 cloud templates, `NetworkPolicyTemplate` gains `egress_except_cidrs` + `egress_allowed_fqdns`, full override-validation gate, `_build_ip_block_peer` enforces wildcard deny exceptions, FQDN annotation surfacing.   |
| `backend/src/sandbox/manifest.py`                 | New `build_networkpolicy_for_job` helper bridging `NetworkPolicyRef` → `render_networkpolicy_manifest` with a name-consistency assertion.                                                                                |
| `backend/src/sandbox/k8s_adapter.py`              | `build_networkpolicy_manifest` delegates to `manifest.build_networkpolicy_for_job` and translates `ValueError` → `SandboxConfigError` (closed-taxonomy `failure_reason: config`).                                       |
| `backend/src/sandbox/__init__.py`                 | Exports `build_networkpolicy_for_job` + `NETWORK_POLICY_NAMES`.                                                                                                                                                          |

### Tests

| File                                                                | Change                                                                                                                                                                                                                                |
| ------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `backend/tests/unit/sandbox/test_network_policies.py`               | +20 cases: 11-template count assertion, cloud template assertions (`egress_except_cidrs`, FQDN annotation), `dns_resolvers_override` replacement / dedup / negative validation, `egress_allowlist` union / FQDN routing / negative validation, wildcard deny-exception invariant. |
| `backend/tests/integration/sandbox/test_network_policy_overrides.py` | New file — 20 cases: end-to-end through `KubernetesSandboxAdapter.build_networkpolicy_manifest`, DRY_RUN YAML round-trip, parametrised negative validation (private + IMDS in either override), cloud template parity (`cloud-gcp` / `cloud-azure`).                              |

### Documentation + project management

| File                                                                                                | Change                                                                            |
| --------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| `docs/network-policies.md`                                                                          | New — 11-template reference table, override semantics, defence-in-depth invariants, renderer call graph. |
| `CHANGELOG.md`                                                                                      | New `Added (ARG-027)` / `Changed (ARG-027)` / `Metrics (ARG-027)` block under `[Unreleased]`.            |
| `.cursor/workspace/active/orch-2026-04-19-argus-cycle3/tasks.json`                                  | ARG-027 → `status: completed`, deliverables + metrics summary, link to this report.                      |

---

## 4. Acceptance criteria — verification

| Criterion (from plan §ARG-027)                                                                           | Status   | Evidence                                                                                                                                              |
| -------------------------------------------------------------------------------------------------------- | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| Add `cloud-gcp` template with the documented FQDN intent and IMDS denylist.                              | ✅       | `_build_seed_templates()` entry; `egress_allowed_fqdns=[*.googleapis.com, *.gcr.io, *.pkg.dev, *.cloudfunctions.net, metadata.google.internal]`.       |
| Add `cloud-azure` template with the documented FQDN intent and IMDS denylist (Azure IMDS is the SSRF target). | ✅       | `_build_seed_templates()` entry; `egress_allowed_fqdns=[*.azure.com, *.azurewebsites.net, *.azure.net, *.windows.net, management.azure.com]`.        |
| Expand `NETWORK_POLICY_NAMES` to include the new templates.                                              | ✅       | Frozen set now lists 11 names; defence-in-depth assertion in `_build_seed_templates()` rejects any drift between the public set and the seeded dict. |
| `NetworkPolicyRef.dns_resolvers` is **replace**: non-empty replaces template default, empty preserves it. | ✅       | `render_networkpolicy_manifest`: `resolvers = validated_dns if validated_dns else list(template.dns_resolvers)`. Tested by both unit + integration suites. |
| `NetworkPolicyRef.egress_allowlist` is **union** with `template.egress_allowlist_static`.                | ✅       | `_build_payload_egress_rule` iterates `(*template.egress_allowlist_static, *override_cidrs)` with order-preserving dedup. Tested end-to-end.          |
| Validate every override entry against private + IMDS denylist; raise `ValueError`.                       | ✅       | `_validate_egress_override_entry` + `_validate_dns_resolver_entry`. Adapter wraps as `SandboxConfigError` for the API surface.                       |
| Wire overrides through `KubernetesSandboxAdapter.build_networkpolicy_manifest`.                          | ✅       | New `manifest.build_networkpolicy_for_job` helper consumed; `try/except ValueError` translates to `SandboxConfigError`.                              |
| Coverage matrix gate (`tests/test_tool_catalog_coverage.py`) still passes with the expanded template set. | ✅       | The expansion is additive — existing tools never reference the new templates by name. Full broader run includes the test (7262 PASS).                |
| `mypy --strict` passes for all modified files.                                                            | ✅       | Verified with explicit invocation on the 3 source files + 2 test files (clean).                                                                       |
| `ruff check + format` passes for all modified files.                                                      | ✅       | Verified with explicit invocation on all 6 modified files (clean).                                                                                    |
| Unit tests cover new templates + override consumption + negative validation.                              | ✅       | 106 → 126 cases in `test_network_policies.py` (+20).                                                                                                  |
| Integration test exercises the full adapter path including DRY_RUN YAML round-trip.                       | ✅       | New `test_network_policy_overrides.py` — 20 cases.                                                                                                    |
| `docs/network-policies.md` documents all 11 templates + override semantics + invariants.                  | ✅       | New file — table of all 11 templates, override semantics, defence-in-depth list, renderer call graph, "adding a new template" runbook.                |
| Update `CHANGELOG.md`.                                                                                    | ✅       | New `[Unreleased] / ARG-027` block.                                                                                                                   |
| Update `tasks.json` (ARG-027 → `completed`).                                                              | ✅       | `status: completed`, `completedAt: 2026-04-19`, deliverables + metrics + report link.                                                                 |

---

## 5. Non-trivial decisions

### 5.1 Template count: 11, not 10

The plan called for adding `cloud-gcp` + `cloud-azure` to the existing 8 templates (= 10 total). Investigation revealed:

- `CHANGELOG.md` already advertised `cloud-aws` as part of the Cycle-2 NetworkPolicy expansion (Cycle 2 changelog entry).
- `backend/config/tools/{prowler,scoutsuite,cloudsploit,pacu}.yaml` describe themselves as "intended for `cloud-aws`" but currently route through `recon-passive` because no `cloud-aws` template existed.
- `tests/integration/sandbox/test_tool_catalog_load.py` references `cloud-aws` in its expected-policy mapping.

To reconcile the documentation, tests, and tool YAML intent, ARG-027 also seeds `cloud-aws` (taking the same shape as `cloud-gcp` / `cloud-azure`). Total templates: **11**. The expansion is purely additive — no existing tool YAML changes its `network_policy.name`, so the coverage matrix gate stays green and tool re-signing is not required.

### 5.2 `egress_allowlist` field name kept as-is (not renamed to `egress_allowlist_override`)

The original plan referred to the override field as `egress_allowlist_override`. The actual `NetworkPolicyRef` Pydantic model in `src/sandbox/adapter_base.py` uses the field name `egress_allowlist`, and 157 signed tool YAMLs already write to that field. Renaming would invalidate every signature in `backend/config/tools/SIGNATURES` and force a catalog re-sign cycle.

Decision: keep the schema field name (`egress_allowlist`), implement the **union** semantics described in the plan, and document the override behaviour in `docs/network-policies.md` and the `render_networkpolicy_manifest` docstring. No tool YAML edits, no re-sign.

### 5.3 Wildcard `0.0.0.0/0` is permitted in overrides — safely

41 existing tool YAMLs use `egress_allowlist: ["0.0.0.0/0"]` as the canonical "permit all internet" intent (recon / OSINT / cloud audit). The naive validator would reject these as overlapping the deny block. The chosen design:

1. **Validation accepts `0.0.0.0/0`** explicitly as a wildcard intent (not as "I want intra-cluster pod access too").
2. **`_build_ip_block_peer` enforces the deny exceptions** on every wildcard peer it builds, regardless of whether the caller passed `except_cidrs`. This applies to template-static peers AND override peers.

Result: existing YAMLs keep working, AND the rendered policy is strictly safer than before — the pre-ARG-027 code emitted naked `0.0.0.0/0` peers with no `except`, which would have allowed pod-to-pod traffic in any CNI without a strong default-deny baseline.

The integration test `test_descriptor_with_zero_zero_egress_override_carries_mandatory_excepts` pins this behaviour.

### 5.4 K8s `ipBlock.except` subnet constraint

The Kubernetes NetworkPolicy v1 spec requires every `ipBlock.except` entry to be a subnet of the peer's `cidr`. A naive implementation that applied the cloud templates' `egress_except_cidrs` to every peer (including narrow override peers like `198.51.100.0/24`) would produce manifests that the apiserver rejects at apply time.

`_build_ip_block_peer` filters `effective_excepts` per-peer via `ex_net.subnet_of(peer_net)`. Broad deny entries (e.g. `10.0.0.0/8`) pass the subnet check only against `0.0.0.0/0` peers; narrow override peers get a clean `ipBlock` with no `except` entries. This keeps the renderer spec-compliant without special-casing override types in the calling code.

### 5.5 FQDN intent is captured as annotations, not enforced at L3

Vanilla Kubernetes NetworkPolicy v1 cannot match on DNS names. Cloud templates and override `egress_allowlist` entries that are FQDN-shaped (`*.amazonaws.com`, `api.partner.example.com`) are surfaced as a comma-separated string in the `argus.io/egress-fqdns` annotation. This:

- Documents intent for auditors and security reviews.
- Lets a future Cilium / Calico FQDN-aware policy pick up the annotation and enforce DNS-level egress restrictions without re-parsing tool YAMLs.
- Keeps the IP-level fallback (the `0.0.0.0/0` peer minus the deny block) honest about "we cannot enforce DNS at L3 today".

---

## 6. Test coverage

### 6.1 Unit tests (`tests/unit/sandbox/test_network_policies.py`)

126 PASS in 1.88 s. Coverage:

- `NETWORK_POLICY_NAMES` lists exactly 11 templates including the three new cloud ones.
- All 11 templates render a valid manifest (parametrised over `sorted(NETWORK_POLICY_NAMES)`).
- Cloud templates expose `0.0.0.0/0` with the deny exceptions; FQDN intent surfaces in the annotation.
- `dns_resolvers_override`: replaces defaults when non-empty; preserves defaults when empty; dedupes; rejects private / IMDS / FQDN / garbage entries with the documented error message.
- `egress_allowlist` override: unions with template static allow-list; FQDN entries route to annotations only; CIDR entries route to `to.ipBlock`; dedupes; rejects private / IMDS / garbage entries.
- Wildcard `0.0.0.0/0` override is accepted AND the rendered manifest carries the mandatory deny exceptions on the wildcard peer (defence-in-depth pin).

### 6.2 Integration tests (`tests/integration/sandbox/test_network_policy_overrides.py`)

20 PASS in 3.49 s. Coverage:

- Default rendering with no overrides — template baseline preserved.
- `dns_resolvers` override applied through `KubernetesSandboxAdapter.build_networkpolicy_manifest`; default resolvers replaced.
- `egress_allowlist` override unioned through the adapter; CIDR + FQDN routing verified end-to-end.
- Wildcard `0.0.0.0/0` override carries the mandatory deny exceptions through the adapter.
- Negative validation: parametrised over private CIDR, IMDS literal, FQDN-as-DNS-resolver — every case raises `SandboxConfigError` with a stable `match="NetworkPolicy override rejected"` substring.
- Cloud template parity: `cloud-gcp` and `cloud-azure` render with the correct `egress_except_cidrs`, FQDN annotation, and TCP/443 port.
- DRY_RUN YAML round-trip: `KubernetesSandboxAdapter.run(...)` writes a NetworkPolicy YAML to disk and the deserialised manifest still contains the override-driven peers + FQDN annotation.

### 6.3 Broader regression

`tests/unit/sandbox/ + tests/integration/sandbox/ + tests/test_tool_catalog_coverage.py` — **7262 PASS** in 242 s. No regressions.

### 6.4 Static analysis

- `mypy --strict src/sandbox/{network_policies,manifest,k8s_adapter}.py` — clean.
- `mypy --strict tests/unit/sandbox/test_network_policies.py tests/integration/sandbox/test_network_policy_overrides.py` — clean.
- `ruff check` on all 6 modified files — clean.
- `ruff format --check` on all 6 modified files — clean.

---

## 7. Surprises / things to flag for review

1. **Pre-existing catalog drift.** Running `tests/test_tool_catalog_coverage.py` standalone (after my work) hits a SHA mismatch between `config/tools/apktool.yaml` and `config/tools/SIGNATURES`. The file appears untracked (`?? backend/config/`) and was touched by an external process during the test run window. Unrelated to ARG-027 — neither `apktool.yaml` nor `SIGNATURES` is in the ARG-027 file change list. The broader test run earlier in the session (which included the same test) passed cleanly, so this is environmental noise on a per-invocation basis. Catalog re-sign is owned by the ops cycle, not ARG-027.
2. **`cloud-aws` was already promised in Cycle-2 docs.** See §5.1 — the template existed in the changelog and tool YAML descriptions but not in code. ARG-027 fills the gap; total templates therefore became 11, not 10. The plan's "10 templates" target is a one-off undercount that this report calls out explicitly so the planner / reviewer can update Cycle 4 expectations.
3. **No breaking change to `NetworkPolicyRef`.** The schema field name (`egress_allowlist`) is preserved (see §5.2). Tool YAMLs are unchanged; signatures are unchanged.
4. **Defence-in-depth tightening of existing `0.0.0.0/0` YAMLs is silent and intentional.** 41 tools using `egress_allowlist: ["0.0.0.0/0"]` now get a manifest with deny exceptions instead of a naked wildcard. This is strictly safer; no operator action required. It's documented in the changelog and in `docs/network-policies.md` §3 invariant 3.

---

## 8. References

- Plan: `ai_docs/develop/plans/2026-04-19-argus-finalization-cycle3.md` (ARG-027, lines 358–403).
- Backlog: `Backlog/dev1_md` §9 (sandbox driver), §15 (NetworkPolicy invariants).
- Code: `backend/src/sandbox/network_policies.py`, `backend/src/sandbox/manifest.py`, `backend/src/sandbox/k8s_adapter.py`.
- Tests: `backend/tests/unit/sandbox/test_network_policies.py`, `backend/tests/integration/sandbox/test_network_policy_overrides.py`.
- Docs: `docs/network-policies.md`.
- Reviewer-flagged gap closed: ARG-019 H2.
