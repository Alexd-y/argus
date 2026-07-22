# 📚 Playbook & Scenario Subsystem Documentation Index

**Created:** 2026-07-22  
**Version:** 1.0  
**Scope:** P2-PLAYBOOKS-002 through P7-WSTG-007  
**Status:** Production Ready

---

## 🎯 Quick Navigation

### For Implementers
- **[Playbook Architecture Guide](playbooks-architecture.md)** — full technical deep-dive
  - Schema, Registry, Lifecycle, Planner, Executor layers
  - How to create a new playbook (step-by-step)
  - Multi-principal auth model (SI-3)
  - Approval & EAP integration (SI-1)

### For QA & Testing
- **[Integration Testing Guide](playbooks-integration-testing.md)** — runnable examples
  - 12 base scenarios with test code
  - Mock fixtures and MockHttpTransport
  - Example: IDOR, Race condition, Rate-limit playbooks
  - Coverage checklist

### For Report & Analysis
- **[WSTG Coverage & Reporting](wstg-scenario-coverage.md)** — 7 status model
  - WSTG v4.2 registry (single source of truth)
  - Scenario-to-WSTG mapping
  - Finding DTO extension (back-compatible SI-7)
  - Report generation from coverage data

### Supporting Docs
- **[Auth Migration Guide](2026-07-22-auth-migration-guide.md)** — multi-principal breakdown
  - Legacy single-auth → owner principal (back-compat)
  - PrincipalConfig, SessionStore, split-plane secrets
  - Playwright session reuse

- **[Planning Document](2026-07-22-argus-pipeline-playbooks.md)** — overall orchestration
  - 8-phase plan (P1–P8)
  - Dependency graph
  - Security invariants (SI-1 to SI-7)
  - Gap analysis (G-1 to G-9 from phase 1 audit)

---

## 📖 Architecture Layers (How Playbooks Execute)

```
┌─────────────────────────────────────────────────────────────────────┐
│ 1. SCHEMA (backend/src/playbooks/schema.py)                        │
│    • Pydantic models: Playbook, PlaybookStep, OracleSpec           │
│    • Declarative only — no Python/shell from YAML (SI-4)           │
│    • Fail-closed validation: extra="forbid", frozen=True           │
│    • Lifecycle enum: DISCOVERED, PLANNED, RUNNING, CONFIRMED, ...  │
└─────────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────────┐
│ 2. REGISTRY (backend/src/playbooks/registry.py)                    │
│    • Fail-closed loading from config/playbooks/<category>/*.yaml   │
│    • Ed25519 signature verification (backend/config/playbooks/SIGNATURES)
│    • Dupe-check: playbook_id unique                                 │
│    • Name-match: playbook_id == filename.stem                       │
│    • Category-match: file directory == playbook.category            │
└─────────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────────┐
│ 3. PLANNER (backend/src/playbooks/planner.py)                      │
│    • Select applicable playbooks for discovered endpoints          │
│    • Filter by applies_when + required_principals + capabilities   │
│    • Route to WAITING_APPROVAL if requires_approval=True           │
│    • Emit PlannedScenario(PLANNED | SKIPPED_NOT_APPLICABLE)        │
└─────────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────────┐
│ 4. APPROVAL GATE (backend/src/policy/)                             │
│    • PreflightChecker combines scope/ownership/policy/approval     │
│    • EAP pre-authorizes action classes within scope (SI-1, SI-2)   │
│    • OR manual approval signature verification (Ed25519)           │
│    • Transition to RUNNING or stay WAITING_APPROVAL                │
└─────────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────────┐
│ 5. EXECUTOR (backend/src/playbooks/executor.py)                    │
│    • Multi-principal session isolation (SI-3: split-plane secrets) │
│    • Execute playbook steps (HTTP, extract, compare, browser, ...) │
│    • Run oracle assertions (baseline vs mutated comparison)        │
│    • Emit OracleResult(FINDING | NO_FINDING | INCONCLUSIVE)       │
│    • Register & execute cleanup steps                              │
│    • Transition to CONFIRMED/REJECTED/PARTIAL/CLEANUP_*            │
└─────────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────────┐
│ 6. EVIDENCE (backend/src/playbooks/evidence.py)                    │
│    • Collect baseline + mutated HTTP exchanges                     │
│    • Mandatory redaction of secrets (SI-3)                         │
│    • Compute normalized diff (SHA-256 hash for dedup)              │
│    • Build EvidenceDTO for persistence                             │
└─────────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────────┐
│ 7. FINDING (backend/src/pipeline/contracts/finding_dto.py)        │
│    • Project scenario result into FindingDTO                       │
│    • Add scenario_id, playbook_id, oracle_result                   │
│    • Add source/target principals, baseline/mutated requests       │
│    • Link to WSTG test case IDs                                    │
│    • All new fields Optional for back-compat (SI-7)               │
└─────────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────────┐
│ 8. REPORT (backend/src/reports/wstg_coverage.py)                  │
│    • Aggregate scenario results across scan                        │
│    • Map each scenario to WSTG test case + 7 coverage statuses     │
│    • Generate Midgard tier report with findings + evidence         │
│    • Track: CONFIRMED_FINDING, EXECUTED_NO_FINDING, etc.          │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 🔐 Security Invariants (SI-1 to SI-7)

| ID | Name | Implementation |
|----|------|-----------------|
| **SI-1** | Approval never ослабляется | EAP pre-authorizes specific action classes within scope; policy gates remain unchanged |
| **SI-2** | Scope-driven, no SSRF bypass | ScopeEngine + EAP targets-allowlist; third-party blocked |
| **SI-3** | Split-plane secrets | LLM sees `principal_id`/`secret_ref`; SessionStore resolves on exec layer only; mandatory redaction in evidence |
| **SI-4** | No shell execution | All actions declarative (argv-only); no `shell=True`, `eval`, imports |
| **SI-5** | No PayloadRegistry bypass | LLM payload'ы registered as dynamic entries + pass approval gates |
| **SI-6** | No prompt injection | External checklist text only in delimiters; no inline instructions |
| **SI-7** | Backward compatible | New FindingDTO fields Optional; legacy single-auth → owner principal; WSTG v4.2 replaces v2.0 |

---

## 📋 12 Base Scenarios (P5)

Все реализованы в `backend/config/playbooks/`:

```
✓ auth.direct-protected-route         (Authentication / low)
✓ mfa.direct-step-skip                (Authentication / high, approval)
✓ registration.duplicate-casefold     (Account Lifecycle / low)
✓ reset.token-reuse-after-password    (Account Lifecycle / high, approval)
✓ session.logout-invalidation         (Session Management / medium)
✓ idor.cross-user-read                (Authorization / low)
✓ idor.cross-user-write               (Authorization / medium)
✓ authorization.method-variant        (Authorization / low)
✓ massassignment.role-injection       (Authorization / high, approval)
✓ ratelimit.login-account-keyed       (Rate Limit / medium)
✓ ratelimit.otp-resend                (Rate Limit / low)
✓ race.single-use-token               (Race Conditions / high, approval)
```

**Each scenario includes:**
- Declarative YAML + Ed25519 signature
- Multi-principal support (owner, attacker, anon)
- Oracle assertion (authz, authn, rate_limit, race, business_logic)
- WSTG v4.2 test case mapping
- Evidence + cleanup

---

## 🧪 Testing Checklist

**Registry:**
```bash
✓ Registry loads fail-closed (unsigned/dupe/mismatch → RegistryLoadError)
✓ Signature verification passes (nuclei -validate in CI)
✓ No import cycles (test_no_cyclic_imports)
```

**Lifecycle:**
```bash
✓ Status transitions validated (allowed_transitions, validate_transition)
✓ reason_required on SKIPPED/REJECTED/CLEANUP_FAILED
✓ Terminal statuses have no outgoing edges
```

**Planner:**
```bash
✓ Applicability filtering (applies_when methods/paths/input_kinds)
✓ Principal availability checked
✓ Approval routing (HIGH/DESTRUCTIVE → WAITING_APPROVAL)
```

**Executor:**
```bash
✓ Multi-principal isolation (separate cookies per principal)
✓ Secrets not in logs/evidence (redaction test)
✓ Cleanup always runs (PARTIAL/REJECTED scenarios)
✓ Oracle deterministic (same input → same verdict)
```

**All 12 Playbooks:**
```bash
✓ Each scenario: CONFIRMED path (vulnerable mock target)
✓ Each scenario: REJECTED path (protected mock target)
✓ Coverage: pytest tests/integration/playbooks/ -v
```

---

## 🚀 How to Add a New Playbook

1. **Plan** (5 min)
   - Choose category (authorization, rate_limit, etc.)
   - Decide playbook_id (e.g., `race.condition-token-reuse`)
   - List required_principals + required_capabilities

2. **Write YAML** (20 min)
   - File: `backend/config/playbooks/<category>/<playbook_id>.yaml`
   - Declare steps (http_request, extract, compare, browser_action, wait, register_cleanup)
   - Add oracle assertions
   - Set risk_level + requires_approval (HIGH/DESTRUCTIVE → true)

3. **Sign** (2 min)
   ```bash
   cd backend
   python scripts/playbooks_sign.py --sign
   python scripts/playbooks_sign.py --verify
   ```

4. **Test** (30 min)
   - Write integration test in `tests/integration/playbooks/test_*.py`
   - Create MockHttpTransport with vulnerable + protected responses
   - Test both CONFIRMED (vulnerable) + REJECTED (protected) paths

5. **Commit** (2 min)
   - Include YAML + signed SIGNATURES + test code
   - Commit message: "Add playbook: <playbook_id> for <WSTG test case>"

---

## 📝 Payloads and Nuclei Integration

### Payload Registry (SI-5)

- Stored: `backend/config/payloads/*.yaml`
- Signed: Ed25519 via `backend/scripts/payloads_sign.py`
- Fail-closed: no inline payloads from LLM; all via registry

### Nuclei argus-* Templates

- Stored: `backend/config/nuclei-templates/argus/argus-*.yaml`
- Strict matchers: AND conditions + negative fixtures
- Safe argv: only hardcoded repo path, never user-supplied
- Validated: `nuclei -validate` in CI

---

## 🔗 Integration Points

### Pipeline Phases
1. **discovery** (LLM/static) → endpoints, capabilities, principals
2. **planning** (ScenarioPlanner) → filter playbooks by applicability
3. **execution** (ScenarioExecutor) → run steps, collect evidence
4. **confirmation** (oracle verdict) → CONFIRMED/REJECTED/INCONCLUSIVE
5. **evidence** (EvidenceBundle) → redacted baseline/mutated diff
6. **finding** (FindingDTO) → cross-reference scenario + WSTG
7. **report** (Midgard tier) → coverage matrix + findings

### External Integrations
- **PayloadRegistry** → scenarios use payload_family references (SI-5)
- **EngagementAuthorizationProfile (EAP)** → pre-authorizes action classes (SI-1)
- **PreflightChecker** → validates scope/ownership/policy/approval
- **SessionStore** → multi-principal isolation (SI-3)
- **Evidence redaction** → mandatory secret removal

---

## 🐛 Troubleshooting

| Issue | Cause | Solution |
|-------|-------|----------|
| `PlaybookSignatureError` | Playbook not signed | `python scripts/playbooks_sign.py --sign` |
| `RegistryLoadError: duplicate playbook_id` | Two files with same id | Rename file to match `playbook_id` in YAML |
| `ValidationError: params invalid` | Wrong action params | Check `HttpRequestParams`, `ExtractParams`, etc. |
| `SessionNotFoundError: attacker` | Principal not in SessionStore | Register principal before executor.run() |
| `OracleResult: INCONCLUSIVE` | Insufficient evidence | Adjust `sensitive_fields` in oracle params |

See **[Playbook Architecture Guide § Troubleshooting](playbooks-architecture.md#troubleshooting)** for details.

---

## 📚 Related Documentation

| Document | Purpose |
|----------|---------|
| [Auth Migration Guide](2026-07-22-auth-migration-guide.md) | Multi-principal model, split-plane secrets, back-compat |
| [Planning Document](2026-07-22-argus-pipeline-playbooks.md) | P1–P8 phases, dependency graph, security invariants |
| [API Contract](../../api-contracts.md) | Frontend ↔ Backend API schemas |
| [Security Model](../../security.md) | Overarching security design |
| [Reporting Guide](../../reporting.md) | Report generation, tier classification |

---

## 🎓 Key Concepts

### Stateful Multi-Step Scenarios (vs Stateless Injections)

- **InjectionPlanner** (old): flat list of parallel, stateless injects (argv-only)
- **ScenarioPlanner** (new): sequences of steps with shared session state, oracle assertions

### Fail-Closed Loading

- Any error (signature, schema, dupe, mismatch, bad oracle params) → **exception at startup**
- No silent skips; enables quick detection of config errors

### Oracle Verdicts

- **FINDING**: baseline vs mutated differ in sensitive ways → vulnerability likely
- **NO_FINDING**: attacker got 403/404 or responses identical → no vulnerability
- **INCONCLUSIVE**: uncertain (e.g., only volatile fields differ) → manual review

### Coverage Statuses

1. NOT_APPLICABLE (endpoint not applicable)
2. NOT_RUN (skipped due to budget/priority)
3. BLOCKED (approval pending, no principal, etc.)
4. PARTIAL (crashed mid-execution)
5. EXECUTED_NO_FINDING (ran, oracle: NO_FINDING)
6. CONFIRMED_FINDING (ran, oracle: FINDING ✓)
7. ERROR (exception during execution)

---

## 🔗 File Paths Summary

```
backend/
├─ src/playbooks/
│  ├─ schema.py              # Pydantic models
│  ├─ registry.py            # Fail-closed load + verify
│  ├─ lifecycle.py           # Status machine
│  ├─ planner.py             # ScenarioPlanner + applicability
│  ├─ executor.py            # Multi-principal executor
│  ├─ actions.py             # Step action implementations
│  ├─ oracles.py             # Oracle verdicts (authz, authn, rate_limit, etc.)
│  ├─ evidence.py            # Evidence collection + redaction
│  └─ cleanup.py             # Cleanup execution
│
├─ src/auth/
│  ├─ session_store.py       # PrincipalSession + SessionStore (SI-3)
│  └─ redaction.py           # Secret redaction helpers
│
├─ src/policy/
│  ├─ engagement_authorization.py  # EAP pre-authorization (SI-1)
│  ├─ preflight.py           # PreflightChecker (scope/ownership/policy/approval)
│  └─ audit.py               # Audit logging
│
├─ src/reports/
│  ├─ wstg_coverage.py       # WSTG v4.2 registry + coverage tracking
│  └─ scenario_coverage.py   # Scenario → WSTG mapping
│
├─ config/playbooks/
│  ├─ authentication/        # 2 playbooks
│  ├─ authorization/         # 4 playbooks
│  ├─ account_lifecycle/     # 2 playbooks
│  ├─ session_management/    # 1 playbook
│  ├─ rate_limit/           # 2 playbooks
│  ├─ race_conditions/      # 1 playbook
│  ├─ SIGNATURES            # Ed25519 signatures
│  └─ _keys/               # Dev signing keys (deleted before commit)
│
├─ config/nuclei-templates/
│  └─ argus/                # argus-*.yaml templates + provenance
│
├─ scripts/
│  └─ playbooks_sign.py     # Sign/verify playbooks (Ed25519)
│
└─ tests/integration/playbooks/
   ├─ conftest.py           # Fixtures + MockHttpTransport
   ├─ test_registry_load.py
   ├─ test_idor_cross_user.py
   ├─ test_auth_direct_protected.py
   ├─ test_race_single_use_token.py
   └─ ... (12 scenarios total)
```

---

## 📞 Questions?

- **Architecture:** See [Playbook Architecture Guide](playbooks-architecture.md)
- **Testing:** See [Integration Testing Guide](playbooks-integration-testing.md)
- **Coverage:** See [WSTG Coverage Guide](wstg-scenario-coverage.md)
- **Multi-principal:** See [Auth Migration Guide](2026-07-22-auth-migration-guide.md)
- **Overall plan:** See [Planning Document](2026-07-22-argus-pipeline-playbooks.md)

---

**Created:** 2026-07-22  
**Status:** Production Ready (P2–P4 ✓, P5–P7 in flight)  
**Last Updated:** 2026-07-22
