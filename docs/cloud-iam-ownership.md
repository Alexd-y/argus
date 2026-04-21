# Cloud-IAM ownership verification

**Status:** production. **Owner:** ARGUS policy plane. **Last updated:** 2026-04-21 (ARG-043).
**Source of truth:** if this doc disagrees with `backend/src/policy/cloud_iam/` or
`backend/src/policy/ownership.py`, **the code wins**. Keep this file in sync.

ARGUS verifies that a tenant actually controls the cloud principal they
claim to own *before* any active scan touches a cloud resource. Three
verifiers ship in `backend/src/policy/cloud_iam/`:

| Method (enum)                              | Provider | Cloud-side proof                                                         | Module      |
| ------------------------------------------ | -------- | ------------------------------------------------------------------------ | ----------- |
| `OwnershipMethod.AWS_STS_ASSUME_ROLE`      | AWS      | `sts:AssumeRole` succeeds with the tenant's external-id challenge token. | `aws.py`    |
| `OwnershipMethod.GCP_SERVICE_ACCOUNT_JWT`  | GCP      | A self-signed SA JWT decodes with the expected `aud` + `argus_token`.    | `gcp.py`    |
| `OwnershipMethod.AZURE_MANAGED_IDENTITY`   | Azure    | `ManagedIdentityCredential.get_token` returns a token whose claims pin the expected `tid` / `oid` / `xms_mirid`. | `azure.py`  |

The three verifiers share a closed-taxonomy failure surface, a 5 s SDK
timeout, a 10 min sliding-window cache, audit-log discipline (hashed
identifiers only), and a strict NetworkPolicy egress allowlist.

---

## 1. Architecture

### 1.1 Layering

```
                 ┌──────────────────────────────────────────────┐
                 │  OwnershipVerifier (src/policy/ownership.py) │
                 │  • Constructor-injected dispatch table        │
                 │  • 10-minute sliding cache (per tenant+target)│
                 │  • Audit emission + cache-hit flag           │
                 └──────────────────┬───────────────────────────┘
                                    │ CloudOwnershipVerifierProtocol.verify(...)
            ┌───────────────────────┼─────────────────────────┐
            ▼                       ▼                         ▼
     AwsStsVerifier        GcpServiceAccountJwtVerifier   AzureManagedIdentityVerifier
   (cloud_iam/aws.py)        (cloud_iam/gcp.py)            (cloud_iam/azure.py)
            │                       │                         │
   StsClientProtocol         GcpIamProtocol               AzureCredentialProtocol
            │                       │                         │
            ▼                       ▼                         ▼
     BotoStsAdapter          GoogleAuthIamAdapter       AzureManagedIdentityAdapter
        (boto3)              (google.auth + iam)        (azure.identity)
```

Tests inject pure `Protocol` stubs (zero SDK imports); production wires
the `Boto*Adapter` / `*Adapter` classes that lazy-import the cloud SDK
inside their async call-site only — no module-level network deps.

### 1.2 Lifecycle of one `verify(challenge)` call

1. `OwnershipVerifier.verify` checks the challenge `method`. If it's a
   `CLOUD_IAM_METHODS` member, the dispatch path is taken; otherwise
   the legacy DNS / HTTP path runs unchanged (Cycle 1 behaviour).
2. The cache (`_cloud_cache`, keyed on `(tenant_id, method, target)`)
   is consulted. A live entry (`verified_at + CLOUD_IAM_TTL_S > utcnow`)
   short-circuits the SDK round-trip and emits an audit event with
   `payload.cache_hit = true`.
3. On cache miss the registered cloud verifier's `verify(challenge)` is
   awaited inside `asyncio.wait_for(..., timeout=CLOUD_SDK_TIMEOUT_S)`.
4. Success ⇒ returned `OwnershipProof` is persisted via the
   `OwnershipProofStore` AND inserted into the cache.
   Failure ⇒ `OwnershipVerificationError` re-raised with a closed-taxonomy
   `summary`; failures are **never** cached.
5. Either path emits exactly one `AuditEvent` with
   `event_type=OWNERSHIP_VERIFY`, hashed target, and the closed-taxonomy
   failure summary on denial.

### 1.3 Public constants (single source of truth)

`from src.policy.ownership import ...`

| Constant                  | Value                          | Purpose                                                             |
| ------------------------- | ------------------------------ | ------------------------------------------------------------------- |
| `CLOUD_IAM_TTL_S`         | `600` (10 min)                 | Sliding-window cache TTL. Externalised for tests and dashboards.    |
| `CLOUD_SDK_TIMEOUT_S`     | `5.0` s                        | Per-call upper bound for any cloud SDK round-trip.                  |
| `CLOUD_IAM_METHODS`       | `frozenset[OwnershipMethod]`   | Dispatch gate — used by the constructor and the request validator.  |
| `CLOUD_IAM_FAILURE_REASONS` | `frozenset[str]` (11 entries) | All cloud-IAM closed-taxonomy summaries (downstream filter helper). |

---

## 2. Per-cloud setup

### 2.1 AWS — `sts:AssumeRole` challenge

**Tenant input.** A target ARN of the form
`arn:aws:iam::<account>:role/<role-name>`. ARNs in `aws-cn` /
`aws-us-gov` partitions are accepted but the partition MUST match the
configured deployment region.

**Required IAM trust policy** (tenant-side):

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "AWS": "arn:aws:iam::<argus-account-id>:role/argus-ownership-verifier" },
    "Action": "sts:AssumeRole",
    "Condition": {
      "StringEquals": { "sts:ExternalId": "<challenge-token>" }
    }
  }]
}
```

The `<challenge-token>` is the 43-char URL-safe value ARGUS issued in
`OwnershipChallenge.token` (cryptographically-random 32 raw bytes).

**Closed-taxonomy outcomes** (raised as `OwnershipVerificationError`):

| Reason                                  | Trigger                                                                  |
| --------------------------------------- | ------------------------------------------------------------------------ |
| `ownership_aws_sts_invalid_arn`         | Target failed `arn:<partition>:iam::<account>:role/<name>` regex.        |
| `ownership_aws_sts_access_denied`       | `boto3.client.exceptions.AccessDenied` / `ValidationError`.              |
| `ownership_aws_sts_region_mismatch`     | Returned `AssumedRoleUser.Arn` partition disagrees with the requested ARN. |
| `ownership_aws_sts_timeout`             | SDK call exceeded `CLOUD_SDK_TIMEOUT_S`.                                 |

### 2.2 GCP — service-account JWT

**Tenant input.** The challenge `target` is `<sa-email>|<expected-aud>`,
e.g. `verifier@argus-prod.iam.gserviceaccount.com|https://ownership.argus.io/argus-prod`.

**Required IAM permissions** (tenant-side, on the SA being verified):

- `iam.serviceAccounts.signJwt` (granted via the
  `roles/iam.serviceAccountTokenCreator` role on the SA itself).
- The verifier project's principal MUST be allowed to call
  `iamcredentials.googleapis.com` (default for the standard role).

The verifier requests the SA to sign a JWT with the following payload:

```json
{
  "iss": "<sa-email>",
  "sub": "<sa-email>",
  "aud": "<expected-audience>",
  "argus_token": "<challenge-token>"
}
```

Signed JWT is decoded against Google's published certs URL. The
`argus_token` claim is compared in constant time to the original
`challenge.token` to avoid timing-based replay distinguishability.

**Closed-taxonomy outcomes:**

| Reason                                            | Trigger                                                                  |
| ------------------------------------------------- | ------------------------------------------------------------------------ |
| `ownership_gcp_sa_jwt_invalid_audience`           | `aud` claim ≠ requested audience, or `sub`/`iss` ≠ SA email, or `argus_token` mismatch. |
| `ownership_gcp_sa_jwt_expired_or_not_yet_valid`   | `exp` ≤ now, `iat` > now + 5 s skew, `nbf` > now + 5 s skew, or `signJwt` ImportError. |
| `ownership_gcp_sa_jwt_timeout`                    | SDK call exceeded `CLOUD_SDK_TIMEOUT_S`.                                 |

### 2.3 Azure — Managed-identity claims pin

**Tenant input.** The challenge `target` is
`<tenant-id>|<object-id>|<mi-resource-id>`, e.g.

```
11111111-2222-3333-4444-555555555555|aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee|/subscriptions/00.../resourcegroups/argus/providers/microsoft.managedidentity/userassignedidentities/argus-prod-mi
```

The Azure SDK's `ManagedIdentityCredential.get_token` is invoked with
the configured `scope` (default `https://management.azure.com/.default`)
and a `client_request_id` set to the challenge token (so attempts are
correlatable in Entra audit logs without leaking the value to ARGUS
audit events).

The returned access token's claims are decoded (no signature check —
the credential SDK enforces RSA validation) and the verifier asserts
all three of:

- `claims["tid"]` (== `clams.aud_tid`) equals the expected tenant id.
- `claims["oid"]` equals the expected object id.
- `claims["xms_mirid"]` (case-insensitively) equals the expected MI ARM
  resource id.

**Closed-taxonomy outcomes:**

| Reason                                       | Trigger                                                                  |
| -------------------------------------------- | ------------------------------------------------------------------------ |
| `ownership_azure_mi_tenant_mismatch`         | `tid` claim ≠ expected tenant id.                                        |
| `ownership_azure_mi_resource_not_owned`      | `oid` ≠ expected object-id, or `xms_mirid` ≠ expected MI resource id.    |
| `ownership_azure_mi_token_refresh_failed`    | `azure.core.exceptions.AzureError`, missing token, or unexpected SDK exception. |
| `ownership_azure_mi_timeout`                 | SDK call exceeded `CLOUD_SDK_TIMEOUT_S`.                                 |

---

## 3. NetworkPolicy egress allowlists

Each cloud verifier requires a Kubernetes `NetworkPolicy` that
constrains backend pods to talk **only** to the relevant cloud control
plane on port 443 (plus DNS to coredns). The three policies live in
`infra/k8s/networkpolicies/` and target pods labeled
`app: argus-backend` AND `cloud-iam: enabled`.

| Manifest                                         | Allowed FQDNs (annotated, IP-pinned)                                                        |
| ------------------------------------------------ | ------------------------------------------------------------------------------------------- |
| `infra/k8s/networkpolicies/cloud-aws.yaml`       | `sts.amazonaws.com`, `iam.amazonaws.com`, regional `sts.<region>.amazonaws.com`.            |
| `infra/k8s/networkpolicies/cloud-gcp.yaml`       | `oauth2.googleapis.com`, `iamcredentials.googleapis.com`, `iam.googleapis.com`, `www.googleapis.com`. |
| `infra/k8s/networkpolicies/cloud-azure.yaml`     | `login.microsoftonline.com`, `login.windows.net`, `management.azure.com`.                    |

Hard invariants enforced by `tests/security/test_cloud_iam_no_secret_leak.py::TestNetworkPolicyEgressAllowlists`:

1. **No `0.0.0.0/0`** in any structural rule (only DNS to kube-dns + the
   pinned cloud control-plane CIDRs).
2. **No `namespaceSelector: {}`** wildcards.
3. **No `- to: []`** (open egress).
4. Egress ports MUST be in `{443, 53}` only.
5. Pod selector MUST require both `app: argus-backend` AND
   `cloud-iam: enabled`. The latter label is an opt-in deployment toggle
   so pods that don't talk to cloud IAM never inherit this policy.
6. IMDS endpoint (`169.254.169.254`) is unreachable — pods carry the
   ARG-027 deny-private-CIDR baseline, which the cloud-iam policy
   *adds to* rather than replaces.

To deploy with cloud verification enabled, label the backend `Deployment`:

```yaml
spec:
  template:
    metadata:
      labels:
        app: argus-backend
        cloud-iam: enabled
```

---

## 4. Audit-log schema

Every verification attempt — success, failure, or cache hit — emits
exactly one `AuditEvent` (`event_type=OWNERSHIP_VERIFY`). The payload
schema is **strict** and validated by
`backend/src/policy/audit.py::AuditLogger._coerce_payload`:

| Field                       | Type         | Notes                                                                          |
| --------------------------- | ------------ | ------------------------------------------------------------------------------ |
| `decision_allowed`          | `bool`       | True iff verification succeeded.                                               |
| `failure_summary`           | `str | None` | Closed-taxonomy reason (only on denial). Capped to 64 chars by Pydantic.       |
| `payload.cloud_provider`    | `str`        | One of `"aws"`, `"gcp"`, `"azure"`.                                            |
| `payload.principal_kind`    | `str`        | `"role_arn"` / `"service_account"` / `"managed_identity_object_id"`, etc.      |
| `payload.principal_hash`    | `str`        | `hash_identifier(principal_id)` — SHA-256 truncated to 16 hex chars.           |
| `payload.target_hash`       | `str`        | `hash_identifier(challenge.target)` — same primitive.                          |
| `payload.method`            | `str`        | The `OwnershipMethod.value`.                                                   |
| `payload.cache_hit`         | `bool`       | True iff served by `OwnershipVerifier._cloud_cache`.                            |
| `payload.attempt_at_ts`     | `str` (ISO8601) | UTC timestamp of the SDK round-trip start.                                  |

**Forbidden in `payload.extra`** (all rejected at runtime by
`emit_cloud_attempt`):

```
principal_arn, principal_email, token, jwt, external_id,
client_secret, access_token, id_token, raw_response
```

The closed taxonomy means dashboards / SIEMs can build deterministic
queries without lexer hell:

```sql
SELECT count(*) FROM audit_events
WHERE event_type = 'OWNERSHIP_VERIFY'
  AND failure_summary = 'ownership_aws_sts_access_denied'
  AND occurred_at > now() - interval '1 day';
```

The chain hash (`AuditEvent.event_hash`) is computed over the fully
sanitised payload — no raw secret values can leak into the immutable
trail even if the upstream caller smuggles one into `extra`.

---

## 5. Operator runbook

### 5.1 "All my cloud verifications time out"

1. Check the egress NetworkPolicy is bound — pod label MUST include
   `cloud-iam: enabled`. Without it, pods inherit only the
   ARG-027 deny-by-default policy and ALL cloud egress is dropped at
   ingress to the host.
2. Verify the cloud control-plane FQDNs resolve via the cluster
   resolver (`kubectl exec ... -- nslookup sts.amazonaws.com`).
3. Look for `ownership_*_timeout` events in the audit log; the count
   should match the SDK-call-count Prometheus metric (when ARG-041
   ships).

### 5.2 "Tenant claims `access_denied`, but ARN is correct"

The closed taxonomy hides the cloud SDK's free-form error message **on
purpose** — both for security (no SDK string leaks) and for stable
analytics. To diagnose:

1. In a fresh shell with the boto3 SDK and the tenant's role, run:
   ```bash
   aws sts assume-role \
     --role-arn arn:aws:iam::<acct>:role/<role> \
     --role-session-name argus-debug \
     --external-id <copy from tenant>
   ```
2. The verbose CLI output reveals whether the trust policy or the
   external-id is the culprit.
3. Confirm tenant's IAM trust policy includes
   `Condition.StringEquals."sts:ExternalId" = <token>`.

### 5.3 "GCP JWT verification keeps failing with `invalid_audience`"

1. Decode the token client-side (`jwt.io`); compare `aud` claim
   against the second half of the challenge target
   (`<sa-email>|<aud>`). Any trailing slash, scheme, or path mismatch
   triggers `ownership_gcp_sa_jwt_invalid_audience`.
2. Confirm the verifier service account has
   `iam.serviceAccounts.signJwt` permission AND that the SA being
   verified is the same one whose key signed the JWT (`iss == sub == sa-email`).

### 5.4 "Azure MI token refresh fails sporadically"

`ownership_azure_mi_token_refresh_failed` is the catch-all for
`AzureError` and unexpected SDK exceptions. Classic causes:

1. Backend pod is *not* on a node with a system-assigned MI / the
   user-assigned MI is *not* attached to the node — check
   `kubectl get pod <argus-backend> -o yaml` for `nodeSelector`
   and confirm the node's MI matches the configured one.
2. IMDS endpoint reachability is by design **denied** at the
   NetworkPolicy layer (defence-in-depth). Use the explicit MI ARM
   resource id (`xms_mirid` claim) to point the SDK at the Entra
   federated endpoint instead.

### 5.5 Cache invalidation (manual)

Two ways:

```python
# Drop everything (rare — used by tests + on cred-rotation events).
verifier.cloud_cache_clear()

# Per tenant + target (programmatic — used by the rotation webhook).
# The dispatch layer doesn't expose a per-key API yet; ARG-049 will
# add `verifier.cloud_cache_evict(tenant_id, target, method)`.
```

For ad-hoc rotation, restart the backend pods (`kubectl rollout restart
deploy/argus-backend`); the cache is process-local.

---

## 6. Security guarantees (what we promise to tenants)

1. **No raw secrets, ever.** Audit payloads carry only SHA-256 truncated
   identifier hashes. Tokens, ARNs, SA emails, JWTs, oid/tid claims, and
   access tokens are never written to disk or to the audit chain. The
   `tests/security/test_cloud_iam_no_secret_leak.py` suite (24+ cases)
   parametrically asserts this invariant for every verifier on every
   success/failure branch.
2. **Closed taxonomy.** Eleven well-known reasons (`CLOUD_IAM_FAILURE_REASONS`)
   surface to operators / dashboards. SDK-side strings, stack traces,
   and exception messages never propagate. Static check in
   `TestClosedTaxonomy::test_modules_only_emit_taxonomy_reasons` greps
   the verifier modules for `OwnershipVerificationError("...")` literal
   leaks.
3. **Constant-time comparisons.** Token, JWT `argus_token`, Azure
   tenant/oid/mi pins use `hmac.compare_digest` to neutralise timing
   side-channels (`tests/unit/policy/cloud_iam/test_common.py::TestConstantTimeAndRedaction`).
4. **Bounded SDK calls.** `CLOUD_SDK_TIMEOUT_S = 5.0 s` is enforced by
   `_common.run_with_timeout`; a malicious cloud-side responder cannot
   stall ARGUS request handlers indefinitely.
5. **Strict NetworkPolicy egress.** No wildcards in any allowlist; the
   three cloud-cohort policies pin to documented FQDNs and never reach
   IMDS or other internal endpoints.
6. **Failures never cached.** Only successful proofs go into
   `_cloud_cache`. A flapping cloud principal cannot trick ARGUS into
   serving a stale denial.
7. **Cache is per `(tenant_id, method, target)`.** Cross-tenant cache
   poisoning is structurally impossible — proven by
   `test_cloud_iam_ownership.py::TestCloudCache::test_cache_keyed_per_tenant`.

---

## 7. Adding a new cloud verifier

(Future work — sketch only.)

1. Add the enum member to `OwnershipMethod` and to `CLOUD_IAM_METHODS`.
2. Define its closed-taxonomy `REASON_*` constants in
   `ownership.py` and add them to `CLOUD_IAM_FAILURE_REASONS`.
3. Implement `cloud_iam/<provider>.py`:
   - `class <Provider>VerifierProtocol(Protocol)` — DI seam.
   - `class <Provider>Adapter` — wraps the real SDK.
   - `class <Provider>Verifier` — the public verifier; must follow the
     three existing examples for audit emission, timeouts, and
     constant-time comparisons.
4. Re-export from `cloud_iam/__init__.py`.
5. Add `infra/k8s/networkpolicies/cloud-<provider>.yaml` with FQDN
   annotations and IP-pinned egress on 443 only.
6. Mirror the four existing test files in
   `tests/unit/policy/cloud_iam/`, the integration coverage in
   `tests/integration/policy/test_cloud_iam_ownership.py`, and the
   security gates in `tests/security/test_cloud_iam_no_secret_leak.py`.
7. Update this document.

---

## 8. References

- Code: `backend/src/policy/cloud_iam/{__init__,_common,aws,gcp,azure}.py`
  and `backend/src/policy/ownership.py` (dispatch + cache).
- NetworkPolicies: `infra/k8s/networkpolicies/cloud-{aws,gcp,azure}.yaml`.
- Tests:
  - Unit: `backend/tests/unit/policy/cloud_iam/test_{common,aws,gcp,azure}.py`.
  - Integration: `backend/tests/integration/policy/test_cloud_iam_ownership.py`.
  - Security: `backend/tests/security/test_cloud_iam_no_secret_leak.py`.
- Sister doc on baseline egress: [`docs/network-policies.md`](network-policies.md).
- Plan: `ai_docs/develop/plans/2026-04-21-arg-043-cloud-iam-ownership.md`.
- Worker report: `ai_docs/develop/reports/2026-04-21-arg-043-cloud-iam-ownership-report.md`.
