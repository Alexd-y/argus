# Kyverno cluster policies (ARG-054)

Cluster-side admission gates for the ARGUS platform. Currently ships one
policy:

| Policy | File | Purpose |
|--------|------|---------|
| `argus-require-signed-images` | `cluster-policy-require-signed-images.yaml` | Deny any Pod whose images are not Cosign-signed via GHA OIDC keyless and not pinned by `@sha256:<digest>`. |

## Manual apply

```bash
kubectl apply -f infra/kyverno/cluster-policy-require-signed-images.yaml
kubectl wait --for=condition=Ready --timeout=2m clusterpolicy/argus-require-signed-images
```

## Helm

The chart in `infra/helm/argus` renders this policy when
`policy.enabled=true` (default `false`). See `docs/admission-policy.md`
for the full operator runbook.

## CI

The kind-based `Admission policy (Kyverno + kind)` GitHub Actions
workflow (`.github/workflows/admission-policy-kind.yml`) verifies on
every PR that:

* Unsigned image (`nginx:1.27.0`) is denied with a non-zero RC.
* Signed-with-digest fixture image (built and `cosign sign --yes`-ed
  in the workflow itself via GHA OIDC) is admitted.

## References

* Plan: `ai_docs/develop/plans/2026-04-22-argus-cycle6-b5.md` (T42)
* Roadmap: `Backlog/dev1_finalization_roadmap.md` §Batch 5
* Operator runbook: `docs/admission-policy.md` (added in T45)
