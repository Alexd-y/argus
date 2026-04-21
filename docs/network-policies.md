# NetworkPolicy templates and per-tool overrides

Status: production. Owner: ARGUS sandbox. Last updated: 2026-04-19 (ARG-027).

The ARGUS sandbox driver applies a Kubernetes `NetworkPolicy` (apiVersion
`networking.k8s.io/v1`) alongside every `Job` it submits. The policy is
selected by the per-tool YAML in `backend/config/tools/*.yaml` via the
`network_policy` block; the `name` field MUST resolve to one of the eleven
templates registered in `backend/src/sandbox/network_policies.py`.

This document is the single source of truth for:

1. The eleven registered templates and what they permit.
2. The two per-tool override surfaces (`dns_resolvers`, `egress_allowlist`)
   and their validation rules.
3. The defence-in-depth invariants enforced unconditionally by the renderer.

If a section here disagrees with the code, **the code wins** — keep this
file in sync.

---

## 1. The eleven templates

`NETWORK_POLICY_NAMES` (in `network_policies.py`) is a frozen set; adding
or removing a template requires a code change AND a coverage matrix
update (`tests/test_tool_catalog_coverage.py`). The current set is:

| Name                | Egress target                                                                  | TCP ports                                                                                                                                                                | UDP ports             | Notes                                                                                                                                          |
| ------------------- | ------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| `recon-passive`     | `0.0.0.0/0` minus private + IMDS                                               | 80, 443                                                                                                                                                                  | —                     | Passive recon (OSINT APIs, CT logs, WHOIS, RDAP). The wildcard peer carries the mandatory deny exceptions injected by the renderer (ARG-027). |
| `recon-active-tcp`  | per-job target CIDR (dynamic)                                                  | 1–65 535 (port range)                                                                                                                                                    | —                     | Full TCP sweep against the resolved target only.                                                                                               |
| `recon-active-udp`  | per-job target CIDR (dynamic)                                                  | —                                                                                                                                                                        | 53, 67, 68, 69, 123, 161, 500, 1900, 5353 | UDP top-100 probes against the per-job target only.                                                                                            |
| `recon-smb`         | per-job target CIDR (dynamic)                                                  | 135, 139, 445                                                                                                                                                            | 137, 138              | smbmap / enum4linux-ng / rpcclient.                                                                                                            |
| `tls-handshake`     | per-job target CIDR (dynamic)                                                  | 443                                                                                                                                                                      | —                     | testssl / sslyze / sslscan / tlsx / nmap ssl-enum.                                                                                             |
| `oast-egress`       | dedicated OAST plane `10.244.250.0/24` + per-job target CIDR (dynamic)         | 25, 53, 80, 443, 587, 8080, 8443 + 1–65 535 (range against the target)                                                                                                   | 53                    | interactsh / oastify clients + SSRF probes (ARG-017 §4.11).                                                                                    |
| `auth-bruteforce`   | per-job target CIDR (dynamic)                                                  | 21, 22, 23, 25, 53, 88, 110, 135, 139, 143, 389, 443, 445, 465, 587, 636, 993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 5985, 5986, 6379, 27017                    | 53, 88, 137, 161, 500 | hydra / medusa / patator / ncrack / cme / kerbrute / smbclient / snmp-check / evil-winrm / redis_cli_probe / mongodb_probe (ARG-017 §4.12 + ARG-019 §4.17). |
| `offline-no-egress` | none                                                                           | —                                                                                                                                                                        | —                     | hashcat / john / ophcrack / hashid / hash_analyzer. **No DNS, no egress.** Defence-in-depth against malicious wordlist / rule packs.                              |
| `cloud-aws`         | `0.0.0.0/0` minus private + IMDS                                               | 443                                                                                                                                                                      | —                     | prowler / scoutsuite / cloudsploit / pacu. FQDN intent: `*.amazonaws.com`, `*.aws.amazon.com`, `*.s3.amazonaws.com`, `*.cloudfront.net`.       |
| `cloud-gcp`         | `0.0.0.0/0` minus private + IMDS                                               | 443                                                                                                                                                                      | —                     | FQDN intent: `*.googleapis.com`, `*.gcr.io`, `*.pkg.dev`, `*.cloudfunctions.net`, `metadata.google.internal`.                                  |
| `cloud-azure`       | `0.0.0.0/0` minus private + IMDS                                               | 443                                                                                                                                                                      | —                     | FQDN intent: `*.azure.com`, `*.azurewebsites.net`, `*.azure.net`, `*.windows.net`, `management.azure.com`.                                     |

All templates also open DNS (UDP/53 + TCP/53) to the pinned resolvers
(`1.1.1.1`, `9.9.9.9` by default), except `offline-no-egress` which sets
`dns_resolvers: []`.

Ingress is **always** denied (`policyTypes: ["Ingress", "Egress"]` with
an empty `ingress` array).

### "Private + IMDS" deny block

The renderer treats the following CIDRs as the canonical denylist; any
wildcard peer (`0.0.0.0/0` or IPv6 `::/0`) and every cloud-parity
template carries them as `ipBlock.except`:

- `10.0.0.0/8`
- `172.16.0.0/12`
- `192.168.0.0/16`
- `169.254.169.254/32` (called out separately so error messages mention
  the cloud metadata SSRF target by name)
- `169.254.0.0/16` (catches the rest of the link-local block)

---

## 2. Per-tool overrides

Two fields on `NetworkPolicyRef` (in `backend/src/sandbox/adapter_base.py`)
let a tool YAML widen the policy without editing the template:

```yaml
network_policy:
  name: cloud-aws
  dns_resolvers:                # override (replace)
    - "8.8.8.8"
  egress_allowlist:             # override (union)
    - "203.0.113.0/24"
    - "api.partner.example.com"
```

| Field             | Semantics                                                                                                                                                                                                                                                                                | Validation                                                                                                                                                                                                                                                                                                                                                          |
| ----------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `dns_resolvers`   | When non-empty **replaces** the template's `dns_resolvers`. When empty / absent the template default (`1.1.1.1`, `9.9.9.9`) is used. Order is preserved, duplicates collapse.                                                                                                            | Each entry MUST be an IPv4 / IPv6 literal or CIDR. **FQDNs are rejected** (NetworkPolicy v1 ipBlock cannot match on DNS names). Entries that overlap `10/8`, `172.16/12`, `192.168/16`, `169.254.169.254/32` or `169.254/16` are rejected (`ValueError` at render time, translated to `SandboxConfigError` by `KubernetesSandboxAdapter`).                                                          |
| `egress_allowlist`| **Unioned** with `template.egress_allowlist_static` (additive — never replaces). FQDN-style entries are surfaced via the `argus.io/egress-fqdns` annotation; CIDR / IP entries are appended to the `to.ipBlock` peer list. Order is preserved, duplicates collapse.                          | Same denylist as `dns_resolvers`, with one exception: the wildcard `0.0.0.0/0` (and IPv6 `::/0`) IS accepted because the renderer auto-attaches the private + IMDS deny exceptions to every wildcard peer (defence-in-depth). FQDN entries (any string starting with a letter or `*`) bypass IP validation and are rendered as documentation only. Garbage strings (`198.51.100.5/99`, etc.) fail with `not a valid CIDR / IP / FQDN`. |

### Worked example

Tool YAML:

```yaml
network_policy:
  name: cloud-aws
  dns_resolvers: []                     # use template defaults
  egress_allowlist:
    - "0.0.0.0/0"                       # accepted; renderer enforces deny exceptions
    - "203.0.113.42/32"                 # accepted
    - "api.partner.example.com"         # → annotation (FQDN-aware controllers will enforce)
```

Rendered manifest (abridged):

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: cloud-aws-7f3c1ea4
  namespace: argus-sandbox
  labels:
    app.kubernetes.io/name: argus-sandbox
    app.kubernetes.io/component: network-policy
    argus.io/template: cloud-aws
  annotations:
    argus.io/egress-fqdns: "*.amazonaws.com,*.aws.amazon.com,*.s3.amazonaws.com,*.cloudfront.net,api.partner.example.com"
spec:
  podSelector:
    matchLabels:
      argus.io/job-id: 7f3c1ea4-…
  policyTypes: ["Ingress", "Egress"]
  ingress: []
  egress:
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0
            except:
              - 10.0.0.0/8
              - 172.16.0.0/12
              - 192.168.0.0/16
              - 169.254.169.254/32
              - 169.254.0.0/16
        - ipBlock:
            cidr: 203.0.113.42/32
      ports:
        - protocol: TCP
          port: 443
    - to:
        - ipBlock: { cidr: 1.1.1.1/32 }
        - ipBlock: { cidr: 9.9.9.9/32 }
      ports:
        - protocol: UDP
          port: 53
        - protocol: TCP
          port: 53
```

### Negative examples (rendered as `SandboxConfigError`)

```yaml
# 1) Pinning DNS to the EC2 / Azure / GCP metadata service:
network_policy:
  name: cloud-aws
  dns_resolvers: ["169.254.169.254"]
# → SandboxConfigError: NetworkPolicy override rejected for tool_id='…':
#   dns_resolvers entry '169.254.169.254' overlaps a private / IMDS deny range …

# 2) Pinning DNS to a FQDN (NetworkPolicy v1 cannot enforce that):
network_policy:
  name: recon-passive
  dns_resolvers: ["dns.example.com"]
# → SandboxConfigError: dns_resolvers entry 'dns.example.com' must be a valid
#   IP / CIDR (FQDNs are not allowed for resolver pinning …)

# 3) Widening egress onto an intra-cluster pod range:
network_policy:
  name: recon-passive
  egress_allowlist: ["10.244.0.0/16"]
# → SandboxConfigError: egress_allowlist_override entry '10.244.0.0/16' overlaps
#   a private / IMDS deny range …

# 4) Garbage CIDR:
network_policy:
  name: recon-passive
  egress_allowlist: ["198.51.100.5/99"]
# → SandboxConfigError: egress_allowlist_override entry '198.51.100.5/99' is
#   not a valid CIDR / IP / FQDN
```

---

## 3. Defence-in-depth invariants

These hold for every rendered NetworkPolicy regardless of how the
upstream YAML is configured:

1. **Ingress is always denied.** `policyTypes` always lists `Ingress`
   AND `Egress`; the `ingress` array is always empty.
2. **Pod isolation.** `spec.podSelector.matchLabels` always includes
   the per-job `argus.io/job-id` label so the policy applies to a
   single Job's pod(s) and never to its neighbours.
3. **No wildcard egress without exceptions.** Every `ipBlock` peer
   whose `cidr` resolves to `0.0.0.0/0` (or IPv6 `::/0`) is rendered
   with the private + IMDS deny list as `except`. This is enforced in
   `_build_ip_block_peer` and applies to template-static peers,
   override peers, and any future code path that reaches the helper.
4. **Per-job uniqueness.** The metadata `name` is suffixed with the
   first 8 hex chars of the Job UUID so concurrent runs of the same
   template don't collide on the K8s API server.
5. **DNS pinning is auditable.** Resolvers are always IP literals (FQDN
   resolvers rejected at validation). The default set is Cloudflare
   (`1.1.1.1`) and Quad9 (`9.9.9.9`); overrides must clear the same
   denylist gate.
6. **FQDN intent is documented, not enforced.** Vanilla NetworkPolicy v1
   does not match on DNS names. The `egress_allowed_fqdns` template
   field and FQDN entries from `egress_allowlist` overrides are
   rendered into the `argus.io/egress-fqdns` annotation so:
   - Audit tooling can diff intended vs. actual reachability;
   - A future Cilium / Calico FQDN-aware policy can pick the list up
     and enforce it without re-parsing YAMLs.

---

## 4. Where overrides flow in the code

```
backend/config/tools/<tool>.yaml
        │  network_policy: { name, dns_resolvers, egress_allowlist }
        ▼
ToolDescriptor.network_policy: NetworkPolicyRef          (adapter_base.py)
        │
        ▼
KubernetesSandboxAdapter.build_networkpolicy_manifest    (k8s_adapter.py)
        │  resolves the template via get_template(name)
        ▼
manifest.build_networkpolicy_for_job                     (manifest.py)
        │  passes overrides through verbatim
        ▼
network_policies.render_networkpolicy_manifest           (network_policies.py)
        │  validates + dedupes + renders → dict
        ▼
KubernetesSandboxAdapter.apply_networkpolicy             (k8s_adapter.py)
        │  serialises → NetworkingV1Api.create_namespaced_network_policy
        ▼
            kube-apiserver  →  CNI enforcement
```

`render_networkpolicy_manifest` is pure (no I/O, no K8s client) so the
same code path drives unit tests, the `--dry-run` CLI mode, and
production cluster deployment.

---

## 5. Adding a new template

1. Add the name to `NETWORK_POLICY_NAMES` in
   `backend/src/sandbox/network_policies.py`.
2. Construct it in `_build_seed_templates()`. Use
   `egress_allowlist_static` + `egress_except_cidrs` for cloud-style
   wildcard egress; use `egress_target_dynamic=True` for active-recon
   templates that pin to the per-job target.
3. Add a unit test in
   `backend/tests/unit/sandbox/test_network_policies.py` asserting
   the rendered `to.ipBlock` shape, the DNS rule, the ingress block,
   and any FQDN annotation.
4. Update this document's table.
5. Re-run `python -m mypy --strict backend/src/sandbox/network_policies.py`
   and `python -m ruff check + format backend/src/sandbox/network_policies.py`.
6. Update the coverage matrix expectation in
   `backend/tests/test_tool_catalog_coverage.py` if applicable.

---

## 6. Related references

- Code: `backend/src/sandbox/network_policies.py`,
  `backend/src/sandbox/manifest.py`,
  `backend/src/sandbox/k8s_adapter.py`.
- Tests: `backend/tests/unit/sandbox/test_network_policies.py`,
  `backend/tests/integration/sandbox/test_network_policy_overrides.py`.
- Backlog: ARG-003 (initial template seed), ARG-017 (oast-egress,
  auth-bruteforce, offline-no-egress), ARG-019 (override field
  surface), ARG-027 (cloud-* templates + override consumption).
