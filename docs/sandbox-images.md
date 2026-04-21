# Sandbox container images

Status: production CI-gated (Cycle 4 / ARG-034). Owner: ARGUS sandbox. Last updated: 2026-04-20.

The ARGUS sandbox driver runs every tool inside a one-shot Kubernetes
`Job` whose container image is one of the four "sandbox images" maintained
in `sandbox/images/`. This document is the single source of truth for:

1. The four image profiles, what tools each ships, and the pinned version
   matrix.
2. The hardening contract enforced statically by
   `backend/tests/integration/sandbox/test_image_security_contract.py`.
3. The SBOM regeneration recipe (CycloneDX 1.5 JSON at
   `/usr/share/doc/sbom.cdx.json`).
4. The Cosign signing recipe (skeleton in Cycle 3 — Cosign keyless +
   Sigstore Fulcio + Rekor wired up by ARG-033 in Cycle 4).
5. Local build + sign helpers in `infra/scripts/`.
6. **CI image build + push to GHCR** (ARG-034).
7. **Trivy blocking scan policy** + `.trivyignore` curation rules
   (ARG-034).
8. **Branch protection requirements** for `main` (ARG-034).

If a section here disagrees with the code, **the code wins** — keep this
file in sync.

---

## 1. Image profile matrix

Every tool YAML in `backend/config/tools/*.yaml` declares an `image:` field.
The six profiles below correspond to the six `Dockerfile`s under
`sandbox/images/`. ARG-048 (Cycle 5) closed the long-standing
`argus-kali-recon` + `argus-kali-network` gap; the catalog still references
one **future** profile — `argus-kali-binary` (5 tools: apktool, binwalk,
jadx, radare2_info, mobsf_api) — that is not yet built and currently falls
back to `argus-kali-full` at runtime via the slim → full alias rule
documented in `backend/src/sandbox/image_resolver.py`.

| Profile | Dockerfile | Tools (count) | Backlog sections | Base image |
|---------|------------|---------------|------------------|------------|
| `web` | `sandbox/images/argus-kali-web/Dockerfile` | 87 | §4.4–§4.14 (HTTP fingerprint, content discovery, crawlers, CMS, web-VA, SQLi, XSS, SSRF/OAST, auth, API) + §4.17 (network protocol allowlist subset) | `kalilinux/kali-rolling:2026.1` |
| `cloud` | `sandbox/images/argus-kali-cloud/Dockerfile` | 26 | §4.13 (heavyweight crackers offloaded from web) + §4.15 (cloud auditing) + §4.16 (IaC / SAST / SCA) | `kalilinux/kali-rolling:2026.1` |
| `browser` | `sandbox/images/argus-kali-browser/Dockerfile` | 6 | §4.19 (Playwright + Chromium browser tooling) | `kalilinux/kali-rolling:2026.1` |
| `full` | `sandbox/images/argus-kali-full/Dockerfile` | superset | §4.18 (binary / mobile / firmware) + safety-net for any tool not yet ported to a slim profile | `kalilinux/kali-rolling:2026.1` |
| `recon` | `sandbox/images/argus-kali-recon/Dockerfile` | 29 | §4.1 (passive recon: subfinder, amass, theHarvester, whois, dnsrecon, fierce, censys, shodan, urlscan, otx, securitytrails, github_search, crt_sh, findomain, assetfinder, chaos, dnsx) + §4.2 (active recon: nmap, masscan, naabu, rustscan, unicornscan, smbmap, rpcclient_enum, enum4linux_ng) | `kalilinux/kali-rolling:2026.1` |
| `network` | `sandbox/images/argus-kali-network/Dockerfile` | 18 | §4.17 (network protocol exploitation: snmpwalk, onesixtyone, ldapsearch, smbclient, responder, impacket-* suite, ike-scan, redis-cli, mongodb shell, kerbrute, bloodhound-python) | `kalilinux/kali-rolling:2026.1` |

### 1.1 Pinned tool versions

Pinning is **strict** in the three slim images and **relaxed** in `full`
(the safety-net image trades reproducibility for breadth).

> **Caveat:** the per-tool YAMLs in `backend/config/tools/` do **not**
> currently expose a `version:` field — see follow-up issue
> `ai_docs/develop/issues/ISS-CYCLE3-tool-yaml-version-field.md` (created
> by ARG-026). Until the schema lands, this table is the authoritative
> mapping of pinned versions per image.

#### `argus-kali-web`

| Tool | Pinned version | Source |
|------|----------------|--------|
| httpx (ProjectDiscovery) | `v1.6.10` | `go install` |
| nuclei | `v3.7.1` | `go install` |
| katana | `v1.1.2` | `go install` |
| gospider | `v1.1.6` | `go install` |
| gau | `v2.2.4` | `go install` |
| hakrawler | `v1.0.2` | `go install` |
| waybackurls | `v0.0.0-20230213113616-15ddc3e7e273` | `go install` |
| ffuf | `v2.1.0` | `go install` |
| gobuster | `v3.6.0` | `go install` |
| gowitness | `v3.0.5` | `go install` |
| webanalyze | `v0.4.0` | `go install` |
| tlsx | `v1.1.7` | `go install` |
| dalfox | `v2.10.0` | `go install` |
| kxss | `v0.0.0-20230331131133-7e4a37ce9e9b` | `go install` |
| subjs | `v1.0.4` | `go install` |
| interactsh-client | `v1.2.0` | `go install` |
| jarm | `0.1.5` | `pip install --user` |
| arjun | `2.2.2` | `pip install --user` |
| paramspider | `1.0.0` | `pip install --user` |
| dirsearch | `0.4.3` | `pip install --user` |
| wfuzz | `3.1.0` | `pip install --user` |
| sqlmap | `1.9` | `pip install --user` |
| XSStrike | `3.1.5` | `pip install --user` |
| impacket | `0.12.0` | `pip install --user` |
| bloodhound | `1.7.2` | `pip install --user` |
| crackmapexec | `5.4.0` | `pip install --user` |
| evil-winrm-py | `0.5.0` | `pip install --user` |
| graphw00f | `1.1.13` | `pip install --user` |
| clairvoyance | `2.6.0` | `pip install --user` |
| wpscan | `3.8.27` | `gem install` |
| wappalyzer (npm) | `7.0.3` | `npm install` |
| retire (npm) | `5.2.7` | `npm install` |
| whatweb / nikto / wapiti / skipfish / xsser / hydra / medusa / ncrack / john / hashcat / smbclient / snmp / ldap-utils / ike-scan / onesixtyone / responder / impacket-scripts / sslscan / sslyze / testssl.sh | apt rolling | `apt-get install` |

#### `argus-kali-cloud`

| Tool | Pinned version | Source |
|------|----------------|--------|
| trivy | `v0.70.0` | `go install` |
| syft | `v1.42.4` | `go install` |
| grype | `v0.92.0` | `go install` |
| tfsec | `v1.28.13` | `go install` |
| kube-bench | `v0.10.4` | `go install` |
| gitleaks | `v8.21.4` | `go install` |
| dockle | `v0.4.14` | `go install` |
| trufflehog | `v3.84.2` | release tarball |
| kics | `v2.1.6` | release tarball |
| terrascan | `v1.19.9` | release tarball |
| prowler | `5.20.0` | `pip install --user` |
| scoutsuite | `5.14.0` | `pip install --user` |
| pacu | `1.6.1` | `pip install --user` |
| cloudsplaining | `0.7.0` | `pip install --user` |
| cloudsplit | `0.6.0` | `pip install --user` |
| kube-hunter | `0.6.10` | `pip install --user` |
| semgrep | `1.99.0` | `pip install --user` |
| bandit | `1.8.0` | `pip install --user` |
| checkov | `3.2.382` | `pip install --user` |
| detect-secrets | `1.5.0` | `pip install --user` |
| cloudsploit (npm) | `1.0.0` | `npm install` |
| john / hashcat / hashid / ophcrack | apt rolling | `apt-get install` |

#### `argus-kali-browser`

| Tool | Pinned version | Source |
|------|----------------|--------|
| playwright (Python) | `1.50.0` | `pip install --user` |
| pyppeteer | `2.0.0` | `pip install --user` |
| puppeteer (npm) | `22.15.0` | `npm install` |
| retire (npm) | `5.2.7` | `npm install` |
| chromium / chromium-driver / firefox-esr | apt rolling | `apt-get install` (Chromium SUID sandbox **removed** post-install) |

#### `argus-kali-full`

`full` is a superset built from the same Go / Python / apt sources as the
slim images, with relaxed pinning on the apt layer. The pip-installed and
go-installed tools are pinned to the same versions as the slim images
listed above. apt-installed tools (apktool, binwalk, radare2, default-jre,
etc.) follow the rolling base.

#### `argus-kali-recon` (ARG-048)

| Tool | Pinned version | Source |
|------|----------------|--------|
| theHarvester | `4.6.0` | `pip install --user` |
| dnsrecon | `1.1.5` | `pip install --user` |
| fierce | `1.5.0` | `pip install --user` |
| censys | `2.2.13` | `pip install --user` |
| shodan | `1.31.0` | `pip install --user` |
| dnstwist | `20240916` | `pip install --user` |
| sublist3r | `1.1` | `pip install --user` |
| python-whois | `0.9.5` | `pip install --user` |
| subfinder | `v2.6.7` | `go install` |
| dnsx | `v1.2.2` | `go install` |
| chaos-client | `v0.5.1` | `go install` |
| naabu | `v2.3.4` | `go install` |
| asnmap | `v1.1.1` | `go install` |
| uncover | `v1.0.9` | `go install` |
| mapcidr | `v1.1.34` | `go install` |
| amass | `v4.2.0` | `go install` |
| assetfinder | `v0.1.1` | `go install` |
| findomain | `v9.0.5` | `go install` |
| rustscan | `v2.3.0` | `go install` |
| gowitness | `v3.0.5` | `go install` |
| nmap / masscan / unicornscan / smbclient / smbmap / ldap-utils / enum4linux / dnsutils / whois | apt rolling | `apt-get install` |

#### `argus-kali-network` (ARG-048)

| Tool | Pinned version | Source |
|------|----------------|--------|
| impacket | `0.12.0` | `pip install --user` |
| bloodhound | `1.7.2` | `pip install --user` |
| crackmapexec | `5.4.0` | `pip install --user` |
| evil-winrm-py | `0.5.0` | `pip install --user` |
| netaddr | `1.3.0` | `pip install --user` |
| dnspython | `2.7.0` | `pip install --user` |
| kerbrute | `v1.0.3` | `go install` |
| gowitness | `v3.0.5` | `go install` |
| interactsh-client | `v1.2.0` | `go install` |
| snmp / snmp-mibs-downloader / onesixtyone / ldap-utils / smbclient / samba-common-bin / responder / impacket-scripts / ike-scan / redis-tools / mongodb-clients / rpcbind / dnsutils / openssl / ssldump | apt rolling | `apt-get install` |

---

## 2. Hardening contract

Every Dockerfile MUST satisfy the following invariants. They are enforced
statically by `backend/tests/integration/sandbox/test_image_security_contract.py`
(65 assertions, runs in <1 s, no Docker daemon required).

| # | Invariant | Where enforced |
|---|-----------|----------------|
| 1 | Multi-stage pattern: ≥1 `FROM ... AS <name>` builder stage AND a final non-builder `FROM` stage | `TestStructure.test_multistage_pattern` |
| 2 | `USER 65532` directive in the final stage (matches k8s `securityContext.runAsUser`) | `TestUserDirective.test_final_stage_user_65532` |
| 3 | `useradd --uid 65532` AND `groupadd --gid 65532` in the final stage | `TestUserDirective.test_useradd_creates_correct_uid` |
| 4 | `HEALTHCHECK` directive present in the final stage, invokes `/usr/local/bin/healthcheck.sh` | `TestHealthcheck.*` |
| 5 | Required OCI labels: `org.opencontainers.image.{title,description,source}` | `TestLabels.test_oci_labels_present` |
| 6 | Required ARGUS labels: `argus.image.profile`, `argus.image.cycle`, `argus.sbom.path` | `TestLabels.*` |
| 7 | `argus.image.profile` matches the Dockerfile's parent directory (e.g. `web` for `argus-kali-web/`) | `TestLabels.test_argus_image_profile_label_matches_directory` |
| 8 | `argus.image.cycle` matches the cycle that introduced the profile (`ARG-026` for web/cloud/browser/full, `ARG-048` for recon/network) | `TestLabels.test_argus_image_cycle_label_matches_introduction` |
| 9 | `argus.sbom.path == "/usr/share/doc/sbom.cdx.json"` | `TestLabels.test_sbom_path_label_present` |
| 10 | `generate_sbom.sh` invoked at build time, targets the canonical SBOM path | `TestSbomGeneration.test_sbom_generation_step_present` |
| 11 | No `RUN chmod +s`, `chmod u+s`, `chmod g+s`, `chmod 4xxx` patterns (no SUID introduction) | `TestNoSuidIntroduction.test_no_suid_introduction` |
| 12 | Shared helpers `_shared/healthcheck.sh` and `_shared/generate_sbom.sh` exist and are COPY'd into every image | `TestSharedHelpers.*` |
| 13 | Browser image explicitly removes Chromium's SUID sandbox (`/usr/lib/chromium/chrome-sandbox`) | `TestProfileSpecificContracts.test_browser_image_documents_no_suid_chromium` |
| 14 | Cloud image ships `syft` (canonical SBOM tool) | `TestProfileSpecificContracts.test_cloud_image_ships_syft` |
| 15 | Full image is a superset (contains nuclei + trivy + chromium signature tools) | `TestProfileSpecificContracts.test_full_image_is_superset_of_others` |
| 16 | Recon image carries §4.1 passive (subfinder) AND §4.2 active (nmap) recon signatures | `TestProfileSpecificContracts.test_recon_image_carries_passive_and_active_recon_signatures` |
| 17 | Network image carries §4.17 protocol exploitation signatures (snmp, impacket) | `TestProfileSpecificContracts.test_network_image_carries_protocol_exploitation_signatures` |
| 18 | Base image is `kalilinux/kali-rolling:<pin>`, NOT `:latest` (reproducibility) | `TestBaseImagePin.test_base_image_is_pinned` |

### 2.1 Runtime hardening (k8s securityContext)

Image-level invariants pair with cluster-level securityContext settings
applied by `backend/src/sandbox/k8s_adapter.py`:

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 65532
  runAsGroup: 65532
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
  capabilities:
    drop: ["ALL"]
  seccompProfile:
    type: RuntimeDefault

automountServiceAccountToken: false
restartPolicy: Never  # at the Job spec level
backoffLimit: 0       # at the Job spec level
```

Both layers must be in place — the image alone is not sufficient and the
Pod alone is not sufficient. They form the
[STRIDE-aligned defence-in-depth](./security-model.md) for the sandbox
runtime.

---

## 3. SBOM regeneration

Every image bakes a CycloneDX 1.5 JSON SBOM at
`/usr/share/doc/sbom.cdx.json` at build time. The `argus.sbom.path` label
exposes that path so downstream Trivy / Grype scans (and the Cosign
attestation pipeline) can locate it without spelunking.

### 3.1 Inside an existing image

```bash
docker run --rm --entrypoint cat argus-kali-web:1.0.0 /usr/share/doc/sbom.cdx.json | jq '.components | length'
```

Returns the number of components (typically 200–800 depending on profile).

### 3.2 Forced regeneration

To regenerate the SBOM after manually adding a package (rare — usually
you'd just rebuild the image), invoke the wrapper inside the running
container:

```bash
docker run --rm --user 65532 \
  -v "$(pwd)/sbom-out:/sbom" \
  argus-kali-cloud:1.0.0 \
  /usr/local/bin/generate_sbom.sh /sbom/sbom.cdx.json
```

The wrapper auto-detects whether `syft` is on `$PATH`. If yes (cloud and
full images), it emits a complete CycloneDX 1.5 doc with PURLs, licences,
and CPEs. If no (web and browser images), it falls back to a minimal
CycloneDX envelope built from `dpkg-query -W` output — still
machine-readable for Trivy / Grype but without licence / CPE metadata.

### 3.3 Validation

The CI workflow validates every SBOM with a tiny Python check:

```python
import json
with open("sbom.cdx.json") as fh:
    doc = json.load(fh)
assert doc["bomFormat"] == "CycloneDX"
assert doc["specVersion"] in {"1.5", "1.6"}
assert isinstance(doc["components"], list) and len(doc["components"]) > 0
```

Anything else fails the pipeline.

---

## 4. Cosign signing (skeleton)

Cycle 3 ships the **skeleton** of the supply-chain signing pipeline:

* **Dry-run by default.** `infra/scripts/sign_images.sh` prints the
  `cosign sign` and `cosign attest` commands it would run, then exits 0.
  Safe to wire into PR builds without configuring any keys.
* **Real signing when `COSIGN_KEY` is set.** Set the env var to either a
  local PEM private key or a Sigstore KMS reference (`awskms://...`,
  `gcpkms://...`, `hashivault://...`). The script then performs real
  `cosign sign` against each image tag AND attempts an attestation of the
  baked-in SBOM with `--type cyclonedx`.
* **No Rekor / Fulcio yet.** Both `cosign sign` and `cosign attest` are
  invoked with `--tlog-upload=false`. Cycle 5 will replace the keyed flow
  with keyless OIDC + Rekor + Fulcio.

### 4.1 PR validation (dry-run)

```bash
infra/scripts/sign_images.sh --profile all --tag pr-12345 --dry-run
```

Prints the commands but does not require docker daemon access.

### 4.2 Local real signing

```bash
cosign generate-key-pair                            # creates cosign.key + cosign.pub
COSIGN_KEY=cosign.key COSIGN_PASSWORD=<pwd> \
  infra/scripts/sign_images.sh \
    --profile all \
    --tag 1.0.0 \
    --output-bundle ./cosign-bundle.json
```

The bundle is a JSON list of `{image, timestamp}` records — useful as a
CI artifact.

### 4.3 CI signing

`.github/workflows/sandbox-images.yml` wires the script into the
`sign-images` job, which runs only on `push` to `main`. The job consumes
two repository secrets:

| Secret | Purpose |
|--------|---------|
| `COSIGN_PRIVATE_KEY` | PEM-encoded private key (or KMS reference) |
| `COSIGN_PASSWORD` | Passphrase for the PEM key |

If either secret is unset the script auto-detects dry-run mode and exits 0
without failing the pipeline. ARG-033 (Cycle 4) replaces this skeleton
with keyless Sigstore Fulcio + Rekor + an in-toto SLSA-style attestation
of the SBOM.

---

## 4a. CI image build + push to GHCR (ARG-034)

The CI workflow `.github/workflows/sandbox-images.yml` no longer keeps
images local. Every successful `build-images` matrix leg pushes two tags
to GitHub Container Registry:

| Tag pattern | Example | Purpose |
|-------------|---------|---------|
| `ghcr.io/<org>/argus-kali-<profile>:<sha>` | `ghcr.io/argus-active-pentest/argus-kali-web:8e3f...d901` | Immutable content-addressed reference. Used by `trivy-scan`, `compose-smoke`, and (after ARG-033) `sign-images` + `verify-images`. |
| `ghcr.io/<org>/argus-kali-<profile>:latest` | `ghcr.io/argus-active-pentest/argus-kali-web:latest` | Floating dev convenience tag. Updated on every push to `main`. |

`<org>` is the `github.repository_owner` lowercased; `<sha>` is the full
40-char `github.sha` of the commit that triggered the workflow.

### 4a.1 Pipeline order

```
hardening-contract       (Dockerfile static analysis)
        │
        ▼
build-images (matrix: web|cloud|browser|full)
        │   ├─ docker login ghcr.io
        │   ├─ build_images.sh --registry ghcr.io/<org> --tag <sha> --push
        │   ├─ extract baked-in SBOM (/usr/share/doc/sbom.cdx.json)
        │   ├─ validate CycloneDX envelope (Python inline check)
        │   ├─ cosign attach sbom --type cyclonedx <image>:<sha>
        │   └─ upload-artifact sbom-<profile>-<sha> (30d retention)
        │
        ├──► trivy-scan (matrix: web|cloud|browser|full) — BLOCKING
        │           └─ docker pull <image>:<sha> + Trivy --exit-code 1
        │
        ├──► compose-smoke
        │           ├─ pull all 4 sandbox images from GHCR
        │           ├─ smoke per image: id (uid 65532) + SBOM head
        │           └─ docker compose up -d postgres redis minio
        │
        └──► sign-images / sign-dry-run (Cycle 3 skeleton; ARG-033 rewrites)
```

### 4a.2 Required GitHub permissions / secrets

| Resource | Value | Why |
|----------|-------|-----|
| `permissions.contents: read` | workflow-level | Checkout the repo |
| `permissions.packages: write` | workflow-level + per-job | Push to GHCR |
| `permissions.id-token: write` | workflow-level | Keyless cosign OIDC (used by ARG-033 attest) |
| `secrets.GITHUB_TOKEN` | auto-provisioned | Authenticates `docker login ghcr.io` (no PAT needed) |
| `secrets.COSIGN_PRIVATE_KEY` | optional, repo secret | Only needed by the Cycle 3 keyed `sign-images` skeleton; ARG-033 retires this. |
| `secrets.COSIGN_PASSWORD` | optional, repo secret | Same as above. |

No PATs and no third-party tokens are required for the GHCR push — the
workflow uses GitHub's own short-lived OIDC token for both registry auth
and (in ARG-033) Sigstore attestation.

### 4a.3 Local equivalent of the CI push

```powershell
# Authenticate once per session (PowerShell, Windows)
$env:CR_PAT = "<personal-access-token-with-write:packages>"
$env:CR_PAT | docker login ghcr.io -u <github-handle> --password-stdin

# Build + push all 4 images at the current HEAD commit
$sha = git rev-parse HEAD
bash infra/scripts/build_images.sh `
  --registry "ghcr.io/<org>" `
  --tag $sha `
  --push
```

bash equivalent (Linux / WSL / macOS):

```bash
echo "$CR_PAT" | docker login ghcr.io -u "<github-handle>" --password-stdin

bash infra/scripts/build_images.sh \
  --registry "ghcr.io/<org>" \
  --tag "$(git rev-parse HEAD)" \
  --push
```

The script refuses `--push` without `--registry` so a slip cannot
silently push to `docker.io/library/argus-kali-*`.

### 4a.4 OCI SBOM artefact (cosign attach sbom)

After each push, the workflow attaches the baked-in CycloneDX 1.5 SBOM
as a sibling OCI artefact next to the image manifest:

```bash
cosign attach sbom \
  --sbom /tmp/sbom-web.cdx.json \
  --type cyclonedx \
  ghcr.io/<org>/argus-kali-web:<sha>
```

Downstream consumers can fetch it without pulling the (multi-GB) image:

```bash
cosign download sbom ghcr.io/<org>/argus-kali-web:<sha> > sbom.cdx.json
```

> **Cosign version pin:** the workflow uses `cosign-release: v2.4.1`.
> `cosign attach sbom` was removed in cosign v3.x, so the pin must stay
> on the v2 line until ARG-033 swaps the mechanism for `cosign attest
> --predicate <sbom> --type cyclonedx` (which works in both v2 and v3).
> The 30-day workflow artefact (`sbom-<profile>-<sha>`) is kept as a
> belt-and-suspenders backup independent of GHCR availability.

---

## 4b. Trivy blocking scan policy (ARG-034)

The `trivy-scan` job is **blocking**. Any unsuppressed CRITICAL or HIGH
finding (fixed OR unfixed) fails the matrix leg and prevents merge to
`main` (see §4c).

### 4b.1 Scan parameters (locked)

| Knob | Value | Rationale |
|------|-------|-----------|
| `severity` | `CRITICAL,HIGH` | OWASP Top 10 supply-chain alignment; MEDIUM is informational. |
| `ignore-unfixed` | `false` | Cycle 3 was `true`. Cycle 4 raises the bar — unfixed CRITICAL still blocks merge so we apply mitigations (sandbox isolation, NetworkPolicy egress deny) explicitly per CVE rather than ignore the class. |
| `exit-code` | `1` | Hard fail on any finding. Was `'0'` (informational) in Cycle 3. |
| `format` | `table` | Human-readable in the GH Actions log. SARIF/JSON output is added in ARG-040 capstone for the GitHub Security tab integration. |
| `trivyignores` | `.trivyignore` | Curated allowlist (see §4b.2). |
| `image-ref` | `ghcr.io/<org>/argus-kali-<profile>:<sha>` | The image is pulled from GHCR (proves push worked + scan target identical to deploy target). |

### 4b.2 `.trivyignore` curation policy

The `.trivyignore` file at the repository root governs every CVE
suppression that the blocking scan can ignore. Policy is also embedded
in the file's header comment for in-place reference.

1. **Empty by default.** Do NOT pre-populate. The first real CI run will
   surface the actual list. Only add entries based on real evidence.
2. **Each entry MUST be on its own line, immediately preceded by a
   four-field comment block:**
   - CVE-YYYY-NNNNN identifier (matches the entry below).
   - Justification (which package, which feature, why ARGUS sandbox does
     not invoke it; cite a file path or test).
   - Owner (`ARG-NNN`) that added the entry.
   - Expiry (`expires: YYYY-MM-DD` — 90 days from add-date).
3. **Quarterly audit.** The cycle owner runs:
   ```powershell
   # PowerShell
   Select-String -Path .trivyignore -Pattern '^CVE-' | ForEach-Object { $_.Line }
   ```
   ```bash
   # bash
   grep -E '^CVE-[0-9]{4}-[0-9]+' .trivyignore
   ```
   …and confirms every active suppression has a non-expired comment block.
   Expired entries either get removed (preferred — upgrade the package)
   or re-justified with a fresh expiry.
4. **No blanket suppressions.** No wildcards, no severity-level filters,
   no toggling `ignore-unfixed` back to `true` to mask findings.
5. **Cosign attestation linkage** (ARG-033, after this lands): the
   in-toto SLSA predicate produced for each image records the active
   suppression set so external verifiers can audit the manifest against
   the signed scan provenance.

### 4b.3 Local replay (regenerate the report off-CI)

```powershell
# PowerShell — pull image then scan locally with same gating as CI
$sha = git rev-parse HEAD
docker pull ghcr.io/<org>/argus-kali-web:$sha

trivy image `
  --severity CRITICAL,HIGH `
  --ignore-unfixed=false `
  --exit-code 1 `
  --ignorefile .trivyignore `
  "ghcr.io/<org>/argus-kali-web:$sha"
```

bash equivalent:

```bash
trivy image \
  --severity CRITICAL,HIGH \
  --ignore-unfixed=false \
  --exit-code 1 \
  --ignorefile .trivyignore \
  ghcr.io/<org>/argus-kali-web:"$(git rev-parse HEAD)"
```

`exit 0` means clean (or all findings are listed in `.trivyignore`).
`exit 1` means real CVE — fix the package version in the Dockerfile and
re-build. Do NOT add to `.trivyignore` unless you can satisfy §4b.2 in
full.

---

## 4c. Branch protection requirements (ARG-034)

Required Status Checks for merging to `main` — set these in
`Settings → Branches → Add rule for main` (or via the GitHub Branch
Protection API).

### 4c.1 Required checks

From `.github/workflows/sandbox-images.yml`:

- `hardening-contract`
- `build-images / Build & push (web)`
- `build-images / Build & push (cloud)`
- `build-images / Build & push (browser)`
- `build-images / Build & push (full)`
- `trivy-scan / Trivy scan (web)`
- `trivy-scan / Trivy scan (cloud)`
- `trivy-scan / Trivy scan (browser)`
- `trivy-scan / Trivy scan (full)`
- `compose-smoke`
- `verify-images` *(added by ARG-033 — Cosign keyless verify)*

From `.github/workflows/ci.yml` (existing — ARG-028 onwards):

- `lint`
- `test-no-docker`
- `test-docker-required`
- `security`
- `npm-audit (Frontend)`
- `npm-audit (admin-frontend)`

### 4c.2 Recommended branch protection settings

| Setting | Value | Why |
|---------|-------|-----|
| Require pull request reviews before merging | ✅ at least 1 | Two-eyes principle. |
| Dismiss stale pull request approvals when new commits are pushed | ✅ | Force re-review on every new commit. |
| Require review from Code Owners | ✅ if `CODEOWNERS` exists | Domain ownership. |
| Require status checks to pass before merging | ✅ | Gate on the list in §4c.1. |
| Require branches to be up to date before merging | ⚠️ optional (`strict: false`) | Brief recommends `false` — avoids forcing a rebuild on every rebase / fast-forward; rely on the matrix instead to catch real regressions. Flip to `true` for strict-linear-history teams. |
| Require signed commits | ✅ recommended | Pairs with Cosign keyless signing — closes the loop on commit→build→deploy authenticity. |
| Require linear history | ⚠️ optional | Squash/rebase merge style only. |
| Include administrators | ✅ | Admins should not be able to bypass blocking Trivy / OIDC verify gates. |
| Allow force pushes | ❌ never | Would let an attacker rewrite signed history. |
| Allow deletions | ❌ never | `main` should never be deleted. |

### 4c.3 Setup checklist (operator runbook)

1. Open `https://github.com/<org>/argus/settings/branches`.
2. Click **Add branch protection rule** (or **Edit** if `main` already
   has one).
3. Pattern: `main`.
4. Tick **Require status checks to pass before merging**.
5. Tick **Require branches to be up to date before merging** if your
   team enforces strict linear history (otherwise leave unchecked).
6. In the search box, add **all 16 checks listed in §4c.1** one by one.
   GitHub's autocomplete only shows checks that have run at least once
   on a PR — push a no-op PR first if any check is missing from the
   dropdown.
7. Tick **Include administrators**.
8. Click **Create** / **Save changes**.
9. Verify by opening a fresh PR; the merge button should be disabled
   until every required check is green.

> **Note on `verify-images`:** this check is added by ARG-033 (Cosign
> keyless signing). Until ARG-033 lands, leave it OFF the required-checks
> list to avoid blocking merges; add it the same day ARG-033 ships.

### 4c.4 Bypass / break-glass procedure

If GHCR or Sigstore is genuinely down (rare — both are 99.99% SLA):

1. The on-call rotation owner files an Incident in the on-call tracker.
2. The Cycle owner temporarily marks the failing check as **non-required**
   in branch protection (DO NOT delete the check; just untick it).
3. Once the outage resolves, re-tick the check WITHIN 4 HOURS and force
   re-run the failing workflow on the affected branch.
4. Post-mortem MUST cover the bypass window — file under
   `ai_docs/develop/issues/ISS-cycle<N>-bp-bypass-<date>.md`.

---

## 4d. Cosign keyless signing (ARG-033)

Cycle 4 retires the keyed Cosign skeleton (§4) in favour of **keyless
signing** through Sigstore Fulcio + Rekor, authenticated by GitHub Actions
OIDC. No long-lived secrets live in the workflow; identity is bound to the
workflow path itself, and every signature is publicly auditable in the
Rekor transparency log.

### 4d.1 Trust chain

```
GH Actions JWT (id-token: write)
        │  (audience = sigstore)
        ▼
Sigstore Fulcio  ──issues──►  X.509 cert (10-min validity)
                              SAN: https://github.com/<org>/<repo>/.github/workflows/sandbox-images.yml@refs/heads/<branch>
                              Issuer: https://token.actions.githubusercontent.com
        │
        ▼
cosign sign --yes <image>     (Fulcio cert + signature → image's OCI sigstore tag)
cosign attest --predicate <SBOM> --type cyclonedx --yes <image>
                              (CycloneDX SBOM as in-toto SLSA-style attestation)
        │
        ▼
Rekor transparency log        (append-only public ledger; entry = sig + cert + log index)
        │
        ▼
verify-images job             (cosign verify --certificate-identity-regexp <pattern>
                                             --certificate-oidc-issuer <token-issuer>)
                              fails the matrix leg (and the merge) if the
                              signature is missing OR the cert identity
                              doesn't match this workflow path.
```

The crucial property: an attacker who cannot push commits with this
exact workflow path cannot mint a Fulcio certificate that the verifier
will accept. A stolen GHCR PAT (read-only) cannot strip + re-sign,
because re-signing requires the OIDC token and that's only available
inside `actions/checkout@v4`-context jobs on this repo.

### 4d.2 Workflow snippet — sign-images job

```yaml
sign-images:
  name: Cosign sign (${{ matrix.profile }})
  needs: [build-images]
  runs-on: ubuntu-latest
  if: github.event_name == 'push' && github.ref == 'refs/heads/main'
  permissions:
    contents: read
    packages: write
    id-token: write   # mandatory — Fulcio OIDC exchange
  strategy:
    fail-fast: false
    matrix:
      profile: [web, cloud, browser, full]
  steps:
    - uses: actions/checkout@v4

    - uses: docker/login-action@v3
      with:
        registry: ghcr.io
        username: ${{ github.actor }}
        password: ${{ secrets.GITHUB_TOKEN }}

    - name: Install Cosign v2
      uses: sigstore/cosign-installer@v3.7.0
      with:
        cosign-release: v2.4.1

    - name: Resolve image ref + extract SBOM
      id: refs
      run: |
        OWNER_LC="$(echo "${{ github.repository_owner }}" | tr '[:upper:]' '[:lower:]')"
        IMAGE_REF="ghcr.io/${OWNER_LC}/argus-kali-${{ matrix.profile }}:${GITHUB_SHA}"
        SBOM_PATH="${{ runner.temp }}/sbom-${{ matrix.profile }}.cdx.json"
        docker pull "$IMAGE_REF"
        docker run --rm --entrypoint cat "$IMAGE_REF" /usr/share/doc/sbom.cdx.json > "$SBOM_PATH"
        echo "image_ref=$IMAGE_REF" >> "$GITHUB_OUTPUT"
        echo "sbom_path=$SBOM_PATH" >> "$GITHUB_OUTPUT"

    - name: Cosign keyless sign + SBOM attest
      env:
        IMAGE_REF: ${{ steps.refs.outputs.image_ref }}
        SBOM_PATH: ${{ steps.refs.outputs.sbom_path }}
      run: |
        chmod +x infra/scripts/sign_images.sh
        infra/scripts/sign_images.sh \
          --image "$IMAGE_REF" \
          --sbom "$SBOM_PATH" \
          --output-bundle "${{ runner.temp }}/cosign-bundle-${{ matrix.profile }}.json"
```

The script runs `cosign sign --yes <image>` (no `--key`) and
`cosign attest --predicate <SBOM> --type cyclonedx --yes <image>`.
`--tlog-upload=true` is the Cosign v2 default — every signature lands
in Rekor automatically.

### 4d.3 Workflow snippet — verify-images job

```yaml
verify-images:
  name: Cosign verify (${{ matrix.profile }})
  needs: [sign-images]
  runs-on: ubuntu-latest
  if: github.event_name == 'push' && github.ref == 'refs/heads/main'
  permissions:
    contents: read
    packages: read
  strategy:
    fail-fast: false
    matrix:
      profile: [web, cloud, browser, full]
  steps:
    - uses: actions/checkout@v4

    - uses: docker/login-action@v3
      with:
        registry: ghcr.io
        username: ${{ github.actor }}
        password: ${{ secrets.GITHUB_TOKEN }}

    - name: Install Cosign v2
      uses: sigstore/cosign-installer@v3.7.0
      with:
        cosign-release: v2.4.1

    - name: Resolve image ref
      id: refs
      run: |
        OWNER_LC="$(echo "${{ github.repository_owner }}" | tr '[:upper:]' '[:lower:]')"
        echo "image_ref=ghcr.io/${OWNER_LC}/argus-kali-${{ matrix.profile }}:${GITHUB_SHA}" >> "$GITHUB_OUTPUT"

    - name: Verify keyless signature (Fulcio cert identity)
      env:
        IMAGE: ${{ steps.refs.outputs.image_ref }}
      run: |
        cosign verify "$IMAGE" \
          --certificate-identity-regexp "^https://github\.com/[^/]+/[^/]+/\.github/workflows/sandbox-images\.yml@refs/heads/.+$" \
          --certificate-oidc-issuer "https://token.actions.githubusercontent.com"

    - name: Verify SBOM attestation (CycloneDX predicate)
      env:
        IMAGE: ${{ steps.refs.outputs.image_ref }}
      run: |
        cosign verify-attestation "$IMAGE" \
          --type cyclonedx \
          --certificate-identity-regexp "^https://github\.com/[^/]+/[^/]+/\.github/workflows/sandbox-images\.yml@refs/heads/.+$" \
          --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

### 4d.4 Local equivalent of the verify

Useful for spot-checks of an image already pushed by CI:

```powershell
# PowerShell
$image = "ghcr.io/<org>/argus-kali-web:<sha>"
cosign verify $image `
  --certificate-identity-regexp '^https://github\.com/[^/]+/[^/]+/\.github/workflows/sandbox-images\.yml@refs/heads/.+$' `
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'

cosign verify-attestation $image `
  --type cyclonedx `
  --certificate-identity-regexp '^https://github\.com/[^/]+/[^/]+/\.github/workflows/sandbox-images\.yml@refs/heads/.+$' `
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'
```

```bash
# bash
IMAGE="ghcr.io/<org>/argus-kali-web:<sha>"
cosign verify "$IMAGE" \
  --certificate-identity-regexp '^https://github\.com/[^/]+/[^/]+/\.github/workflows/sandbox-images\.yml@refs/heads/.+$' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'

cosign verify-attestation "$IMAGE" \
  --type cyclonedx \
  --certificate-identity-regexp '^https://github\.com/[^/]+/[^/]+/\.github/workflows/sandbox-images\.yml@refs/heads/.+$' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'
```

`exit 0` means the signature exists, the Fulcio certificate is valid,
and the SAN matches our workflow path. `exit 1` means **do not deploy
this image** — it was either not signed by us or the cert was minted
under a different identity.

### 4d.5 Permissions matrix (post-ARG-033)

| Resource | Sign job | Verify job | Why |
|----------|----------|------------|-----|
| `contents: read` | ✅ | ✅ | `actions/checkout@v4` |
| `packages: write` | ✅ | ❌ | Push signature artefacts to GHCR sigstore tag |
| `packages: read` | (covered by write) | ✅ | Pull image manifest + signature for verify |
| `id-token: write` | ✅ | ❌ | Mandatory for Fulcio OIDC exchange (sign only) |
| `secrets.GITHUB_TOKEN` | ✅ | ✅ | `docker login ghcr.io` (auto-provisioned) |
| `secrets.COSIGN_PRIVATE_KEY` | ❌ retired | n/a | Not needed in keyless mode (only for §4e rollback) |
| `secrets.COSIGN_PASSWORD` | ❌ retired | n/a | Same as above |

The two retired secrets remain only for the keyed rollback runbook in
§4e. Delete them from the repo settings once §4e has been rehearsed
once and the runbook is filed.

---

## 4e. Rollback to keyed mode (Sigstore degraded)

**When to use:** Sigstore Fulcio or Rekor is genuinely degraded /
unreachable. Check `https://status.sigstore.dev` first; if both
services are green, the failure is in our workflow and rolling back
will not help — fix forward.

**Why the rollback is intrusive:** keyed signatures don't carry an OIDC
identity, so the verify job's `--certificate-identity-regexp` check
won't apply. We trade public verifiability for availability — only
do this when CI is truly stuck.

### 4e.1 Operator runbook

1. **Provision an emergency keypair.** On a workstation with cosign
   installed:

    ```bash
    cosign generate-key-pair
    # Prompts for a passphrase (use a strong one — this key replaces
    # the entire trust chain for the duration of the outage).
    # Writes: cosign.key (private) + cosign.pub (public)
    ```

2. **Store the private half as a repo secret.**

    - GitHub → Settings → Secrets and variables → Actions
    - Name: `COSIGN_KEY` — value: contents of `cosign.key` (the PEM)
    - Name: `COSIGN_PASSWORD` — value: passphrase from step 1

3. **Commit the public half** so external verifiers (and §4e.4 below)
   have something to check against:

    ```powershell
    # PowerShell
    New-Item -ItemType Directory -Force -Path infra/cosign | Out-Null
    Move-Item .\cosign.pub infra/cosign\cosign.pub
    git add infra/cosign/cosign.pub
    git commit -m "ops(cosign): emergency public key for rollback (ARG-033, expires <YYYY-MM-DD>)"
    ```

    ```bash
    # bash
    mkdir -p infra/cosign
    mv cosign.pub infra/cosign/cosign.pub
    git add infra/cosign/cosign.pub
    git commit -m "ops(cosign): emergency public key for rollback (ARG-033, expires <YYYY-MM-DD>)"
    ```

4. **Re-run the failing `sign-images` workflow** with the secret
   plumbed in. Either:

    - Add `env: { COSIGN_KEY: ${{ secrets.COSIGN_KEY }}, COSIGN_PASSWORD: ${{ secrets.COSIGN_PASSWORD }} }`
      to the `Cosign keyless sign + SBOM attest` step of `sign-images`
      and push the patch on a hotfix branch, OR
    - Use `workflow_dispatch` to re-run the existing job after manually
      patching the env block locally.

    The script auto-detects the env var, switches to keyed mode, and
    prints a `WARNING: KEYED ROLLBACK MODE` banner. `--tlog-upload`
    is forced to `false` (no Rekor entries during the outage).

5. **Verify locally** that the keyed signature applies cleanly:

    ```powershell
    # PowerShell
    cosign verify --key infra/cosign/cosign.pub `
      ghcr.io/<org>/argus-kali-web:<sha>
    ```

    ```bash
    # bash
    cosign verify --key infra/cosign/cosign.pub \
      ghcr.io/<org>/argus-kali-web:<sha>
    ```

6. **Temporarily mark `verify-images` as non-required** in branch
   protection (Settings → Branches → main → Status checks). Files
   signed in this mode WILL fail keyless verify, by construction.

### 4e.2 Post-incident re-sign

When `https://status.sigstore.dev` reports all systems operational:

1. Revert the `sign-images` env-block patch from §4e.1 step 4.
2. Re-run the workflow on the same `main` HEAD; keyless signatures will
   land alongside the keyed ones (cosign supports multiple signatures
   per image).
3. Re-tick `verify-images` as a Required Status Check.
4. **Revoke the emergency key**:

    ```bash
    # GitHub Settings → Secrets → delete COSIGN_KEY + COSIGN_PASSWORD
    git rm infra/cosign/cosign.pub
    git commit -m "ops(cosign): revoke emergency rollback key (Sigstore restored YYYY-MM-DD)"
    ```

5. File a post-mortem under
   `ai_docs/develop/issues/ISS-cycle<N>-cosign-rollback-<date>.md`
   covering the outage window, signed digests, and any consumer that
   pulled an unsigned image.

### 4e.3 Compatibility matrix

| Mode | `--key` | `--tlog-upload` | `--certificate-identity-regexp` | Verifier command |
|------|---------|-----------------|---------------------------------|------------------|
| **Keyless (default)** | absent | `true` (default) | required at verify time | `cosign verify <image> --certificate-identity-regexp ... --certificate-oidc-issuer ...` |
| **Keyed rollback** | `${COSIGN_KEY}` | forced `false` | not applicable | `cosign verify --key infra/cosign/cosign.pub <image>` |
| **Dry-run** | n/a | n/a | n/a | (no signature produced) |

Mixed verification (an image signed in BOTH modes) is supported by
`cosign verify` — pass either `--certificate-identity-regexp` or
`--key` and a matching signature is enough.

---

## 4f. Verifying offline (air-gapped)

For air-gapped consumers (an offline customer site, an SCIF, etc.) the
verifier must be handed: (a) the signature blob, (b) the Fulcio
certificate, (c) optionally the Rekor inclusion proof. Cosign v2 emits
all three on demand.

### 4f.1 Producing the offline bundle

Run this on a connected machine that has just signed the image:

```bash
IMAGE="ghcr.io/<org>/argus-kali-web:<sha>"

# 1. Pull the signature + certificate from the registry's sigstore tag.
cosign sign --yes \
  --output-signature sig.bin \
  --output-certificate cert.pem \
  "$IMAGE"

# 2. (Optional) Fetch the Rekor bundle that proves the entry exists.
cosign download attestation "$IMAGE" > attestation.json
```

Bundle these three artefacts into a tar file along with the image
manifest and ship them to the offline consumer.

### 4f.2 Verifying offline

On the air-gapped machine, with cosign installed but no network:

```bash
IMAGE="<local-registry-or-docker-load-target>"

# Verify the signature against the supplied certificate, with NO
# transparency-log lookup. Cosign v2 spelling:
cosign verify "$IMAGE" \
  --insecure-ignore-tlog=true \
  --certificate cert.pem \
  --signature sig.bin \
  --certificate-identity-regexp '^https://github\.com/[^/]+/[^/]+/\.github/workflows/sandbox-images\.yml@refs/heads/.+$' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'
```

> **Cosign syntax caveat:** the offline verification flag has changed
> across cosign versions (`--rekor-url ''` worked in v1.x;
> `--insecure-ignore-tlog=true` is the current v2.x form). Check
> `cosign verify --help` against your installed version before
> shipping to a customer.

### 4f.3 Trust roots for offline use

The Fulcio root certificate is bundled with cosign itself (TUF root,
refreshed on the connected machine before air-gap). If the consumer
needs to verify cert-chain validity without `cosign`, ship them
`fulcio_v1.crt.pem` from the Sigstore TUF repo together with the
bundle. They can then run an OpenSSL chain check independently.

---

## 5. Local build + sign workflow

The two helpers under `infra/scripts/` cover every profile + every flag
combination.

### 5.1 Build everything

```powershell
# Windows / PowerShell (cmd / WSL works too — the script is bash-compatible)
bash infra/scripts/build_images.sh --tag 1.0.0
```

Builds the four images and tags each with both `1.0.0` and `latest`.
Build context is `sandbox/images/` (the shared `_shared/` directory has to
be visible to `COPY` directives).

### 5.2 Build a single profile

```powershell
bash infra/scripts/build_images.sh --profile cloud --tag 1.0.0 --no-cache
```

### 5.3 Push to a registry

The script now supports a single-shot build + push via the `--push`
flag (added in ARG-034). `--push` requires `--registry` so it cannot
accidentally push to `docker.io/library/argus-kali-*`.

```powershell
# One command builds AND pushes both <tag> and :latest for all four profiles
bash infra/scripts/build_images.sh `
  --tag 1.0.0 `
  --registry ghcr.io/argus-active-pentest `
  --push
```

Authenticate first via `docker login ghcr.io` (use a PAT with
`write:packages` scope for local pushes; CI uses the auto-provisioned
`GITHUB_TOKEN`).

The legacy two-step flow (build then push manually) still works if you
prefer it — just omit `--push`:

```powershell
bash infra/scripts/build_images.sh --tag 1.0.0 --registry ghcr.io/argus-active-pentest
docker push ghcr.io/argus-active-pentest/argus-kali-web:1.0.0
# ...repeat for cloud / browser / full + :latest
```

Use `--dry-run` to preview both build and push commands without touching
Docker.

### 5.4 Verify the hardening contract before pushing

```powershell
cd backend
python -m pytest tests/integration/sandbox/test_image_security_contract.py -q
```

Should report `≥65 passed in <1 s` against the current Dockerfiles. Any
failure indicates a regression — fix it before pushing.

---

## 6. Adding a new profile

Adding a new slim image (e.g. `argus-kali-binary`) is a four-step change.
ARG-048 followed exactly this recipe to land `recon` and `network`:

1. Create `sandbox/images/argus-kali-<profile>/Dockerfile` mirroring the
   pattern in this doc.
2. Add `<profile>` to `IMAGE_PROFILES` (and to `EXPECTED_CYCLE_PER_PROFILE`)
   in `backend/tests/integration/sandbox/test_image_security_contract.py`.
3. Add `<profile>` to the matrix in `infra/scripts/build_images.sh` and
   `infra/scripts/sign_images.sh` (the `ALL_PROFILES` array).
4. Add `<profile>` to the matrix in `.github/workflows/sandbox-images.yml`
   (build + trivy + sign + verify jobs — all four legs).
5. Add a CycloneDX placeholder SBOM at
   `infra/sandbox/images/sbom-<profile>.cdx.json` (committed stub —
   real per-image SBOM is baked into `/usr/share/doc/sbom.cdx.json` at
   build time and extracted by CI).
6. Update the table in §1 of this document and add a per-image pin
   block in §1.1.
7. Add a profile-specific contract test under
   `TestProfileSpecificContracts` so the new image's signature tools are
   asserted (drift gate).

The hardening contract test must remain green after step 1 — no
exceptions. The branch-protection required-status-checks list MUST be
updated to include the new `build-images / Build & push (<profile>)`,
`trivy-scan / Trivy scan (<profile>)`, `sign-images / Cosign sign
(<profile>)`, and `verify-images / Cosign verify (<profile>)` legs
before the merge lands.

---

## 7. Known follow-ups

* **`version:` field in tool YAMLs** — landed in ARG-040 (Cycle 4). Each
  YAML now carries a mandatory `version: <semver>` field; the
  `tool-yaml-version-monotonic` ratchet test enforced in ARG-049 (C15)
  prevents downgrades.
* **Real Cosign keys + Rekor + Fulcio** — landed in ARG-033 (Cycle 4).
  The `sandbox-images.yml` workflow signs every image keyless via GH OIDC
  → Sigstore Fulcio → Rekor; verified independently by the
  `verify-images` job.
* **Helm chart** publishing the SBOM as a Kubernetes ConfigMap —
  Cycle 5 ARG-045 (Helm chart for production deployment) tracks this.
* **Trivy / Grype gating with a CVSS threshold** — landed in ARG-034
  (Cycle 4). The `trivy-scan` job is now `exit-code: 1` on any
  CRITICAL+HIGH; merge-blocking.
* **Slim `argus-kali-binary` image** — currently 5 tool YAMLs
  (`apktool`, `binwalk`, `jadx`, `mobsf_api`, `radare2_info`) reference
  it but the image doesn't exist yet; they fall back to
  `argus-kali-full` via the resolver alias rule. Tracked under Cycle 6
  carry-over.
