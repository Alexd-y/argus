# ARGUS Prompt Catalog Signing Keys

Ed25519 keys used to sign every YAML descriptor under `backend/config/prompts/`.
The application is **fail-closed**: at startup the signed prompt registry
(`src.orchestrator.prompt_registry.PromptRegistry`) verifies every loaded YAML
against `backend/config/prompts/SIGNATURES`; an unknown / mismatched / missing
signature aborts startup. See `Backlog/dev1_md` §6, §19 and the cycle-1 plan
`ai_docs/develop/plans/2026-04-17-argus-finalization-cycle1.md` (ARG-008).

## Layout

```
backend/config/prompts/
├── _keys/
│   ├── README.md                       (this file)
│   ├── .gitkeep                        (forces git to keep the dir)
│   ├── dev_signing.ed25519.priv        (DEV ONLY — gitignored, delete after signing)
│   └── <key_id>.ed25519.pub            (committed; the canonical public key)
├── SIGNATURES                          (committed; one line per YAML)
└── <prompt_id>.yaml                    (committed; one prompt descriptor per file)
```

Public keys (`<key_id>.ed25519.pub`) ARE committed. Private keys (`*.priv`)
are NEVER committed — they are listed in `backend/.gitignore`. Workflow
expectation: generate the dev pair, sign, verify, then delete the private key.
The public key stays in the repo.

## Format of `SIGNATURES`

One line per signed YAML, whitespace-separated:

```
<sha256_hex>  <relative_yaml_path>  <ed25519_signature_b64>  <public_key_id>
```

* `sha256_hex`           — lowercase hex SHA-256 of the raw YAML bytes (no normalisation).
* `relative_yaml_path`   — POSIX path relative to `backend/config/prompts/`.
* `ed25519_signature_b64` — base64-encoded Ed25519 signature over the raw YAML bytes.
* `public_key_id`        — short id (first 16 hex chars of `sha256(pub_key_raw)`).

Lines starting with `#` and empty lines are ignored.

## Generate dev keys (local development only)

```powershell
python backend/scripts/prompts_sign.py generate-keys --out backend/config/prompts/_keys
```

This emits `dev_signing.ed25519.priv` (raw 32-byte private key) and
`<key_id>.ed25519.pub` (raw 32-byte public key).

## Sign all YAMLs

```powershell
python backend/scripts/prompts_sign.py sign `
    --key         backend/config/prompts/_keys/dev_signing.ed25519.priv `
    --prompts-dir backend/config/prompts `
    --out         backend/config/prompts/SIGNATURES
```

Re-running is idempotent and rewrites `SIGNATURES` from scratch.

## Verify all YAMLs

```powershell
python backend/scripts/prompts_sign.py verify `
    --prompts-dir backend/config/prompts `
    --signatures  backend/config/prompts/SIGNATURES `
    --keys-dir    backend/config/prompts/_keys
```

Exits non-zero if any YAML is unsigned, signed by an unknown key, or has been
tampered with. CI must run this on every PR.

## Production keys

* Generated **outside** the repository on a hardened workstation.
* Private key is pushed into a Kubernetes `Secret` and mounted via CSI into
  the signing container only. It MUST NEVER be checked into git.
* The public key (`<key_id>.ed25519.pub`) is the only artefact that lives in
  the repo (or is fetched at runtime from the same `Secret`).
* Rotate every 90 days or upon any suspected compromise. Record old key
  rotations in `ai_docs/security/key-rotation-log.md`.

## Threat model

The signed registry is the trust boundary between LLM behaviour and the rest
of the pipeline. A tampered prompt could downgrade safety constraints
(e.g. flip `raw_payloads_allowed=true`) or expand scope. With signing the
descriptor is refused at startup, so an attacker who lands a malicious
prompt PR cannot influence agent behaviour without also compromising the
signing key.
