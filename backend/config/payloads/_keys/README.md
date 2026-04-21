# ARGUS Payload Catalog Signing Keys

Ed25519 keys used to sign every YAML descriptor under `backend/config/payloads/`.
The application is **fail-closed**: at startup the signed payload registry
(`src.payloads.registry.PayloadRegistry`) verifies every loaded YAML against
`backend/config/payloads/SIGNATURES`; an unknown / mismatched / missing
signature aborts startup. See `Backlog/dev1_md` §6, §7 and the cycle-1 plan
`ai_docs/develop/plans/2026-04-17-argus-finalization-cycle1.md` (ARG-005).

## Layout

```
backend/config/payloads/
├── _keys/
│   ├── README.md                       (this file)
│   ├── .gitkeep                        (forces git to keep the dir)
│   ├── dev_signing.ed25519.priv        (DEV ONLY — gitignored, delete after signing)
│   └── <key_id>.ed25519.pub            (committed; the canonical public key)
├── SIGNATURES                          (committed; one line per YAML)
└── <family_id>.yaml                    (committed; one payload-family descriptor per file)
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
* `relative_yaml_path`   — POSIX path relative to `backend/config/payloads/`.
* `ed25519_signature_b64` — base64-encoded Ed25519 signature over the raw YAML bytes.
* `public_key_id`        — short id (first 16 hex chars of `sha256(pub_key_raw)`).

Lines starting with `#` and empty lines are ignored.

## Generate dev keys (local development only)

```powershell
python backend/scripts/payloads_sign.py generate-keys --out backend/config/payloads/_keys
```

This emits `dev_signing.ed25519.priv` (raw 32-byte private key) and
`<key_id>.ed25519.pub` (raw 32-byte public key).

## Sign all YAMLs

```powershell
python backend/scripts/payloads_sign.py sign `
    --key          backend/config/payloads/_keys/dev_signing.ed25519.priv `
    --payloads-dir backend/config/payloads `
    --out          backend/config/payloads/SIGNATURES
```

Re-running is idempotent and rewrites `SIGNATURES` from scratch.

## Verify all YAMLs

```powershell
python backend/scripts/payloads_sign.py verify `
    --payloads-dir backend/config/payloads `
    --signatures   backend/config/payloads/SIGNATURES `
    --keys-dir     backend/config/payloads/_keys
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

The signed registry is the last line of defence between an attacker who
manages to commit a malicious payload-family YAML (e.g. via a poisoned PR)
and the validator: without a valid signature the descriptor is refused at
startup, so the malicious payload bytes never reach
`PayloadBuilder.build`. The mutation/encoder allow-lists are the second line
of defence (no shell metacharacters can ever flow through pure-string
encoders to the sandbox).
