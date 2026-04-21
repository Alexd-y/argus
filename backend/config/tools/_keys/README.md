# ARGUS Tool Catalog Signing Keys

Ed25519 keys used to sign every YAML descriptor under `backend/config/tools/`.
The application is **fail-closed**: at startup the signed tool registry
(`src.sandbox.tool_registry.ToolRegistry`) verifies every loaded YAML against
`backend/config/tools/SIGNATURES`; an unknown / mismatched / missing signature
makes startup abort. See `Backlog/dev1_md` §3 and §18.

## Layout

```
backend/config/tools/
├── _keys/
│   ├── README.md                       (this file)
│   ├── .gitkeep                        (forces git to keep the dir)
│   ├── dev_signing.ed25519.priv        (DEV ONLY — gitignored, delete after signing)
│   └── <key_id>.ed25519.pub            (committed; the canonical public key)
├── SIGNATURES                          (committed; one line per YAML)
└── *.yaml                              (committed; one tool descriptor per file)
```

Public keys (`<key_id>.ed25519.pub`) ARE committed: the tool registry is
fail-closed and cannot verify a signature without the matching public key, so
the artefact every operator needs to validate the catalog must live in the
repo (or be mounted from the same Kubernetes Secret in production).

Private keys (`*.priv`) are **never** committed and are listed in
`backend/.gitignore`. Workflow expectation: generate the dev pair, sign,
verify, then delete the private key. The public key stays in the repo.

## Format of `SIGNATURES`

One line per signed YAML, whitespace-separated:

```
<sha256_hex>  <relative_yaml_path>  <ed25519_signature_b64>  <public_key_id>
```

* `sha256_hex`           — lowercase hex SHA-256 of the raw YAML bytes (no normalisation).
* `relative_yaml_path`   — POSIX path relative to `backend/config/tools/`.
* `ed25519_signature_b64` — base64-encoded Ed25519 signature over the raw YAML bytes.
* `public_key_id`        — short id (first 16 hex chars of `sha256(pub_key_raw)`).

Lines starting with `#` and empty lines are ignored.

## Generate dev keys (local development only)

```powershell
python backend/scripts/tools_sign.py --generate-keys --out backend/config/tools/_keys
```

This emits `dev_signing.ed25519.priv` (raw 32-byte private key) and
`dev_signing.ed25519.pub` (raw 32-byte public key) plus prints the
`public_key_id` to stdout.

## Sign all YAMLs

```powershell
python backend/scripts/tools_sign.py --sign `
    --key       backend/config/tools/_keys/dev_signing.ed25519.priv `
    --tools-dir backend/config/tools `
    --out       backend/config/tools/SIGNATURES
```

Re-running is idempotent and rewrites `SIGNATURES` from scratch.

## Verify all YAMLs

```powershell
python backend/scripts/tools_sign.py --verify `
    --tools-dir   backend/config/tools `
    --signatures  backend/config/tools/SIGNATURES `
    --keys-dir    backend/config/tools/_keys
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
manages to commit a malicious YAML (e.g. via a poisoned PR) and the sandbox
runner: without a valid signature the descriptor is refused at startup, so
the malicious command never reaches `ShellToolAdapter.build_command`. The
allowlist enforced by `src.sandbox.templating` is the second line of defence
(no shell metacharacters can ever reach the argv list).
