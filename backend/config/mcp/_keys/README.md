# ARGUS MCP Server Config Signing Keys

Ed25519 keys used to sign every YAML descriptor under `backend/config/mcp/`.
The MCP server (`src.mcp.server`) treats `server.yaml` as a tamper-evident
configuration: ops dashboards / CI gates verify the signed manifest before
deploying changes. See `Backlog/dev1_md` §13 (MCP server) and
`ai_docs/develop/plans/2026-04-19-argus-finalization-cycle3.md` (ARG-023).

## Layout

```
backend/config/mcp/
├── _keys/
│   ├── README.md                       (this file)
│   ├── dev_signing.ed25519.priv        (DEV ONLY — gitignored, delete after signing)
│   └── <key_id>.ed25519.pub            (committed; the canonical public key)
├── SIGNATURES                          (committed; one line per YAML)
└── server.yaml                         (committed; the MCP server contract)
```

Public keys (`<key_id>.ed25519.pub`) ARE committed. Private keys (`*.priv`)
are NEVER committed — they are listed in `backend/.gitignore`.

## Format of `SIGNATURES`

One line per signed YAML, whitespace-separated:

```
<sha256_hex>  <relative_yaml_path>  <ed25519_signature_b64>  <public_key_id>
```

Lines starting with `#` and empty lines are ignored.

## Workflow

```powershell
# 1. Generate dev keys (one-time, local only)
python backend/scripts/mcp_sign.py generate-keys --out backend/config/mcp/_keys

# 2. Re-sign every time you edit server.yaml
python backend/scripts/mcp_sign.py sign `
    --key     backend/config/mcp/_keys/dev_signing.ed25519.priv `
    --mcp-dir backend/config/mcp `
    --out     backend/config/mcp/SIGNATURES

# 3. Delete the private key (or move it to a vault)
Remove-Item backend/config/mcp/_keys/dev_signing.ed25519.priv

# 4. CI verifies on every PR
python backend/scripts/mcp_sign.py verify `
    --mcp-dir   backend/config/mcp `
    --signatures backend/config/mcp/SIGNATURES `
    --keys-dir  backend/config/mcp/_keys
```

## Production keys

* Generated **outside** the repository on a hardened workstation.
* Private key is pushed into a Kubernetes `Secret` and mounted via CSI into
  the signing container only. It MUST NEVER be checked into git.
* The public key (`<key_id>.ed25519.pub`) is the only artefact that lives in
  the repo (or is fetched at runtime from the same `Secret`).
* Rotate every 90 days or upon any suspected compromise. Record old key
  rotations in `ai_docs/security/key-rotation-log.md`.
