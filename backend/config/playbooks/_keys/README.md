# ARGUS Playbook Catalog Signing Keys

Ed25519 keys used to sign every YAML descriptor under `backend/config/playbooks/`.
The application is **fail-closed**: at startup `src.playbooks.registry.PlaybookRegistry`
verifies every loaded playbook against `backend/config/playbooks/SIGNATURES`; an
unknown / mismatched / missing signature aborts startup.

## Layout

```
backend/config/playbooks/
├── _keys/
│   ├── README.md                       (this file)
│   ├── dev_signing.ed25519.priv        (DEV ONLY - gitignored, delete after signing)
│   └── <key_id>.ed25519.pub            (committed; the canonical public key)
├── SIGNATURES                          (committed; one line per YAML)
└── <category>/<playbook_id>.yaml       (committed; one playbook per file)
```

Public keys (`<key_id>.ed25519.pub`) ARE committed. Private keys (`*.priv`)
are NEVER committed.

## Generate dev keys (local development only)

```powershell
python backend/scripts/playbooks_sign.py generate-keys --out backend/config/playbooks/_keys
```

## Sign all playbooks

```powershell
python backend/scripts/playbooks_sign.py sign `
    --key           backend/config/playbooks/_keys/dev_signing.ed25519.priv `
    --playbooks-dir backend/config/playbooks `
    --out           backend/config/playbooks/SIGNATURES
```

## Verify all playbooks

```powershell
python backend/scripts/playbooks_sign.py verify `
    --playbooks-dir backend/config/playbooks `
    --signatures    backend/config/playbooks/SIGNATURES `
    --keys-dir      backend/config/playbooks/_keys
```
