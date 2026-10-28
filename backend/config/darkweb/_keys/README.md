# Dark Web Monitoring — catalog signing keys

The DWM YAML catalogs under `backend/config/darkweb/*.yaml` are Ed25519-signed
(the same machinery as the payloads/tools/prompts catalogs — `src.sandbox.signing`).

- `*.ed25519.pub` — committed trusted public keys (raw 32 bytes). `KeyManager`
  recomputes the key id from the bytes and trusts any pub key present here.
- `dev_signing.ed25519.priv` — the dev private key. **Never committed**
  (gitignored; delete after signing). Production keys come from the HSM / Vault /
  k8s Secret, never from `generate-keys`.

Re-sign after editing any catalog:

```
python backend/scripts/darkweb_sign.py sign \
  --key backend/config/payloads/_keys/dev_signing.ed25519.priv \
  --payloads-dir backend/config/darkweb \
  --out backend/config/darkweb/SIGNATURES
```

Verify:

```
python backend/scripts/darkweb_sign.py verify \
  --payloads-dir backend/config/darkweb \
  --signatures backend/config/darkweb/SIGNATURES \
  --keys-dir backend/config/darkweb/_keys
```
