# XSStrike (plugin integration entrypoint in ARGUS)

Upstream: [s0md3v/XSStrike](https://github.com/s0md3v/XSStrike).

## Install (host / dev)

1. Clone into the vendor path (gitignored by default):

   ```bash
   mkdir -p vendor
   git clone --depth 1 https://github.com/s0md3v/XSStrike.git vendor/XSStrike
   cd vendor/XSStrike
   pip install -r requirements.txt
   ```

2. Or set `XSSTRIKE_SCRIPT` to an absolute path to `xsstrike.py`.

## Docker

The ARGUS **sandbox** image (`sandbox/Dockerfile`) installs XSStrike under `/opt/xsstrike`. With `sandbox_enabled=true`, the backend adapter runs:

`docker exec <sandbox> python3 /opt/xsstrike/xsstrike.py ...`

## Usage from ARGUS

See `backend/src/recon/vulnerability_analysis/xsstrike_adapter.py` — `XSStrikeAdapter.run(url, config)`.

Non-interactive scans use `--skip` (and optionally `--skip-dom` for speed).
