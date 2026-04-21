# Optional e2e vulnerable targets (Juice Shop, DVWA, WebGoat)

Compose: `infra/docker-compose.vuln-targets.yml`

Purpose: fast Playwright smoke tests (`Frontend/tests/e2e/vuln-targets/`) that prove a lab container responds. This is **not** the ARG-047 full-stack scan (`infra/docker-compose.e2e.yml` + `scripts/e2e_full_scan.sh`).

## Safety

- Run only on isolated lab hosts or CI. Do not port-forward to untrusted networks.
- Do **not** commit lab passwords or API keys. WebGoat / DVWA test logins are passed via environment variables in CI (`E2E_WEBGOAT_*`), not checked into `.env` files.

## Pinning

Images use `name:tag@sha256:…` as recorded in Docker Hub at integration time. Bump tags/digests deliberately when upgrading lab versions.

## Local run (one target at a time)

```powershell
# From repo root
docker compose -f infra/docker-compose.vuln-targets.yml --profile dvwa up -d --wait
cd Frontend
$env:E2E_VULN_TARGET = "dvwa"
$env:E2E_VULN_BASE_URL = "http://127.0.0.1:40080"
$env:PLAYWRIGHT_NO_SERVER = "1"
npm run test:e2e:vuln-smoke
docker compose -f infra/docker-compose.vuln-targets.yml --profile dvwa down -v
```

Juice Shop profile: `juice-shop`, URL `http://127.0.0.1:3000`.  
WebGoat profile: `webgoat`, URL `http://127.0.0.1:48080` — set `E2E_WEBGOAT_USERNAME` and `E2E_WEBGOAT_PASSWORD` for the login step.

## CI

Workflow: `.github/workflows/e2e-vuln-target-smoke.yml` — matrix `target: [juice-shop, dvwa, webgoat]`. Non-Juice legs are `continue-on-error` (third-party image flake tolerance); see workflow comments.
