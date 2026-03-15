# ARGUS Recon Module

Modular reconnaissance orchestration system for authorized web application pentesting.

> **IMPORTANT**: This system is designed exclusively for **authorized security assessments**.
> All operations must be within an explicitly defined scope and rules of engagement.

## Architecture

```
src/recon/
├── adapters/            # Tool adapter interfaces + implementations
│   ├── base.py          # ToolAdapter ABC + ToolResult
│   ├── registry.py      # Central adapter registry
│   ├── subfinder_adapter.py
│   └── httpx_adapter.py
├── normalization/       # Raw → canonical normalization
│   ├── pipeline.py      # Orchestrates normalization + DB persistence
│   └── dedup.py         # Deduplication logic
├── reporting/           # Report builders
│   ├── csv_builder.py   # CSV reports (assets, services, APIs, params)
│   ├── markdown_builder.py  # MD reports (summary, hypotheses, attack surface)
│   └── generator.py     # Orchestrates all report generation
├── scope/               # Scope validation & enforcement
│   ├── validator.py     # ScopeValidator class
│   └── enforcement.py   # DB-integrated scope checking
├── jobs/                # Job orchestration
│   └── runner.py        # Celery task for recon job execution
├── ai_prep/             # AI input bundle preparation
│   └── bundler.py       # Sanitized data packages for LLM analysis
├── schemas/             # Pydantic schemas
│   ├── base.py          # Enums (ReconStage, FindingType, etc.)
│   ├── scope.py         # Scope rules and config
│   ├── findings.py      # 15 canonical finding types
│   ├── engagement.py    # Engagement CRUD schemas
│   ├── target.py        # Target CRUD schemas
│   ├── job.py           # Job CRUD schemas
│   ├── artifact.py      # Artifact response schemas
│   └── hypothesis.py    # Hypothesis CRUD schemas
├── services/            # Business logic
│   ├── engagement_service.py
│   ├── target_service.py
│   ├── scanjob_service.py
│   └── artifact_service.py
├── cli/                 # Typer CLI commands
│   └── commands/
│       ├── init_engagement.py  # Folder structure generation
│       ├── status.py           # Engagement status display
│       └── export.py           # Artifact export to local FS
└── storage.py           # MinIO storage with hierarchical keys
```

## Database Models

Located in `src/db/models_recon.py`:

| Model | Table | Purpose |
|-------|-------|---------|
| Engagement | engagements | Pentest engagement container |
| ReconTarget | recon_targets | Specific target within engagement |
| ScanJob | scan_jobs | Individual tool/scan run |
| Artifact | artifacts | File stored in MinIO |
| NormalizedFinding | normalized_findings | Canonical recon finding |
| Hypothesis | hypotheses | Generated hypothesis |

## Recon Stages (0-18)

| # | Stage | Description | Key Artifacts |
|---|-------|-------------|---------------|
| 0 | Scope Prep | Define scope and RoE | scope.txt, roe.txt |
| 1 | Domain/DNS | WHOIS, DNS records | dns_records.txt |
| 2 | Subdomain Enum | Passive subdomain discovery | subdomains_raw.txt |
| 3 | DNS Validation | Resolve and validate | resolved.txt, cname_map.csv |
| 4 | Live Hosts | HTTP probing | live_hosts.txt, http_probe.csv |
| 5 | Clustering | Group hosts by role | host_groups.md |
| 6 | Fingerprinting | Technology detection | tech_profile.csv |
| 7 | Entry Points | Standard endpoints | interesting_endpoints.txt |
| 8 | URL Crawling | URL collection | urls_raw.txt, urls_dedup.txt |
| 9 | Parameters | Parameter analysis | param_inventory.csv |
| 10 | JS Analysis | JavaScript inspection | js_findings.md |
| 11 | API Surface | API discovery | api_inventory.csv |
| 12 | Port Scanning | Service detection | service_inventory.csv |
| 13 | TLS/Headers | SSL and security headers | headers_summary.md |
| 14 | Content Discovery | Hidden paths | content_discovery.txt |
| 15 | OSINT | Public source intelligence | github_findings.md |
| 16 | Hypothesis | Generate hypotheses | hypotheses.md |
| 17 | Attack Map | Attack surface map | attack_surface.md |
| 18 | Reporting | Final reports | recon_summary.md |

## API Endpoints

All endpoints are prefixed with `/api/v1/recon/`.

### Engagements
- `POST /engagements` — Create engagement
- `GET /engagements` — List engagements
- `GET /engagements/{id}` — Get engagement with stats
- `PATCH /engagements/{id}` — Update engagement
- `POST /engagements/{id}/activate` — Activate (requires scope rules)
- `POST /engagements/{id}/complete` — Mark as completed

### Targets
- `POST /engagements/{id}/targets` — Add target (scope-validated)
- `GET /engagements/{id}/targets` — List targets
- `GET /targets/{id}` — Get target
- `DELETE /targets/{id}` — Delete target

### Jobs
- `POST /engagements/{id}/jobs` — Create scan job
- `GET /engagements/{id}/jobs` — List jobs
- `GET /jobs/{id}` — Get job detail
- `POST /jobs/{id}/cancel` — Cancel job

### Artifacts & Findings
- `GET /engagements/{id}/artifacts` — List artifacts
- `GET /artifacts/{id}` — Get artifact metadata
- `GET /artifacts/{id}/download` — Get download URL
- `GET /engagements/{id}/findings` — List findings
- `GET /findings/{id}` — Get finding detail

## CLI Usage

```bash
# Initialize engagement workspace
python -m src.recon.cli.main init create "my-engagement" --output-dir ./output --scope-file scope.txt

# Check engagement status
python -m src.recon.cli.main status show <engagement-id>

# Export artifacts to local directory
python -m src.recon.cli.main export artifacts <engagement-id> --output-dir ./export
```

## Scope Enforcement

Scope is enforced at three levels:

1. **Target creation** — targets must match engagement scope rules
2. **Job creation** — engagement must be in `active` status
3. **Tool output** — adapter filters out-of-scope results

### Scope Configuration Example

```json
{
  "rules": [
    {"rule_type": "include", "value_type": "domain", "pattern": "example.com"},
    {"rule_type": "include", "value_type": "cidr", "pattern": "10.0.0.0/24"},
    {"rule_type": "exclude", "value_type": "domain", "pattern": "internal.example.com"}
  ],
  "wildcard_subdomains": true,
  "max_rate_per_second": 10,
  "roe_text": "Authorized for external recon only. No DoS."
}
```

## MinIO Storage

Artifacts are stored with hierarchical keys:

```
engagements/{engagement_id}/targets/{target_id}/jobs/{job_id}/{stage_name}/{filename}
```

Example: `engagements/abc123/targets/def456/jobs/ghi789/02_subdomains/subdomains_raw.txt`

## Adding a New Tool Adapter

1. Create `src/recon/adapters/my_tool_adapter.py`:

```python
from src.recon.adapters.base import ToolAdapter

class MyToolAdapter(ToolAdapter):
    @property
    def name(self) -> str:
        return "mytool"

    @property
    def supported_stages(self) -> list[int]:
        return [2]  # Which recon stages this tool supports

    async def build_command(self, target, config):
        return ["mytool", "-d", target, "-json"]

    async def parse_output(self, raw_output):
        # Parse tool-specific output into dicts
        return [{"subdomain": line} for line in raw_output.splitlines() if line]

    async def normalize(self, raw_results):
        # Convert to canonical finding format
        return [{
            "finding_type": "subdomain",
            "value": r["subdomain"],
            "data": {"subdomain": r["subdomain"], "source": "mytool"},
            "source_tool": "mytool",
            "confidence": 0.8,
        } for r in raw_results]
```

2. Register in `src/recon/adapters/registry.py`:
```python
from src.recon.adapters.my_tool_adapter import MyToolAdapter
register(MyToolAdapter())
```

## Configuration

Environment variables (in `.env`):

| Variable | Default | Description |
|----------|---------|-------------|
| RECON_TOOLS_TIMEOUT | 300 | Tool execution timeout (seconds) |
| RECON_MAX_CONCURRENT_JOBS | 5 | Max parallel recon jobs |
| RECON_ARTIFACT_BUCKET | argus-recon | MinIO bucket for recon artifacts |
| RECON_DEFAULT_DNS_RESOLVER | 8.8.8.8 | Default DNS resolver |
| RECON_SCOPE_STRICT | true | Enforce strict scope checking |
| RECON_RATE_LIMIT_PER_SECOND | 10 | Default rate limit |
| RECON_MAX_SUBDOMAINS | 10000 | Max subdomains per target |

## Non-Goals

This module does NOT implement:
- Exploit execution or payload generation
- Vulnerability exploitation
- Authentication bypass attempts
- Credential stuffing or brute force
- Stealth/evasion techniques
- Persistence mechanisms
- Denial-of-service testing

## Stage 1 (Upgraded Recon Flow)

Stage 1 report pipeline now includes:

- baseline contract snapshot (`stage1_contract_baseline.json`)
- MCP audit linkage (`mcp_invocation_audit_meta.json`, `mcp_invocation_audit.jsonl`)
- upgraded enrichment artifacts (routes/forms/params/js/api/clusters/anomaly/stage2 prep)
- 7 AI task persistence bundles + schema contracts

Main modules:

- `src/recon/reporting/stage1_report_generator.py`
- `src/recon/reporting/stage1_enrichment_builder.py`
- `src/recon/reporting/stage1_contract.py`
- `src/recon/mcp/policy.py`
- `src/recon/mcp/audit.py`

Reference documentation:

- `docs/recon-stage1-flow.md`

## Methodology Mapping

Requirements are derived from two methodology documents:
- `Recon/Recon.md` — Full recon methodology (stages, tools, outputs)
- `Recon/Recon checklist.md` — Step-by-step checklist with folder structure

Key mappings:
- Stages 0-18 → Methodology steps 0-18
- Canonical finding types → Data categories from methodology
- CSV columns → Inventory formats from checklist
- Folder structure → `recon/` tree from checklist
- AI prompts → Templates from methodology section 12
