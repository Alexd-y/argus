# Parser batch T05 — heartbeat → mapped (top-20)

Cycle 6 worker task **T05** wires twenty catalog tools that previously fell through to the ARG-020 heartbeat path (`parsers.dispatch.unmapped_tool`) into first-class parsers.

## Methodology

- **Source of the top-20 set:** Backlog web-scanner cluster **§4.5–§4.10** (discovery / crawler text, CMS text helpers, `jsql` JSON export, SQL / NoSQL / SSTI heuristic probes including `arachni`, XSS JSON auxiliaries). The exact tool IDs are ratchet-pinned as `_T05_NEWLY_MAPPED` in `backend/tests/test_tool_catalog_coverage.py` (comment: *data-driven top-20 heartbeat → mapped batch*).
- **Registry anchors:** Inline **§4.x** comments next to each entry in `backend/src/sandbox/parsers/__init__.py` document which backlog slice and parser function apply (search for `Cycle 6 T05`).
- **Grouping rule:** Tools are merged by **stable stdout / file shape**—shared `TEXT_LINES` discovery and probe parsers vs dedicated `JSON_OBJECT` modules for `jsql` and XSS auxiliaries—so new tools in the same cluster extend an existing module when the wire format matches.
- **Proof:** Golden fixtures under `backend/tests/fixtures/heartbeat/t05/` plus `tests/integration/sandbox/parsers/test_t05_heartbeat_top20_dispatch.py` assert each ID hits a real parser, not the heartbeat fallback.

## Modules

| Module | Tools | Strategy |
| --- | --- | --- |
| `discovery_text_parser.py` | `gobuster_dir`, `gobuster_auth`, `paramspider`, `hakrawler`, `waybackurls`, `linkfinder`, `subjs`, `secretfinder`, `kxss`, `joomscan`, `cmsmap`, `magescan` | `TEXT_LINES` (MageScan tolerates JSON on stdout) |
| `xss_auxiliary_json_parser.py` | `xsstrike`, `xsser`, `playwright_xss_verify` | `JSON_OBJECT` |
| `jsql_probe_parser.py` | `jsql` | `JSON_OBJECT` |
| `sqli_probe_text_parser.py` | `ghauri`, `tplmap`, `nosqlmap`, `arachni` | `TEXT_LINES` (heuristic line match + redaction) |

## Ratchet

`backend/tests/test_tool_catalog_coverage.py` pins **118 mapped / 39 heartbeat** (157 descriptors, 0 `binary_blob`). New parsers must update `MAPPED_PARSER_COUNT` / `HEARTBEAT_PARSER_COUNT` in lock-step and extend `_T05_NEWLY_MAPPED` (or successor allow-list).

## Fixtures

Golden samples: `backend/tests/fixtures/heartbeat/t05/`. Integration tests: `tests/integration/sandbox/parsers/test_t05_heartbeat_top20_dispatch.py`.

## Docs regeneration

After YAML or registry changes, prefer `python -m scripts.docs_tool_catalog --out ../docs/tool-catalog.md` so parser-status columns stay deterministic.
