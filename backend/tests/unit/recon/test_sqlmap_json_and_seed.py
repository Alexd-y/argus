"""sqlmap JSON-POST support + operator-seeded injection surfaces.

The juice-shop login SQLi lives in a JSON API (`POST /rest/user/login`, email
param). Before this, build_sqlmap_va_argv dropped JSON bodies (only `k=v` got
`--data`), so sqlmap probed the login as a parameterless GET and never confirmed
the injection; and the crawler never surfaced the SPA's XHR endpoint. These
guard the JSON argv + the seed path that fix both.
"""

from __future__ import annotations

from src.recon.vulnerability_analysis.active_scan.input_surface_inventory import (
    input_surface_items_from_seed,
)
from src.recon.vulnerability_analysis.active_scan.sqlmap_va_adapter import (
    build_sqlmap_va_argv,
    normalize_sqlmap_findings,
    parse_sqlmap_stdout,
)

_LOGIN = "http://juice-shop:3000/rest/user/login"

# Real sqlmap confirmation output for the juice-shop JSON login SQLi.
_SQLMAP_CONFIRMED = """sqlmap identified the following injection point(s) with a total of 442 HTTP(s) requests:
---
Parameter: JSON email ((custom) POST)
    Type: boolean-based blind
    Title: SQLite boolean-based blind - WHERE clause
    Payload: {"email":"argus_probe' AND CASE WHEN 7881=7881 THEN 7881 ELSE 1 END-- Wnam"}
---
back-end DBMS: SQLite"""


def test_json_body_is_passed_with_content_type() -> None:
    argv = build_sqlmap_va_argv(_LOGIN, '{"email":"argus_probe"}')
    assert "--data" in argv
    assert argv[argv.index("--data") + 1] == '{"email":"argus_probe"}'
    assert "-H" in argv
    assert argv[argv.index("-H") + 1] == "Content-Type: application/json"


def test_ignore_code_is_added() -> None:
    # Without --ignore-code sqlmap aborts on the login's 401 and never confirms.
    argv = build_sqlmap_va_argv(_LOGIN, '{"email":"p"}')
    assert "--ignore-code" in argv
    assert argv[argv.index("--ignore-code") + 1] == "401,403"


# Real mid-run output: sqlmap PROVES the injection ("parameter 'q' is '...'
# injectable") within seconds, but at --level 3 the final "Parameter:"/"Payload:"
# summary only prints ~237s later — past the 300s per-tool timeout, so a loaded
# run is killed before it. Detection must not depend on reaching the summary.
_SQLMAP_MIDRUN_NO_SUMMARY = """[09:24:02] [INFO] testing connection to the target URL
[09:24:03] [WARNING] heuristic (basic) test shows that GET parameter 'q' might not be SQL injectable
[09:24:04] [INFO] GET parameter 'q' appears to be 'AND boolean-based blind - WHERE or HAVING clause' injectable (with --string="oblonga")
[09:24:04] [INFO] heuristic (extended) test shows that the back-end DBMS could be 'SQLite'
[09:24:04] [INFO] GET parameter 'q' is 'SQLite >= 3.9 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (JSON path)' injectable
"""


def test_midrun_injectable_without_summary_is_detected() -> None:
    rows = parse_sqlmap_stdout(_SQLMAP_MIDRUN_NO_SUMMARY)
    assert len(rows) == 1
    assert rows[0]["param"] == "q"
    # The confirmed verdict ("is '...' injectable") wins over the tentative one.
    assert "error-based" in (rows[0]["injection_type"] or "")


def test_midrun_injectable_becomes_cwe89_finding() -> None:
    url = "http://juice-shop:3000/rest/products/search?q=1"
    findings = normalize_sqlmap_findings(
        parse_sqlmap_stdout(_SQLMAP_MIDRUN_NO_SUMMARY),
        target_url=url,
        argv=build_sqlmap_va_argv(url, None),
    )
    assert len(findings) == 1
    assert findings[0]["data"]["cwe"] == "CWE-89"


def test_negative_verdict_is_not_a_false_positive() -> None:
    neg = (
        "[INFO] testing connection to the target URL\n"
        "[WARNING] GET parameter 'q' does not seem to be injectable\n"
        "[CRITICAL] all tested parameters do not appear to be injectable\n"
    )
    assert parse_sqlmap_stdout(neg) == []


def test_parser_handles_json_multiword_param() -> None:
    # The real confirmation names the param "JSON email ((custom) POST)".
    rows = parse_sqlmap_stdout(_SQLMAP_CONFIRMED)
    assert len(rows) == 1
    assert rows[0]["param"] == "JSON email"
    assert rows[0]["dbms"] == "SQLite"
    assert "boolean-based blind" in rows[0]["injection_type"]


def test_confirmed_output_becomes_cwe89_high_finding() -> None:
    rows = parse_sqlmap_stdout(_SQLMAP_CONFIRMED)
    findings = normalize_sqlmap_findings(
        rows, target_url=_LOGIN, argv=build_sqlmap_va_argv(_LOGIN, '{"email":"p"}')
    )
    assert len(findings) == 1
    d = findings[0]["data"]
    assert d["cwe"] == "CWE-89"
    assert d["severity"] == "high"


def test_form_body_passed_without_json_header() -> None:
    argv = build_sqlmap_va_argv(_LOGIN, "email=argus_probe")
    assert "--data" in argv
    assert argv[argv.index("--data") + 1] == "email=argus_probe"
    assert "-H" not in argv


def test_garbage_body_not_passed() -> None:
    # Not JSON ({...}) and no '=' → not a usable body.
    argv = build_sqlmap_va_argv(_LOGIN, "just some words")
    assert "--data" not in argv


def test_newline_body_rejected() -> None:
    argv = build_sqlmap_va_argv(_LOGIN, '{"email":"a"}\nX-Evil: 1')
    assert "--data" not in argv


def test_level_risk_from_settings(monkeypatch) -> None:
    import src.recon.vulnerability_analysis.active_scan.sqlmap_va_adapter as mod

    monkeypatch.setattr(mod, "_sqlmap_level_risk", lambda: ("3", "2"))
    argv = build_sqlmap_va_argv(_LOGIN, None)
    assert argv[argv.index("--level") + 1] == "3"
    assert argv[argv.index("--risk") + 1] == "2"


def test_seed_surface_builds_login_email_json() -> None:
    items = input_surface_items_from_seed(
        [
            {
                "url": _LOGIN,
                "param_name": "email",
                "method": "POST",
                "location": "json",
                "content_type": "application/json",
                "auth_context": "anonymous",
            }
        ]
    )
    assert len(items) == 1
    it = items[0]
    assert it.param_name == "email"
    assert it.method == "POST"
    assert it.location == "json"
    assert it.url == _LOGIN


def test_seed_ignores_non_dict_and_empty() -> None:
    assert input_surface_items_from_seed([]) == []
    assert input_surface_items_from_seed(["x", 1, None]) == []
    assert input_surface_items_from_seed("nope") == []


def test_argv_json_param_extraction() -> None:
    from src.recon.vulnerability_analysis.active_scan.va_active_scan_phase import (
        _sqlmap_argv_json_param,
    )

    body, param = _sqlmap_argv_json_param(
        ["sqlmap", "-u", _LOGIN, "--data", '{"email":"argus_probe"}']
    )
    assert body == {"email": "argus_probe"}
    assert param == "email"
    # Form body / no --data → None (nothing to re-prove as JSON).
    assert _sqlmap_argv_json_param(["sqlmap", "-u", _LOGIN, "--data", "email=x"]) is None
    assert _sqlmap_argv_json_param(["sqlmap", "-u", _LOGIN]) is None
