"""HTTP fuzzer engine for quick pre-scan detection.

Sends payloads to target URLs via GET parameters and POST JSON bodies.
Compares responses against a baseline to detect genuine vulnerability
triggers while filtering out SPA-shell false positives.

This is intentionally lightweight — no subprocess calls, no Docker sandbox,
just ``httpx`` requests with detection-signature matching. Heavy tools
(nuclei, sqlmap, dalfox) run in VULN_ANALYSIS only on candidate endpoints
identified here.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

from src.recon.quick_fuzz.candidate_builder import FuzzCandidate, build_candidates_from_fuzz_results
from src.recon.quick_fuzz.detection_sigs import DETECTION_SIGNATURES
from src.recon.quick_fuzz.payload_registry import load_payloads
from src.recon.quick_fuzz.spa_guard import is_same_response, is_spa_shell

logger = logging.getLogger(__name__)

_HTTP_TIMEOUT: float = 8.0
_MAX_PARAMS_PER_URL: int = 5
_MAX_PAYLOADS_PER_CATEGORY: int = 10


def _inject_param(url: str, param: str, payload: str) -> str:
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [payload]
    new_query = urlencode(params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def _extract_params(url: str) -> dict[str, list[str]]:
    parsed = urlparse(url)
    return parse_qs(parsed.query, keep_blank_values=True)


async def _fetch_baseline(client: httpx.AsyncClient, url: str) -> tuple[str, int, bool] | None:
    try:
        r = await client.get(url, timeout=_HTTP_TIMEOUT)
        return r.text, r.status_code, is_spa_shell(r.text)
    except Exception:
        return None


async def fuzz_url(
    client: httpx.AsyncClient,
    url: str,
    payloads: list[str],
    category: str,
    baseline_body: str,
    baseline_status: int,
    baseline_is_spa: bool,
    delay: float = 0.3,
) -> list[dict[str, Any]]:

    findings: list[dict[str, Any]] = []
    params = _extract_params(url)
    if not params:
        params = {"q": ["test"], "id": ["1"], "search": ["test"]}

    sigs = DETECTION_SIGNATURES.get(category, [])

    for param in list(params.keys())[:_MAX_PARAMS_PER_URL]:
        for payload in payloads[:_MAX_PAYLOADS_PER_CATEGORY]:
            fuzzed_url = _inject_param(url, param, payload)
            try:
                r = await client.get(fuzzed_url, timeout=_HTTP_TIMEOUT, follow_redirects=True)
                body = r.text
                body_lower = body.lower()
                size_diff = abs(len(r.content) - len(baseline_body.encode("utf-8", errors="replace")))

                same_response = is_same_response(
                    body, baseline_body, r.status_code, baseline_status,
                )
                if baseline_is_spa and same_response:
                    await asyncio.sleep(delay)
                    continue

                triggered = any(s.lower() in body_lower for s in sigs)

                if category == "ssti" and triggered:
                    triggered = bool(re.search(r"\b49\b", body))

                if category == "xss" and triggered:
                    encoded = payload.replace("<", "&lt;").replace(">", "&gt;")
                    if encoded in body and payload not in body:
                        triggered = False

                status_changed = r.status_code != baseline_status

                if triggered or (size_diff > 500 and status_changed):
                    findings.append({
                        "url": fuzzed_url,
                        "param": param,
                        "payload": payload[:80],
                        "category": category,
                        "status": r.status_code,
                        "size_diff": size_diff,
                        "triggered": triggered,
                        "response_snippet": body[:200],
                    })

                await asyncio.sleep(delay)

            except httpx.HTTPError:
                continue

    return findings


async def fuzz_post_json(
    client: httpx.AsyncClient,
    url: str,
    payloads: list[str],
    fields: list[str],
    category: str,
    delay: float = 0.3,
) -> list[dict[str, Any]]:

    findings: list[dict[str, Any]] = []
    sigs = DETECTION_SIGNATURES.get(category, [])

    for field in fields:
        for payload in payloads[:_MAX_PAYLOADS_PER_CATEGORY]:
            body_data = {field: payload}
            try:
                r = await client.post(url, json=body_data, timeout=_HTTP_TIMEOUT)
                resp_lower = r.text.lower()
                if any(s.lower() in resp_lower for s in sigs):
                    findings.append({
                        "url": url,
                        "param": field,
                        "payload": payload[:80],
                        "category": category,
                        "method": "POST/JSON",
                        "status": r.status_code,
                        "response_snippet": r.text[:200],
                        "triggered": True,
                    })
                await asyncio.sleep(delay)
            except httpx.HTTPError:
                continue

    return findings


async def run_quick_fuzz(
    target: str,
    categories: tuple[str, ...] | list[str] | None = None,
    custom_wordlist_path: str | None = None,
    delay: float = 0.3,
    console: Any | None = None,
) -> dict[str, Any]:

    payload_map = load_payloads(categories=categories, custom_wordlist_path=custom_wordlist_path)

    total_payloads = sum(len(v) for v in payload_map.values())

    if console:
        console.print(f"[bold cyan]═══ QUICK FUZZ[/bold cyan] → {target}")
        console.print(f"[dim]Categories: {list(payload_map.keys())} — {total_payloads} payloads[/dim]")

    async with httpx.AsyncClient(
        headers={"User-Agent": "ARGUS-QuickFuzz/1.0"},
        follow_redirects=True,
    ) as client:
        baseline = await _fetch_baseline(client, target)
        if baseline is None:
            if console:
                console.print("[red]✗ Could not reach target for baseline[/red]")
            return {"findings": [], "fuzz_results": [], "candidates": []}
        baseline_body, baseline_status, baseline_is_spa = baseline

        all_fuzz_results: list[dict[str, Any]] = []

        for category, payloads in payload_map.items():
            if console:
                console.print(f"[bold]Fuzzing: {category.upper()}[/bold]")

            results = await fuzz_url(
                client, target, payloads, category,
                baseline_body, baseline_status, baseline_is_spa, delay,
            )
            all_fuzz_results.extend(results)

            triggered = [r for r in results if r.get("triggered")]
            if console and triggered:
                for res in triggered:
                    console.print(
                        f"  [bold red]⚠ TRIGGERED[/bold red] "
                        f"{res['category']} — param={res['param']} "
                        f"payload={res['payload'][:40]}"
                    )

        all_findings: list[dict[str, Any]] = []
        for result in all_fuzz_results:
            if result.get("triggered"):
                category = result.get("category", "").lower()
                severity = "high" if category in ("sqli", "ssti", "command_injection", "xxe") else "medium"
                all_findings.append({
                    "module": "quick_fuzz",
                    "category": f"Injection ({category.upper()})",
                    "owasp_id": "A05",
                    "owasp_name": "Injection",
                    "severity": severity,
                    "title": f"{category.upper()} confirmed — param '{result.get('param', '')}'",
                    "description": f"Payload produced a distinctive response indicating {category.upper()} vulnerability.",
                    "evidence": (
                        f"URL: {result.get('url', '')}\n"
                        f"Param: {result.get('param', '')}\n"
                        f"Payload: {result.get('payload', '')}\n"
                        f"Response: {result.get('response_snippet', '')[:200]}"
                    ),
                    "fix": "Parameterize queries, validate/sanitize all inputs, use allowlists.",
                    "url": target,
                })

        candidates = build_candidates_from_fuzz_results(all_fuzz_results)

        if console:
            console.print(
                f"[green]✓ Quick fuzz complete — "
                f"{len(all_findings)} finding(s), {len(candidates)} candidate(s)[/green]"
            )

        return {
            "findings": all_findings,
            "fuzz_results": all_fuzz_results,
            "candidates": [c.model_dump() for c in candidates],
        }