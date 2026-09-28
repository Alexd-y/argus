"""Attack narrative + impact chains builder (Part II, Phase K — prompt §16).

Turns findings into a chronological attack narrative and impact chains, keeping the
**proven** chain (every step backed by evidence) strictly separate from the
**hypothetical** chain (independent unproven steps are never merged into one chain —
FND-03). MITRE ATT&CK technique mapping is applied only where a finding's class
justifies it, not for completeness.

Pure module: it consumes :class:`ReportFinding` objects and returns
:class:`ReportAttackStep` / :class:`ReportExploitChain`. No DB / LLM / network.
"""

from __future__ import annotations

from src.reports.report_document import ReportAttackStep, ReportExploitChain, ReportFinding

_PROVEN = frozenset({"confirmed", "exploitable"})

#: Minimal, justified CWE/class → MITRE ATT&CK (tactic, technique) mapping.
_ATTACK_MAP: dict[str, tuple[str, str]] = {
    "sqli": ("TA0009", "T1190"),  # Collection / Exploit Public-Facing Application
    "rce": ("TA0002", "T1190"),  # Execution
    "cmdi": ("TA0002", "T1059"),  # Command and Scripting Interpreter
    "ssrf": ("TA0007", "T1190"),
    "xss": ("TA0001", "T1189"),  # Drive-by Compromise
    "idor": ("TA0007", "T1083"),
    "bola": ("TA0007", "T1083"),
    "auth_bypass": ("TA0006", "T1078"),  # Valid Accounts
}

_PHASE_BY_CLASS: dict[str, str] = {
    "auth_bypass": "entry",
    "sqli": "data_access",
    "idor": "data_access",
    "bola": "data_access",
    "rce": "privesc",
    "cmdi": "privesc",
    "ssrf": "entry",
    "xss": "entry",
}


def _phase(f: ReportFinding) -> str:
    if f.confirmation_class and f.confirmation_class in _PHASE_BY_CLASS:
        return _PHASE_BY_CLASS[f.confirmation_class]
    return "entry"


def _attack(f: ReportFinding) -> tuple[str | None, str | None]:
    if f.confirmation_class and f.confirmation_class in _ATTACK_MAP:
        return _ATTACK_MAP[f.confirmation_class]
    return (None, None)


def build_attack_narrative(findings: list[ReportFinding]) -> list[ReportAttackStep]:
    """Chronological narrative from proven findings only (each step has evidence)."""
    proven = [f for f in findings if f.verification_status in _PROVEN and f.evidence_ids]
    # Order by phase progression, then finding id for determinism.
    phase_rank = {"recon": 0, "entry": 1, "persistence": 2, "privesc": 3, "data_access": 4}
    proven.sort(key=lambda f: (phase_rank.get(_phase(f), 1), f.finding_id))
    steps: list[ReportAttackStep] = []
    for i, f in enumerate(proven, 1):
        tactic, technique = _attack(f)
        steps.append(
            ReportAttackStep(
                order_index=i,
                phase=_phase(f),
                description=f"{f.title} ({f.finding_id})",
                tactic=tactic,
                technique_id=technique,
                claim_ids=[c.claim_id for c in f.claims],
                evidence_ids=list(f.evidence_ids),
            )
        )
    return steps


def build_exploit_chains(findings: list[ReportFinding]) -> list[ReportExploitChain]:
    """Build proven + hypothetical chains, kept separate (FND-03).

    * Proven chain — the ordered proven-finding steps, if there are 2+ (a single
      step is not a "chain").
    * Hypothetical chains — one per suspected finding, never merged, each with an
      explicit ``to_verify`` list. Independent hypotheses are never joined.
    """
    chains: list[ReportExploitChain] = []
    proven_steps = build_attack_narrative(findings)
    if len(proven_steps) >= 2:
        chains.append(
            ReportExploitChain(
                chain_id="CH-proven-1",
                kind="proven",
                title="Proven impact chain",
                steps=proven_steps,
                outcome=proven_steps[-1].description,
            )
        )

    suspected = [f for f in findings if f.verification_status == "suspected"]
    for i, f in enumerate(suspected, 1):
        chains.append(
            ReportExploitChain(
                chain_id=f"CH-hyp-{i}",
                kind="hypothetical",
                title=f"Hypothetical: {f.title}",
                steps=[
                    ReportAttackStep(
                        order_index=1,
                        phase=_phase(f),
                        description=f"{f.title} ({f.finding_id})",
                    )
                ],
                to_verify=[
                    f.downgrade_reason
                    or "Reproduce with a discriminator and a negative control before asserting."
                ],
            )
        )
    return chains


__all__ = ["build_attack_narrative", "build_exploit_chains"]
