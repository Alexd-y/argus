"""CVSS v3.1 auto-scoring from OWASP category and vulnerability keywords.

When a finding reaches the pipeline without an explicit CVSS vector, this
module derives a reasonable default from the OWASP Top 10:2025 category ID
combined with a keyword scan of the finding title/category. The result is
a (score, severity_label, vector_string) triple that can be back-filled
into the finding dict before persistence.

Pure-Python CVSS v3.1 base-score calculator — no external dependencies
beyond stdlib and the project's own ``severity_label`` helper.
"""

from __future__ import annotations

import math
from typing import Any

from pydantic import BaseModel, Field

from src.findings.cvss import severity_label

_AV_WEIGHTS: dict[str, float] = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC_WEIGHTS: dict[str, float] = {"L": 0.77, "H": 0.44}
_PR_WEIGHTS: dict[str, dict[str, float]] = {
    "N": {"U": 0.85, "C": 0.85},
    "L": {"U": 0.62, "C": 0.68},
    "H": {"U": 0.27, "C": 0.50},
}
_UI_WEIGHTS: dict[str, float] = {"N": 0.85, "R": 0.62}
_C_WEIGHTS: dict[str, float] = {"N": 0.00, "L": 0.22, "H": 0.56}
_I_WEIGHTS: dict[str, float] = {"N": 0.00, "L": 0.22, "H": 0.56}
_A_WEIGHTS: dict[str, float] = {"N": 0.00, "L": 0.22, "H": 0.56}


class CVSSVectorSpec(BaseModel):
    """Compact CVSS v3.1 metric vector specification."""

    av: str = Field(default="N", min_length=1, max_length=1)
    ac: str = Field(default="L", min_length=1, max_length=1)
    pr: str = Field(default="N", min_length=1, max_length=1)
    ui: str = Field(default="N", min_length=1, max_length=1)
    s: str = Field(default="U", min_length=1, max_length=1)
    c: str = Field(default="N", min_length=1, max_length=1)
    i: str = Field(default="N", min_length=1, max_length=1)
    a: str = Field(default="N", min_length=1, max_length=1)

    def to_vector_string(self) -> str:
        return (
            f"CVSS:3.1/AV:{self.av}/AC:{self.ac}/PR:{self.pr}"
            f"/UI:{self.ui}/S:{self.s}/C:{self.c}/I:{self.i}/A:{self.a}"
        )

    def compute_score(self) -> float:
        av = _AV_WEIGHTS.get(self.av, 0.85)
        ac = _AC_WEIGHTS.get(self.ac, 0.77)
        pr_scope = self.s if self.s in ("U", "C") else "U"
        pr = _PR_WEIGHTS.get(self.pr, _PR_WEIGHTS["N"]).get(pr_scope, 0.85)
        ui = _UI_WEIGHTS.get(self.ui, 0.85)
        conf = _C_WEIGHTS.get(self.c, 0.0)
        integ = _I_WEIGHTS.get(self.i, 0.0)
        avail = _A_WEIGHTS.get(self.a, 0.0)

        iss = 1.0 - (1.0 - conf) * (1.0 - integ) * (1.0 - avail)

        if self.s == "U":
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

        exploitability = 8.22 * av * ac * pr * ui

        if impact <= 0:
            return 0.0

        if self.s == "U":
            raw = min(impact + exploitability, 10.0)
        else:
            raw = min(1.08 * (impact + exploitability), 10.0)

        return math.ceil(raw * 10) / 10


OWASP_CVSS_MAP: list[tuple[tuple[str, str], CVSSVectorSpec]] = [
    (("A05", "sqli"), CVSSVectorSpec(av="N", ac="L", pr="N", ui="N", s="C", c="H", i="H", a="H")),
    (("A05", "xss"), CVSSVectorSpec(av="N", ac="L", pr="N", ui="R", s="C", c="L", i="L", a="N")),
    (("A05", "ssti"), CVSSVectorSpec(av="N", ac="L", pr="N", ui="N", s="C", c="H", i="H", a="H")),
    (("A05", "command"), CVSSVectorSpec(av="N", ac="L", pr="N", ui="N", s="C", c="H", i="H", a="H")),
    (("A05", "path_traversal"), CVSSVectorSpec(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="N", a="N")),
    (("A05", "ssrf"), CVSSVectorSpec(av="N", ac="L", pr="N", ui="N", s="C", c="H", i="L", a="N")),
    (("A05", "xxe"), CVSSVectorSpec(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="L", a="N")),
    (("A05", "nosql"), CVSSVectorSpec(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="N")),
    (("A05", "prompt_injection"), CVSSVectorSpec(av="N", ac="L", pr="N", ui="N", s="U", c="L", i="L", a="N")),
    (("A05", "open_redirect"), CVSSVectorSpec(av="N", ac="L", pr="N", ui="R", s="U", c="L", i="L", a="N")),
    (("A05", "rce"), CVSSVectorSpec(av="N", ac="L", pr="N", ui="N", s="C", c="H", i="H", a="H")),
    (("A02", "hsts"), CVSSVectorSpec(av="N", ac="H", pr="N", ui="R", s="U", c="L", i="L", a="N")),
    (("A02", "csp"), CVSSVectorSpec(av="N", ac="L", pr="N", ui="R", s="C", c="L", i="L", a="N")),
    (("A02", "misconfig"), CVSSVectorSpec(av="N", ac="L", pr="N", ui="N", s="U", c="L", i="N", a="N")),
    (("A04", "https"), CVSSVectorSpec(av="N", ac="H", pr="N", ui="N", s="U", c="H", i="L", a="N")),
    (("A01", "bola"), CVSSVectorSpec(av="N", ac="L", pr="L", ui="N", s="U", c="H", i="H", a="N")),
    (("A01", "idor"), CVSSVectorSpec(av="N", ac="L", pr="L", ui="N", s="U", c="H", i="H", a="N")),
    (("A01", "access"), CVSSVectorSpec(av="N", ac="L", pr="L", ui="N", s="U", c="H", i="H", a="N")),
    (("A07", "credential"), CVSSVectorSpec(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="N")),
    (("A07", "jwt"), CVSSVectorSpec(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="N")),
    (("A06", "rate"), CVSSVectorSpec(av="N", ac="L", pr="N", ui="N", s="U", c="N", i="L", a="H")),
    (("A03", "supply"), CVSSVectorSpec(av="N", ac="H", pr="N", ui="N", s="U", c="H", i="H", a="H")),
    (("A08", "integrity"), CVSSVectorSpec(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="H")),
    (("A09", "logging"), CVSSVectorSpec(av="N", ac="L", pr="N", ui="N", s="U", c="L", i="N", a="N")),
]

_FALLBACK_VECTOR = CVSSVectorSpec()


def auto_score_finding(finding: dict[str, Any]) -> tuple[float, str, str]:
    """Derive a CVSS v3.1 base score and vector from OWASP category + title.

    Returns (score, severity_label, vector_string).
    """
    owasp_id = str(finding.get("owasp_category", "") or "").upper()
    title = str(finding.get("title", "") or "").lower()
    category = str(finding.get("category", "") or "").lower()
    haystack = f"{category} {title}"

    for (prefix, keyword), spec in OWASP_CVSS_MAP:
        if owasp_id.startswith(prefix) and keyword in haystack:
            score = spec.compute_score()
            return score, severity_label(score), spec.to_vector_string()

    for (_, keyword), spec in OWASP_CVSS_MAP:
        if keyword in haystack:
            score = spec.compute_score()
            return score, severity_label(score), spec.to_vector_string()

    score = _FALLBACK_VECTOR.compute_score()
    return score, severity_label(score), _FALLBACK_VECTOR.to_vector_string()


class CVSSAutoScorer:
    """Stateless service that back-fills CVSS vectors into finding dicts."""

    def score_finding(self, finding: dict[str, Any]) -> dict[str, Any]:
        has_vector = bool(finding.get("cvss_vector") or finding.get("cvss_v3_vector"))
        if has_vector:
            finding.setdefault("cvss_auto_scored", False)
            finding.setdefault("cvss_overridden", False)
            return finding

        score, sev_label, vector = auto_score_finding(finding)
        finding["cvss"] = score
        finding["cvss_vector"] = vector
        finding["cvss_v3_vector"] = vector
        finding["cvss_v3_score"] = score
        finding["severity"] = sev_label.lower() if sev_label.lower() in (
            "critical", "high", "medium", "low", "none", "info", "informational",
        ) else finding.get("severity", "info")
        finding["cvss_auto_scored"] = True
        finding["cvss_overridden"] = False
        return finding

    def score_all_findings(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        for finding in findings:
            self.score_finding(finding)
        return findings
