import re
from typing import Any, Literal

from pydantic import BaseModel

# Certificate fields are set by whoever controls the scanned endpoint, so strip
# control chars + Markdown/HTML metacharacters before they reach a renderer. ``*``
# is kept (legitimate in wildcard cert names, e.g. ``*.example.com``); emphasis
# runs are harmless compared with newlines/link/code/HTML injection.
_CERT_UNSAFE_RE = re.compile(r"[\x00-\x1f\x7f`#\[\]<>|\\~]")


def _clean_cert(value: str) -> str:
    s = _CERT_UNSAFE_RE.sub(" ", str(value or ""))
    return re.sub(r"\s+", " ", s).strip()[:512]


# Single shared weak-protocol registry (canonical lower-case labels) so the column
# parser and the reconcile step classify identically — no parser/validator drift.
WEAK_TLS_VERSIONS = frozenset({"sslv2", "sslv3", "tls 1.0", "tls 1.1"})


def canon_tls_version(raw: Any) -> str:
    """Canonical lower-case protocol label for comparison.

    ``TLSv1.1`` / ``TLS1.1`` / ``tls 1.1`` -> ``tls 1.1``; ``TLS 1`` / ``TLS1`` ->
    ``tls 1.0`` (missing minor is 1.0); ``SSLv2`` -> ``sslv2``. ``""`` when the
    token is not a recognised SSL/TLS version (so unrelated text never matches a
    weak-protocol or not-offered check)."""
    s = re.sub(r"\s+", " ", str(raw or "").strip().lower())
    m = re.match(r"ssl\s*v?\s*([23])\b", s)
    if m:
        return f"sslv{m.group(1)}"
    m = re.match(r"tls\s*v?\s*1(?:\.(\d))?\b", s)
    if m:
        return f"tls 1.{m.group(1) if m.group(1) is not None else '0'}"
    return ""


def _display_tls_version(canon: str) -> str:
    if canon.startswith("sslv"):
        return "SSLv" + canon[-1]
    if canon.startswith("tls "):
        return "TLS " + canon[4:]
    return canon


def reconcile_tls_protocols(
    legacy_protocols: Any, legacy_weak: Any, cf: dict[str, Any]
) -> tuple[list[str], list[str]]:
    """Combine the legacy token-scan protocol lists with the column parse WITHOUT
    fail-open: versions testssl reports ``not offered`` are the only authoritative
    negatives and are removed from both lists; every other legacy-flagged weak
    protocol is kept (never silently dropped). Classification uses the shared
    :data:`WEAK_TLS_VERSIONS` registry via :func:`canon_tls_version`."""
    not_off = {canon_tls_version(p) for p in (cf.get("not_offered") or [])}
    # Positive evidence wins: a version explicitly reported offered anywhere is NOT
    # a negative, even if another section said "not offered".
    not_off -= {canon_tls_version(p) for p in (cf.get("protocols") or [])}
    not_off.discard("")

    def _dropped(label: str) -> bool:
        cv = canon_tls_version(label)
        return bool(cv) and cv in not_off

    # Only the legacy token-scan entries are removable (they produced the false
    # positives); the column parse's offered/weak lists are authoritative positives
    # and are never dropped — no negative result erases positive weak evidence.
    protocols: list[str] = []
    for p in list(legacy_protocols or []):
        if p and not _dropped(p) and p not in protocols:
            protocols.append(p)
    for p in cf.get("protocols") or []:
        if p and p not in protocols:
            protocols.append(p)
    weak: list[str] = []
    for p in list(legacy_weak or []):
        if p and not _dropped(p) and p not in weak:
            weak.append(p)
    for p in cf.get("weak_protocols") or []:
        if p and p not in weak:
            weak.append(p)
    return protocols, weak


def parse_testssl_cert_fields(stdout: str) -> dict[str, Any]:
    """Extract issuer/subject/SAN/validity from testssl (or openssl) TLS text.

    testssl prints a column layout -- ``Issuer   <v>``, ``Common Name (CN)  <v>``,
    ``subjectAltName (SAN)  <hosts>``, ``Certificate Validity (UTC) ... (<from> --> <to>)``
    -- which the legacy openssl-oriented matcher missed, and its greedy ``Issuer``
    regex grabbed the CAA commentary line (``match with "Issuer" below``) instead of
    the real field. Anchor on the field line; also accept openssl ``issuer=``/``CN=``/
    ``notBefore=``/``notAfter=``. Returns empty strings/lists when absent.
    """
    out: dict[str, Any] = {
        "issuer": "",
        "subject": "",
        "san": [],
        "valid_from": "",
        "valid_to": "",
        "validity": "",
        "protocols": [],
        "weak_protocols": [],
        "not_offered": [],
    }
    text = stdout or ""
    # Protocols from testssl's per-version column. Record offered versions AND the
    # authoritative ``not offered`` negatives (the reconcile step removes the latter
    # from the legacy token scan). testssl prints e.g. ``SSLv2 not offered (OK)`` /
    # ``TLS 1.2 offered``. Classify weakness via the shared WEAK_TLS_VERSIONS set.
    for pm in re.finditer(
        r"(?mi)^[\s}]*(SSLv2|SSLv3|TLS\s*1(?:\.[0-3])?|TLSv1\.[0-3])\s+(not offered|offered)",
        text,
    ):
        canon = canon_tls_version(pm.group(1))
        if not canon:
            continue
        if pm.group(2).strip().lower() == "not offered":
            if canon not in out["not_offered"]:
                out["not_offered"].append(canon)
            continue
        label = _display_tls_version(canon)
        if label not in out["protocols"]:
            out["protocols"].append(label)
            if canon in WEAK_TLS_VERSIONS:
                out["weak_protocols"].append(label)
    # testssl prefixes some field lines with a stray ``}`` from its formatting, so
    # tolerate a leading brace/space before each label.
    m = re.search(r"(?mi)^[\s}]*Issuer\s{2,}(\S[^\n]*)", text) or re.search(
        r"(?i)\b(?:issuer=|i:)\s*(\S[^\n]*)", text
    )
    if m:
        cand = _clean_cert(m.group(1).strip().strip('"'))
        if cand and "below" not in cand.lower():
            out["issuer"] = cand
    m = re.search(r"(?mi)^[\s}]*Common Name \(CN\)\s+(\S[^\n,{]*)", text) or re.search(
        r"(?i)\bCN\s*=\s*([^\s,/]+)", text
    )
    if m:
        out["subject"] = _clean_cert(m.group(1))
    m = re.search(r"(?mi)^[\s}]*subjectAltName \(SAN\)\s+(\S[^\n{]*)", text)
    if m:
        out["san"] = [
            _clean_cert(h)
            for h in re.split(r"[\s,]+", m.group(1).strip())
            if h.strip() and "." in h
        ][:32]
    vm = re.search(
        r"Certificate Validity.*?\((\d{4}-\d\d-\d\d[^-]*?)-->\s*(\d{4}-\d\d-\d\d[^)]*)\)",
        text,
    )
    if vm:
        out["valid_from"] = vm.group(1).strip()[:64]
        out["valid_to"] = vm.group(2).strip()[:64]
    else:
        nb = re.search(r"(?i)(?:Not Before|notBefore=|Not valid before)\s*:?\s*(.+)", text)
        na = re.search(r"(?i)(?:Not After|notAfter=|Not valid after)\s*:?\s*(.+)", text)
        if nb:
            out["valid_from"] = nb.group(1).strip()[:64]
        if na:
            out["valid_to"] = na.group(1).strip()[:64]
    if out["valid_from"] and out["valid_to"]:
        out["validity"] = f"{out['valid_from']} - {out['valid_to']}"
    elif out["valid_to"]:
        out["validity"] = out["valid_to"]
    return out


class CertificateChain(BaseModel):
    issuer: str
    subject: str
    expiry: str
    san: list[str] = []
    depth: int = 1


class TlsProtocol(BaseModel):
    name: Literal["TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"]
    enabled: bool
    weak: bool = False


class CipherSuite(BaseModel):
    name: str
    strength: str
    key_exchange: str
    weak: bool = False


class TlsAnalysis(BaseModel):
    domain: str
    cert_chain: list[CertificateChain]
    protocols: list[TlsProtocol]
    ciphers: list[CipherSuite]
    hsts: str | None = None
    ocsp_stapling: bool = False
    weak_protocols: list[str] = []
    expiry_days: int = 0
    grade: str = "F"


def parse_testssl_output(stdout: str) -> TlsAnalysis:
    analysis = TlsAnalysis(domain="")

    for line in stdout.split("\n"):
        line_lower = line.lower()

        if "hostname" in line_lower:
            analysis.domain = extract_value(line, "hostname")

        if "protocol" in line_lower:
            if "tls 1.0" in line_lower and "not supported" in line_lower:
                analysis.protocols.append(TlsProtocol(name="TLSv1.0", enabled=False, weak=True))
            elif "tls 1.0" in line_lower:
                analysis.protocols.append(TlsProtocol(name="TLSv1.0", enabled=True, weak=True))
            elif "tls 1.1" in line_lower and "not supported" in line_lower:
                analysis.protocols.append(TlsProtocol(name="TLSv1.1", enabled=False, weak=True))
            elif "tls 1.1" in line_lower:
                analysis.protocols.append(TlsProtocol(name="TLSv1.1", enabled=True, weak=True))
            elif "tls 1.2" in line_lower:
                analysis.protocols.append(TlsProtocol(name="TLSv1.2", enabled=True, weak=False))
            elif "tls 1.3" in line_lower:
                analysis.protocols.append(TlsProtocol(name="TLSv1.3", enabled=True, weak=False))

        if (
            "ciphers" in line_lower
            and "weak" in line_lower
            and ("rc4" in line_lower or "des" in line_lower or "3des" in line_lower)
        ):
            analysis.ciphers.append(
                CipherSuite(
                    name=line.strip(),
                    strength="weak",
                    key_exchange="unknown",
                    weak=True,
                )
            )
            analysis.weak_protocols.append("weak ciphers detected")

        if "hsts" in line_lower and "max-age" in line_lower:
            analysis.hsts = extract_value(line, "max-age")

        if "ocsp stapling" in line_lower and "supported" in line_lower:
            analysis.ocsp_stapling = True

    calculate_expiry_days(analysis)

    return analysis


def parse_sslscan_output(stdout: str) -> TlsAnalysis:
    analysis = TlsAnalysis(domain="")

    for line in stdout.split("\n"):
        line_lower = line.lower()

        if "host" in line_lower:
            analysis.domain = extract_value(line, "host")

        if "ssl" in line_lower and "v1.0" in line_lower:
            analysis.protocols.append(
                TlsProtocol(name="TLSv1.0", enabled="accepted" in line_lower, weak=True)
            )

        if "ssl" in line_lower and "v1.1" in line_lower:
            analysis.protocols.append(
                TlsProtocol(name="TLSv1.1", enabled="accepted" in line_lower, weak=True)
            )

        if "ssl" in line_lower and "v1.2" in line_lower:
            analysis.protocols.append(
                TlsProtocol(name="TLSv1.2", enabled="accepted" in line_lower, weak=False)
            )

        if "ssl" in line_lower and "v1.3" in line_lower:
            analysis.protocols.append(
                TlsProtocol(name="TLSv1.3", enabled="accepted" in line_lower, weak=False)
            )

    return analysis


def parse_openssl_output(
    cert_pem: str,  # noqa: ARG001 - retained for signature/API compatibility
    protocols: str,
    ciphers: str,  # noqa: ARG001 - retained for signature/API compatibility
) -> TlsAnalysis:
    analysis = TlsAnalysis(domain="")

    for line in protocols.split("\n"):
        line_lower = line.lower()
        if "tls" in line_lower and "1.0" in line_lower:
            analysis.protocols.append(TlsProtocol(name="TLSv1.0", enabled=True, weak=True))
        elif "tls" in line_lower and "1.1" in line_lower:
            analysis.protocols.append(TlsProtocol(name="TLSv1.1", enabled=True, weak=True))
        elif "tls" in line_lower and "1.2" in line_lower:
            analysis.protocols.append(TlsProtocol(name="TLSv1.2", enabled=True, weak=False))
        elif "tls" in line_lower and "1.3" in line_lower:
            analysis.protocols.append(TlsProtocol(name="TLSv1.3", enabled=True, weak=False))

    analysis.cert_chain.append(
        CertificateChain(issuer="unknown", subject="unknown", expiry="unknown", depth=1)
    )

    return analysis


def extract_value(
    line: str, key: str  # noqa: ARG001 - retained for signature/API compatibility
) -> str:
    if ":" in line:
        parts = line.split(":", 1)
        if len(parts) > 1:
            return parts[1].strip()
    return ""


def calculate_expiry_days(analysis: TlsAnalysis) -> int:
    if not analysis.cert_chain:
        return 0

    expiry_str = analysis.cert_chain[0].expiry
    if expiry_str:
        try:
            from datetime import datetime

            expiry_date = datetime.fromisoformat(expiry_str.replace("Z", "+00:00"))
            from datetime import datetime as DT

            now = DT.now(expiry_date.tzinfo)
            analysis.expiry_days = (expiry_date - now).days
        except Exception:
            analysis.expiry_days = -1
    else:
        analysis.expiry_days = -1

    return analysis.expiry_days
