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
    }
    text = stdout or ""
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
