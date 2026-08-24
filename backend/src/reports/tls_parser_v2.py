from typing import Literal

from pydantic import BaseModel


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

        if "ciphers" in line_lower and "weak" in line_lower:
            if "rc4" in line_lower or "des" in line_lower or "3des" in line_lower:
                analysis.ciphers.append(CipherSuite(name=line.strip(), strength="weak", key_exchange="unknown", weak=True))
                analysis.weak_protocols.append("weak ciphers detected")

        if "hsts" in line_lower and "max-age" in line_lower:
            analysis.hsts = extract_value(line, "max-age")

        if "ocsp stapling" in line_lower:
            if "supported" in line_lower:
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
            analysis.protocols.append(TlsProtocol(name="TLSv1.0", enabled="accepted" in line_lower, weak=True))

        if "ssl" in line_lower and "v1.1" in line_lower:
            analysis.protocols.append(TlsProtocol(name="TLSv1.1", enabled="accepted" in line_lower, weak=True))

        if "ssl" in line_lower and "v1.2" in line_lower:
            analysis.protocols.append(TlsProtocol(name="TLSv1.2", enabled="accepted" in line_lower, weak=False))

        if "ssl" in line_lower and "v1.3" in line_lower:
            analysis.protocols.append(TlsProtocol(name="TLSv1.3", enabled="accepted" in line_lower, weak=False))

    return analysis


def parse_openssl_output(cert_pem: str, protocols: str, ciphers: str) -> TlsAnalysis:
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

    analysis.cert_chain.append(CertificateChain(issuer="unknown", subject="unknown", expiry="unknown", depth=1))

    return analysis


def extract_value(line: str, key: str) -> str:
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
