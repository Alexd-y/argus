"""OSINT/Intel adapters for Stage 1 recon — Shodan, NVD, crt.sh, RDAP, etc."""

from src.recon.adapters.intel.abuseipdb_adapter import AbuseIpDbIntelAdapter
from src.recon.adapters.intel.base import IntelAdapter, _finding
from src.recon.adapters.intel.censys_adapter import CensysIntelAdapter
from src.recon.adapters.intel.crtsh_adapter import CrtShIntelAdapter
from src.recon.adapters.intel.exploitdb_adapter import ExploitDbIntelAdapter
from src.recon.adapters.intel.github_adapter import GitHubIntelAdapter
from src.recon.adapters.intel.greynoise_adapter import GreyNoiseIntelAdapter
from src.recon.adapters.intel.nvd_adapter import NvdIntelAdapter
from src.recon.adapters.intel.otx_adapter import OtxIntelAdapter
from src.recon.adapters.intel.rdap_adapter import RdapIntelAdapter
from src.recon.adapters.intel.securitytrails_adapter import SecurityTrailsIntelAdapter
from src.recon.adapters.intel.shodan_adapter import ShodanIntelAdapter
from src.recon.adapters.intel.urlscan_adapter import UrlScanIntelAdapter
from src.recon.adapters.intel.virustotal_adapter import VirusTotalIntelAdapter

__all__ = [
    "IntelAdapter",
    "_finding",
    "ShodanIntelAdapter",
    "CrtShIntelAdapter",
    "RdapIntelAdapter",
    "NvdIntelAdapter",
    "GitHubIntelAdapter",
    "ExploitDbIntelAdapter",
    "CensysIntelAdapter",
    "SecurityTrailsIntelAdapter",
    "VirusTotalIntelAdapter",
    "UrlScanIntelAdapter",
    "AbuseIpDbIntelAdapter",
    "GreyNoiseIntelAdapter",
    "OtxIntelAdapter",
]


def get_available_intel_adapters() -> list[IntelAdapter]:
    """Return list of intel adapters that are configured and available."""
    adapters = [
        ShodanIntelAdapter(),
        CrtShIntelAdapter(),
        RdapIntelAdapter(),
        NvdIntelAdapter(),
        GitHubIntelAdapter(),
        ExploitDbIntelAdapter(),
        CensysIntelAdapter(),
        SecurityTrailsIntelAdapter(),
        VirusTotalIntelAdapter(),
        UrlScanIntelAdapter(),
        AbuseIpDbIntelAdapter(),
        GreyNoiseIntelAdapter(),
        OtxIntelAdapter(),
    ]
    return [a for a in adapters if a.is_available()]
