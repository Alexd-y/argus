"""Intel adapters — Shodan, NVD, GitHub, Exploit-DB. Optional: Censys, crt.sh."""

from src.data_sources.censys_client import CensysClient
from src.data_sources.crtsh_client import CrtShClient
from src.data_sources.exploitdb_client import ExploitDBClient
from src.data_sources.github_client import GitHubClient
from src.data_sources.hibp_client import HIBPClient
from src.data_sources.nvd_client import NVDClient
from src.data_sources.securitytrails_client import SecurityTrailsClient
from src.data_sources.shodan_client import ShodanClient
from src.data_sources.virustotal_client import VirusTotalClient

__all__ = [
    "CensysClient",
    "CrtShClient",
    "ExploitDBClient",
    "GitHubClient",
    "HIBPClient",
    "NVDClient",
    "SecurityTrailsClient",
    "ShodanClient",
    "VirusTotalClient",
]
