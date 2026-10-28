"""Intel adapters — Shodan, NVD, GitHub, Exploit-DB. Optional: Censys, crt.sh.

Dark Web Monitoring adapters (gated, off-by-default): Ahmia, DeHashed,
LeakCheck, Psbdmp.
"""

from src.data_sources.ahmia_client import AhmiaClient
from src.data_sources.censys_client import CensysClient
from src.data_sources.crtsh_client import CrtShClient
from src.data_sources.dehashed_client import DehashedClient
from src.data_sources.exploitdb_client import ExploitDBClient
from src.data_sources.github_client import GitHubClient
from src.data_sources.hibp_client import HIBPClient
from src.data_sources.leakcheck_client import LeakCheckClient
from src.data_sources.nvd_client import NVDClient
from src.data_sources.psbdmp_client import PsbdmpClient
from src.data_sources.securitytrails_client import SecurityTrailsClient
from src.data_sources.shodan_client import ShodanClient
from src.data_sources.virustotal_client import VirusTotalClient

__all__ = [
    "AhmiaClient",
    "CensysClient",
    "CrtShClient",
    "DehashedClient",
    "ExploitDBClient",
    "GitHubClient",
    "HIBPClient",
    "LeakCheckClient",
    "NVDClient",
    "PsbdmpClient",
    "SecurityTrailsClient",
    "ShodanClient",
    "VirusTotalClient",
]
