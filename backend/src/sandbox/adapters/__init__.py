"""ARGUS tool adapter implementations — one per wired tool.

Each adapter subclasses :class:`~src.sandbox.adapter_base.ShellToolAdapter`
so the tool registry can resolve ``adapter_factory`` lookups by class name.
The concrete parse wiring lives in :mod:`src.sandbox.parsers`; adapters
here are identity anchors for the catalog.
"""

from __future__ import annotations

from src.sandbox.adapters.amass_adapter import AmassAdapter
from src.sandbox.adapters.gowitness_adapter import GowitnessAdapter
from src.sandbox.adapters.grype_adapter import GrypeAdapter
from src.sandbox.adapters.hydra_adapter import HydraAdapter
from src.sandbox.adapters.joomscan_adapter import JoomscanAdapter
from src.sandbox.adapters.kiterunner_adapter import KiterunnerAdapter
from src.sandbox.adapters.kube_hunter_adapter import KubeHunterAdapter
from src.sandbox.adapters.masscan_adapter import MasscanAdapter
from src.sandbox.adapters.medusa_adapter import MedusaAdapter
from src.sandbox.adapters.naabu_adapter import NaabuAdapter
from src.sandbox.adapters.nikto_adapter import NiktoAdapter
from src.sandbox.adapters.nmap_full_adapter import NmapFullAdapter
from src.sandbox.adapters.openapi_scanner_adapter import OpenapiScannerAdapter
from src.sandbox.adapters.prowler_adapter import ProwlerAdapter
from src.sandbox.adapters.sslyze_adapter import SSLyzeAdapter
from src.sandbox.adapters.testssl_adapter import TestsslAdapter
from src.sandbox.adapters.trivy_fs_adapter import TrivyFSAdapter
from src.sandbox.adapters.trufflehog_adapter import TrufflehogAdapter
from src.sandbox.adapters.wpscan_adapter import WPScanAdapter
from src.sandbox.adapters.zap_baseline_adapter import ZAPBaselineAdapter

__all__ = [
    "AmassAdapter",
    "GowitnessAdapter",
    "GrypeAdapter",
    "HydraAdapter",
    "JoomscanAdapter",
    "KiterunnerAdapter",
    "KubeHunterAdapter",
    "MasscanAdapter",
    "MedusaAdapter",
    "NaabuAdapter",
    "NiktoAdapter",
    "NmapFullAdapter",
    "OpenapiScannerAdapter",
    "ProwlerAdapter",
    "SSLyzeAdapter",
    "TestsslAdapter",
    "TrivyFSAdapter",
    "TrufflehogAdapter",
    "WPScanAdapter",
    "ZAPBaselineAdapter",
]
