"""Dark Web Monitoring collectors.

Each collector wraps a gated external source and turns a
:class:`~src.intel.dark_web.contracts.DarkWebSelector` into a list of raw
records. A collector whose source is not configured (no env key / disabled
channel) returns an empty list with a structured log — it NEVER raises.
"""

from __future__ import annotations

from src.intel.dark_web.collectors.ahmia_search import AhmiaSearchCollector
from src.intel.dark_web.collectors.base import BaseCollector, DarkWebCollector
from src.intel.dark_web.collectors.breach_hibp import HibpBreachCollector
from src.intel.dark_web.collectors.breach_leak_apis import (
    DehashedCollector,
    LeakCheckCollector,
)
from src.intel.dark_web.collectors.feeds import FeedsCollector
from src.intel.dark_web.collectors.hidden_networks import (
    ForumMonitorCollector,
    I2pCrawlerCollector,
    TelegramMonitorCollector,
    TorCrawlerCollector,
    hidden_network_collectors,
)
from src.intel.dark_web.collectors.intelx_search import IntelxSearchCollector
from src.intel.dark_web.collectors.paste_github import (
    GithubLeakCollector,
    PsbdmpPasteCollector,
)

__all__ = [
    "AhmiaSearchCollector",
    "BaseCollector",
    "DarkWebCollector",
    "DehashedCollector",
    "FeedsCollector",
    "ForumMonitorCollector",
    "GithubLeakCollector",
    "HibpBreachCollector",
    "I2pCrawlerCollector",
    "IntelxSearchCollector",
    "LeakCheckCollector",
    "PsbdmpPasteCollector",
    "TelegramMonitorCollector",
    "TorCrawlerCollector",
    "all_dark_web_collectors",
    "default_breach_first_collectors",
    "hidden_network_collectors",
]


def default_breach_first_collectors() -> list[BaseCollector]:
    """The breach-first MVP collector set (no Tor/I2P/Telegram — those are W-8)."""

    return [
        HibpBreachCollector(),
        DehashedCollector(),
        LeakCheckCollector(),
        PsbdmpPasteCollector(),
        AhmiaSearchCollector(),
        GithubLeakCollector(),
        IntelxSearchCollector(),
        FeedsCollector(),
    ]


def all_dark_web_collectors() -> list[BaseCollector]:
    """Breach-first + hidden-network collectors. Each is individually gated, so
    the hidden-network ones stay inert unless their sandbox transport is set."""

    return default_breach_first_collectors() + hidden_network_collectors()
