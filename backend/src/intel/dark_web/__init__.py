"""Dark Web Monitoring (DWM) — passive OSINT monitoring of hidden networks and
leak marketplaces for an *authorized* assessment target.

This package is an extension of the ``src.intel`` enrichment layer. It is
OFF BY DEFAULT and gated three ways (see ``gates.py``):

1. ``settings.dark_web_monitoring_enabled`` (global kill-switch, default False),
2. per-scan opt-in (``options.dark_web.enabled``), and
3. per-tenant entitlement (DWM is a paid Asgard/Valhalla capability).

Hard invariants enforced across the subsystem (see
``docs/develop/PROMPT-dark-web-monitoring.md`` §2-3):

* **Authorized-only / passive-only.** Selectors are drawn only from the
  engagement scope. No purchase/login/posting/join; no de-anonymisation.
* **Provability.** A DWM observation is external OSINT; it NEVER raises a
  :class:`~src.db.models.Finding` ``evidence_tier`` to CONFIRMED/EXPLOITED.
  The ceiling for a DWM signal is SUSPECTED (tier 2).
* **PII minimisation.** Raw records are stored encrypted in MinIO; passwords
  are stored as a presence flag / hash, never plaintext; reports mask PII.
"""

from __future__ import annotations

__all__: list[str] = []
