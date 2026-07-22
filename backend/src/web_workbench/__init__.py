"""ARGUS Web Security Workbench.

Native, in-scope-only implementation of Burp Suite Professional / DAST-class
workflows built on top of the existing ARGUS platform (pipeline, sandbox, MCP,
PayloadRegistry, PromptRegistry, playbooks, Nuclei, OAST, evidence, reporting).

Every active operation is gated by the shared :mod:`src.policy` layer
(``ScopeEngine`` → ``PreflightChecker`` → EAP) and a signed
:class:`~src.policy.engagement_authorization.EngagementAuthorizationProfile`.

Phase 1 (WB-P1-FOUNDATION) delivers the project / scope / EAP foundation:
domain contracts, persisted models (see :mod:`src.db.models_web_workbench`) and
a service that reuses the existing scope + engagement-authorization primitives.
Subsequent phases add the proxy, manual tools, scanner, extensions, AI/MCP and
reporting slices (see the plan doc
``ai_docs/develop/plans/2026-07-22-argus-web-workbench.md``).
"""

__all__: list[str] = []
