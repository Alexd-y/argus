"""ARG-044 — Celery sub-package for ARGUS-specific scheduling.

This package coexists with the upstream :mod:`celery` distribution. Only
ARGUS-internal modules import from ``src.celery`` (absolute imports);
the upstream library is reached via ``from celery import ...`` which
resolves through ``sys.path`` to the installed distribution.

Sub-modules:

* :mod:`src.celery.tasks.intel_refresh` — daily EPSS / KEV beat tasks.
* :mod:`src.celery.beat_schedule` — registry of beat schedules wired
  into the global Celery app at import time.
"""

from __future__ import annotations

__all__: list[str] = []
