"""Cairn — native port of the Cairn Fact–Intent blackboard search engine into ARGUS.

Cairn (https://github.com/oritera/Cairn, AGPL-3.0, v0.2.1) is a state-space search
engine built on a blackboard architecture with an explicit Fact–Intent graph. This
package ports its functionality natively onto ARGUS infrastructure (PostgreSQL +
RLS, Celery, sandbox, WhiteRabbitNeo) — there is no separate cairn-server /
cairn-dispatcher service and no SQLite.

Provenance / attribution is recorded in ``docs/third_party/cairn.md``. Deliberate
deviations from upstream (async, distributed writers via Postgres row locks instead
of a single-writer dispatcher, hardened sandbox execution) are recorded in
``docs/cairn_port_deviations.md``.

The subsystem is gated behind ``settings.cairn_enabled`` and is OFF by default.
"""
