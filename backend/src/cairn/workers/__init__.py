"""Cairn worker drivers.

The primary driver is :class:`~src.cairn.workers.wrb.WrbAgentDriver`, which runs a
``ReActAgent`` over ``call_llm_unified`` (WhiteRabbitNeo). CLI parity drivers
(claude/codex/pi) are opt-in and only usable under ``lab_unrestricted`` with the
``cairn_cli_drivers_enabled`` flag; their upstream ``--dangerously-*`` flags are
removed on port.
"""
