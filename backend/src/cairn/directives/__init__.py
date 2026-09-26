"""Pentest directive generator (Phase 14).

Local LLMs formulate the next pentest step ("directive") from what has been found.
A directive is a specialised Cairn intent: typed, focused on a concrete
service/port/CVE, with a success criterion and a mandatory proof requirement.

Safety is enforced deterministically by the application, not the model:
intrusiveness is clamped to what the execution mode + lease allow, and target
addresses in the rendered text come from verified scope — never from model output.
"""
