"""Customer-facing transactional notifications (Block 4.7).

Distinct from the ops-alerting channels in ``src.mcp.services.notifications``
(Slack/Jira/etc.): this package sends report-ready / quota / purchase emails to
the scan requester via Resend.
"""
