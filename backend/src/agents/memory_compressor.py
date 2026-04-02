"""
Memory compression for long-running scans (Strix pattern).

When scan history exceeds a token threshold, compress it into a structured
summary that preserves all critical context while discarding verbose noise.
"""

from __future__ import annotations

import logging
import os

from src.llm.task_router import LLMTask, call_llm_for_task

logger = logging.getLogger(__name__)

COMPRESSION_SYSTEM_PROMPT = """\
You are summarizing a security scan's progress for context compression.
The scan is ongoing — the summary will replace verbose history.

PRESERVE (critical, never lose):
1. All discovered vulnerabilities: name, URL, severity, evidence snippet
2. All tested endpoints and their HTTP status codes
3. Current hypotheses about unexplored attack vectors
4. Authentication tokens, session values, credentials found
5. Technologies detected: frameworks, versions, libraries
6. Next planned actions

DISCARD (safe to lose):
- Verbose tool output with no findings
- Repeated failed payloads (keep only summary: "tried 200 XSS payloads, none fired")
- Status messages and acknowledgments
- Duplicate information already captured

OUTPUT: Structured markdown summary preserving all critical context.
Max length: 2000 tokens.
"""

_CHARS_PER_TOKEN_ESTIMATE = 4
_DEFAULT_COMPRESSION_THRESHOLD_CHARS = 20_000
_MAX_HISTORY_MESSAGES_TO_COMPRESS = 30


class ScanMemoryCompressor:
    """
    Compress scan history when it grows too large.

    Tracks LLM call count per scan session. When history size exceeds
    ``compression_threshold_chars`` (~5k tokens), triggers compression
    via a cheap LLM call that produces a structured summary.
    """

    def __init__(
        self,
        scan_id: str,
        compression_threshold_chars: int = _DEFAULT_COMPRESSION_THRESHOLD_CHARS,
    ):
        self.scan_id = scan_id
        self.compression_threshold_chars = compression_threshold_chars
        self.call_count = 0
        self.compressed_summary: str | None = None
        self._compression_count = 0

    @property
    def is_enabled(self) -> bool:
        return os.environ.get("MEMORY_COMPRESSION_ENABLED", "true").lower() == "true"

    def should_compress(self, history: list[dict]) -> bool:
        """Check if history needs compression based on estimated token count."""
        if not self.is_enabled:
            return False
        total_chars = sum(len(str(msg.get("content", ""))) for msg in history)
        return total_chars > self.compression_threshold_chars

    async def maybe_compress(self, history: list[dict]) -> str | None:
        """
        Compress history if it exceeds the threshold.

        Returns the compressed summary, or ``None`` if compression was not needed.
        The compressed summary replaces the verbose history — caller should
        substitute the full history with a single message containing this summary.
        """
        self.call_count += 1

        if not self.should_compress(history):
            return None

        recent = history[-_MAX_HISTORY_MESSAGES_TO_COMPRESS:]
        history_text = "\n\n".join(
            f"[{msg.get('role', 'unknown')}]: {str(msg.get('content', ''))[:500]}"
            for msg in recent
        )

        try:
            response = await call_llm_for_task(
                task=LLMTask.DEDUP_ANALYSIS,
                prompt=f"Compress this scan history:\n\n{history_text}",
                system_prompt=COMPRESSION_SYSTEM_PROMPT,
            )
            self.compressed_summary = response.text
            self._compression_count += 1
            logger.info(
                "Scan %s: memory compressed (compression #%d, %d messages -> summary)",
                self.scan_id,
                self._compression_count,
                len(recent),
            )
            return self.compressed_summary
        except Exception as exc:
            logger.warning("Memory compression failed for scan %s: %s", self.scan_id, exc)
            return None

    def build_compressed_history(self, original_history: list[dict]) -> list[dict]:
        """
        Build a new history list with compression applied.

        If a compressed summary exists, returns a short history:
        [system context with summary] + [last few messages].
        Otherwise returns the original history unchanged.
        """
        if not self.compressed_summary:
            return original_history

        summary_message = {
            "role": "system",
            "content": (
                f"[COMPRESSED CONTEXT — compression #{self._compression_count}]\n\n"
                f"{self.compressed_summary}"
            ),
        }
        tail = original_history[-5:] if len(original_history) > 5 else original_history
        return [summary_message] + tail

    def get_stats(self) -> dict:
        return {
            "scan_id": self.scan_id,
            "call_count": self.call_count,
            "compression_count": self._compression_count,
            "has_compressed_summary": self.compressed_summary is not None,
        }
