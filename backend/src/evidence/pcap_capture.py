"""Scoped network-traffic capture (PCAP) producer (wave 2a, etap 6).

Produces the ``PCAP`` evidence kind where the proof is at the network level and
invisible in the application exchange. Runs ``tcpdump`` in the sandbox
(``CAP_NET_RAW`` is already granted; no new privilege). Three non-negotiable
guards, all built from the job (never hand-set):

* **Scope** — a BPF filter pinned to the target host + the ports under test, so
  neighbouring containers' and service traffic are never captured (that would
  be both a leak and an out-of-scope breach).
* **Limits** — a wall-clock and a file-size cap, with forced termination.
* **Redaction** — the default snaplen is headers-only (96 bytes), so packet
  payloads (where app-protocol credentials live) are never written. Full-payload
  capture with per-protocol redaction is deliberately out of scope: an honest
  truncated artifact beats a complete one that leaks the client's credentials.

Capture is tenant-policy-gated and OFF by default (volume).
"""

from __future__ import annotations

import contextlib
import ipaddress
import logging
import re
import shutil
import subprocess
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from time import perf_counter

_logger = logging.getLogger(__name__)

#: Headers-only snaplen (ethernet+IP+TCP/UDP headers fit well under this). A
#: payload-free capture cannot leak app-layer credentials.
_HEADERS_ONLY_SNAPLEN = 96

_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,253}$")


class CaptureUnavailable(RuntimeError):
    """Raised when no packet-capture tool (tcpdump) is available."""


class CaptureScopeError(ValueError):
    """Raised when the capture target/ports fail validation (fail-closed)."""


@dataclass(frozen=True)
class CaptureSpec:
    """Bounded, scoped capture parameters derived from the scan job."""

    target_host: str
    ports: tuple[int, ...] = ()
    max_seconds: int = 60
    max_bytes: int = 50 * 1024 * 1024
    interface: str = "any"
    #: Headers-only by default (no payload → no credential leak).
    snaplen: int = _HEADERS_ONLY_SNAPLEN
    payload_excluded: bool = field(default=True)


def tcpdump_available() -> bool:
    return shutil.which("tcpdump") is not None


def _validate_host(host: str) -> str:
    host = (host or "").strip()
    if not host:
        raise CaptureScopeError("capture requires a target host")
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    if not _HOSTNAME_RE.fullmatch(host):
        raise CaptureScopeError(f"invalid capture host: {host!r}")
    return host


def _validate_ports(ports: tuple[int, ...]) -> tuple[int, ...]:
    out: list[int] = []
    for p in ports:
        if not isinstance(p, int) or not (1 <= p <= 65535):
            raise CaptureScopeError(f"invalid capture port: {p!r}")
        out.append(p)
    return tuple(dict.fromkeys(out))  # dedupe, keep order


def build_bpf_filter(spec: CaptureSpec) -> str:
    """BPF filter pinned to the target host (+ ports) — nothing else is captured."""
    host = _validate_host(spec.target_host)
    ports = _validate_ports(spec.ports)
    if ports:
        port_expr = " or ".join(f"port {p}" for p in ports)
        return f"host {host} and ({port_expr})"
    return f"host {host}"


def build_tcpdump_argv(spec: CaptureSpec, *, output_path: Path) -> list[str]:
    """Build the tcpdump argv with scope + size cap + headers-only snaplen.

    The wall-clock limit is enforced by the caller running this under a
    subprocess timeout; the file-size cap is ``-C`` (MiB) with a single file.
    """
    size_mb = max(1, spec.max_bytes // (1024 * 1024))
    return [
        "tcpdump",
        "-i",
        spec.interface,
        "-w",
        str(output_path),
        "-s",
        str(spec.snaplen),  # headers-only → payload excluded
        "-C",
        str(size_mb),  # rotate/cap at size_mb MiB
        "-W",
        "1",  # keep a single capture file (bounded)
        "-n",  # no name resolution (no extra lookups)
        build_bpf_filter(spec),
    ]


def capture_description(spec: CaptureSpec) -> str:
    """Human description recording the honest truncation (payload exclusion)."""
    scope = f"host {spec.target_host}"
    if spec.ports:
        scope += " ports " + ",".join(str(p) for p in spec.ports)
    note = "headers-only (payload excluded)" if spec.payload_excluded else "full payload"
    return f"pcap capture: {scope}; snaplen={spec.snaplen} {note}; <= {spec.max_seconds}s"


@dataclass(frozen=True)
class CaptureResult:
    """Outcome of a bounded capture."""

    output_path: Path
    size_bytes: int
    duration_seconds: float
    #: "completed" | "wall_clock" | "size_cap" — why the capture stopped.
    stopped_reason: str


def _terminate(proc: object) -> None:
    """Idempotent best-effort stop: graceful terminate (so tcpdump flushes a valid
    pcap), then hard kill — ALWAYS reaping with a final wait() so no zombie is
    left behind. Safe to call more than once (the watchdog and the finally block
    both call it): an already-exited process is a no-op."""
    with contextlib.suppress(Exception):
        if proc.poll() is not None:  # type: ignore[attr-defined]  # already exited
            return
    with contextlib.suppress(Exception):
        proc.terminate()  # type: ignore[attr-defined]
    try:
        proc.wait(timeout=5)  # type: ignore[attr-defined]
        return
    except Exception:
        pass
    with contextlib.suppress(Exception):
        proc.kill()  # type: ignore[attr-defined]
    with contextlib.suppress(Exception):
        proc.wait(timeout=5)  # type: ignore[attr-defined]  # reap the SIGKILL'd child


def run_tcpdump_capture(
    spec: CaptureSpec,
    *,
    output_path: Path,
    runner: Callable[..., object] = subprocess.Popen,
) -> CaptureResult:
    """Run tcpdump bounded by BOTH the wall-clock (``spec.max_seconds``, HARD —
    enforced here, not delegated to a hypothetical caller) and the file size
    (``spec.max_bytes`` via ``-C``). Blocks for up to ``max_seconds``, then stops
    tcpdump gracefully so the pcap is flushed and valid. ``runner`` is injectable
    so the control flow is unit-testable without a live tcpdump.

    Raises :class:`CaptureUnavailable` when tcpdump is not installed.
    """
    if not tcpdump_available():
        raise CaptureUnavailable("tcpdump is not available in this runtime")
    # Validate scope fail-closed before spawning anything.
    build_bpf_filter(spec)
    argv = build_tcpdump_argv(spec, output_path=output_path)
    proc = runner(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    reason = "completed"
    start = perf_counter()
    try:
        proc.wait(timeout=spec.max_seconds)  # type: ignore[attr-defined]
    except subprocess.TimeoutExpired:
        reason = "wall_clock"
        _terminate(proc)
    else:
        # tcpdump exited on its own BEFORE the wall-clock. With ``-W 1 -C`` that
        # normally means the size cap tripped (exit 0); a NON-zero exit means it
        # failed to start (bad interface, missing CAP_NET_RAW, rejected BPF,
        # unwritable path) — surface that as "error" rather than a clean capture.
        rc = getattr(proc, "returncode", None)
        if rc is not None and rc != 0:
            reason = "error"
    duration = perf_counter() - start

    size = output_path.stat().st_size if output_path.exists() else 0
    if reason not in ("error", "wall_clock") and spec.max_bytes and size >= spec.max_bytes:
        reason = "size_cap"
    return CaptureResult(
        output_path=output_path,
        size_bytes=size,
        duration_seconds=duration,
        stopped_reason=reason,
    )


@contextmanager
def pcap_session(
    spec: CaptureSpec,
    *,
    output_path: Path,
    runner: Callable[..., object] = subprocess.Popen,
) -> Iterator[object]:
    """Capture while the ``with`` body runs (e.g. a tool executes against the
    target). tcpdump is always stopped on exit, and a watchdog enforces the
    wall-clock cap even if the body overruns — so a hung tool cannot leave an
    unbounded capture running. Yields the tcpdump process handle.
    """
    if not tcpdump_available():
        raise CaptureUnavailable("tcpdump is not available in this runtime")
    build_bpf_filter(spec)
    argv = build_tcpdump_argv(spec, output_path=output_path)
    proc = runner(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    watchdog = threading.Timer(float(spec.max_seconds), _terminate, args=(proc,))
    watchdog.daemon = True
    watchdog.start()
    try:
        yield proc
    finally:
        watchdog.cancel()
        _terminate(proc)


__all__ = [
    "CaptureResult",
    "CaptureScopeError",
    "CaptureSpec",
    "CaptureUnavailable",
    "build_bpf_filter",
    "build_tcpdump_argv",
    "capture_description",
    "pcap_session",
    "run_tcpdump_capture",
    "tcpdump_available",
]
