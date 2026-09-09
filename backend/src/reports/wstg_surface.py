"""Surface observations for WSTG applicability (ARGUS-WSTG-COV-1 §Surface).

Replaces the three-bool ``(authenticated, has_input_surface, has_cookies)``
heuristic with structured, evidence-backed observations. The core rule is that
**running a tool never proves a feature is present or absent**:

* ``present``  — the feature was positively observed, backed by evidence;
* ``absent``   — the feature is confirmed absent *within the stated scope*,
  backed by evidence (a completed discovery that found none);
* ``unknown``  — no conclusive observation (no data, incomplete discovery,
  timeout, or error). ``unknown`` is the safe default and keeps dependent tests
  in the denominator.

Producers should emit ``unknown`` whenever the underlying data source is not yet
implemented, rather than guessing.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class SurfaceFeature(StrEnum):
    """Target features that gate WSTG test applicability."""

    FORMS = "forms"
    QUERY_PARAMS = "query_params"
    PATH_PARAMS = "path_params"
    BODY_INPUTS = "body_inputs"
    COOKIES = "cookies"
    AUTH_MECHANISM = "auth_mechanism"
    CONFIRMED_SESSION = "confirmed_session"
    CONFIRMED_ROLES = "confirmed_roles"
    FILE_UPLOAD = "file_upload"
    API = "api"
    WEBSOCKETS = "websockets"
    CLIENT_INPUT = "client_input"


class SurfaceState(StrEnum):
    PRESENT = "present"
    ABSENT = "absent"
    UNKNOWN = "unknown"


class DiscoveryStatus(StrEnum):
    NOT_ATTEMPTED = "not_attempted"
    INCOMPLETE = "incomplete"
    COMPLETE = "complete"
    FAILED = "failed"


@dataclass(frozen=True)
class SurfaceObservation:
    """A structured observation about one target feature."""

    feature: SurfaceFeature
    state: SurfaceState
    scan_id: str | None = None
    scope_ref: str | None = None
    target_ref: str | None = None
    evidence_refs: tuple[str, ...] = ()
    observed_at: str | None = None
    discovery_status: DiscoveryStatus = DiscoveryStatus.NOT_ATTEMPTED
    limitations: tuple[str, ...] = ()
    observation_id: str | None = None

    def confirms_absent(self) -> bool:
        """``absent`` is only trustworthy from a completed discovery with evidence."""
        return (
            self.state == SurfaceState.ABSENT
            and self.discovery_status == DiscoveryStatus.COMPLETE
            and bool(self.evidence_refs)
        )

    def confirms_present(self) -> bool:
        return self.state == SurfaceState.PRESENT and bool(self.evidence_refs)


def build_surface_index(
    observations: list[SurfaceObservation],
) -> dict[SurfaceFeature, SurfaceObservation]:
    """Reduce observations to one authoritative record per feature.

    ``present`` (with evidence) wins over ``absent``; ``absent`` (confirmed) wins
    over ``unknown``. This means a positive sighting is never overwritten by a
    later empty scan.
    """

    def rank(o: SurfaceObservation) -> int:
        if o.confirms_present():
            return 3
        if o.state == SurfaceState.PRESENT:
            return 2
        if o.confirms_absent():
            return 1
        return 0  # unknown / unconfirmed absent

    index: dict[SurfaceFeature, SurfaceObservation] = {}
    for obs in observations:
        current = index.get(obs.feature)
        if current is None or rank(obs) > rank(current):
            index[obs.feature] = obs
    return index


def unknown_observation(feature: SurfaceFeature, **kw) -> SurfaceObservation:
    """Convenience constructor for the safe default."""
    return SurfaceObservation(feature=feature, state=SurfaceState.UNKNOWN, **kw)


__all__ = [
    "DiscoveryStatus",
    "SurfaceFeature",
    "SurfaceObservation",
    "SurfaceState",
    "build_surface_index",
    "unknown_observation",
]
