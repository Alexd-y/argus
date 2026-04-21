"""M-5, M-10: Phase labels are English."""

from __future__ import annotations


class TestPhaseLabelsEnglish:
    """Phase labels must not contain Cyrillic characters."""

    def test_phase_labels_are_english(self) -> None:
        from src.reports.jinja_minimal_context import _PHASE_LABELS

        for key, label in _PHASE_LABELS.items():
            assert not any(
                "\u0400" <= c <= "\u04ff" for c in label
            ), f"Phase label {key!r} contains Cyrillic: {label}"
            assert label.strip(), f"Phase label {key!r} is empty"

    def test_phase_labels_cover_all_phases(self) -> None:
        from src.reports.jinja_minimal_context import _PHASE_LABELS

        required = {"recon", "threat_modeling", "vulnerability_analysis", "exploitation", "reporting"}
        missing = required - set(_PHASE_LABELS.keys())
        assert not missing, f"Missing phase labels: {missing}"

    def test_phase_labels_are_non_empty_strings(self) -> None:
        from src.reports.jinja_minimal_context import _PHASE_LABELS

        for key, label in _PHASE_LABELS.items():
            assert isinstance(label, str), f"Phase label {key!r} is not a string"
            assert len(label) >= 3, f"Phase label {key!r} too short: {label!r}"
