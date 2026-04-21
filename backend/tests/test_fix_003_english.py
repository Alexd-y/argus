"""FIX-003: All templates English-only, no Cyrillic in general partials, i18n removed."""

from __future__ import annotations

import re
from pathlib import Path

import pytest


ARGUS_ROOT = Path(__file__).resolve().parent.parent.parent
GENERAL_PARTIALS_DIR = (
    ARGUS_ROOT / "backend" / "src" / "reports" / "templates" / "reports" / "partials"
)

CYRILLIC_RE = re.compile(r"[\u0400-\u04FF]")

GENERAL_PARTIAL_FILES = [
    "findings_table.html.j2",
    "owasp_compliance_table.html.j2",
    "active_web_scan.html.j2",
    "artifacts.html.j2",
    "scan_artifacts_inner.html.j2",
]


class TestGeneralPartialsNoCyrillic:
    """FIX-003: The 5 general partials must have no Cyrillic text."""

    @pytest.fixture(scope="class")
    def partials_content(self) -> dict[str, str]:
        assert GENERAL_PARTIALS_DIR.exists(), (
            f"General partials dir not found: {GENERAL_PARTIALS_DIR}"
        )
        loaded: dict[str, str] = {}
        for name in GENERAL_PARTIAL_FILES:
            path = GENERAL_PARTIALS_DIR / name
            if path.exists():
                loaded[name] = path.read_text(encoding="utf-8")
        return loaded

    @pytest.mark.parametrize("template_name", GENERAL_PARTIAL_FILES)
    def test_no_cyrillic_in_template(
        self, partials_content: dict[str, str], template_name: str,
    ) -> None:
        if template_name not in partials_content:
            pytest.skip(f"Template {template_name} not found")
        content = partials_content[template_name]
        matches = CYRILLIC_RE.findall(content)
        assert not matches, (
            f"{template_name} contains Cyrillic: {''.join(matches[:20])!r}"
        )


class TestScanArtifactPhaseLabelsEnglish:
    """_SCAN_ARTIFACT_PHASE_LABELS values must be English."""

    def test_values_are_english(self) -> None:
        from src.services.reporting import _SCAN_ARTIFACT_PHASE_LABELS

        for key, label in _SCAN_ARTIFACT_PHASE_LABELS.items():
            matches = CYRILLIC_RE.findall(label)
            assert not matches, (
                f"_SCAN_ARTIFACT_PHASE_LABELS[{key!r}] has Cyrillic: {label!r}"
            )

    def test_values_are_strings(self) -> None:
        from src.services.reporting import _SCAN_ARTIFACT_PHASE_LABELS

        for key, label in _SCAN_ARTIFACT_PHASE_LABELS.items():
            assert isinstance(label, str), f"Label for {key} must be str"
            assert label.strip(), f"Label for {key} must not be empty"


class TestActiveWebScanAILabelsExist:
    """_ACTIVE_WEB_SCAN_AI_LABELS (not _RU) must exist and be English."""

    def test_labels_dict_exists(self) -> None:
        from src.services.reporting import _ACTIVE_WEB_SCAN_AI_LABELS

        assert isinstance(_ACTIVE_WEB_SCAN_AI_LABELS, dict)
        assert len(_ACTIVE_WEB_SCAN_AI_LABELS) > 0

    def test_labels_are_english(self) -> None:
        from src.services.reporting import _ACTIVE_WEB_SCAN_AI_LABELS

        for key, label in _ACTIVE_WEB_SCAN_AI_LABELS.items():
            matches = CYRILLIC_RE.findall(label)
            assert not matches, (
                f"_ACTIVE_WEB_SCAN_AI_LABELS[{key!r}] has Cyrillic: {label!r}"
            )

    def test_no_ru_variant(self) -> None:
        """There should be no _ACTIVE_WEB_SCAN_AI_LABELS_RU attribute."""
        import src.services.reporting as mod

        assert not hasattr(mod, "_ACTIVE_WEB_SCAN_AI_LABELS_RU"), (
            "Deprecated _ACTIVE_WEB_SCAN_AI_LABELS_RU should not exist"
        )
