"""ChromiumBackend hardening — SSRF/exfil defence + self-contained styling.

The Chromium PDF backend renders report HTML that can embed data derived from
untrusted scan targets. These tests cover the pure hardening helpers (no browser
needed): local-stylesheet inlining (so the branded template renders styled with
the network blocked) and the request router that blocks every non-inline scheme
(so a malicious finding field can never drive the browser to SSRF internal
services / cloud IMDS or exfiltrate data).

Pure/offline — lives under ``tests/reports/`` (an offline path prefix).
"""

from __future__ import annotations

from pathlib import Path

import pytest
from src.reports.pdf_backend import _abort_remote_request, _inline_local_stylesheets


class _FakeRequest:
    def __init__(self, url: str) -> None:
        self.url = url


class _FakeRoute:
    def __init__(self, url: str) -> None:
        self.request = _FakeRequest(url)
        self.action: str | None = None

    def continue_(self) -> None:
        self.action = "continue"

    def abort(self) -> None:
        self.action = "abort"


# ---------------------------------------------------------------------------
# Request router — the core SSRF/exfil block
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "http://169.254.169.254/latest/meta-data/",  # cloud IMDS
        "https://internal-service.local/",
        "http://localhost:8000/api/v1/reports",
        "file:///etc/passwd",
        "ftp://example.com/x",
        "ws://evil/collect",
    ],
)
def test_router_aborts_remote_and_dangerous_schemes(url):
    route = _FakeRoute(url)
    _abort_remote_request(route)
    assert route.action == "abort", f"{url} should have been aborted"


@pytest.mark.parametrize(
    "url",
    [
        "data:image/png;base64,iVBORw0KGgo=",
        "about:blank",
        "blob:abc-123",
    ],
)
def test_router_allows_inline_schemes(url):
    route = _FakeRoute(url)
    _abort_remote_request(route)
    assert route.action == "continue", f"{url} should be allowed (inline)"


def test_router_fails_closed_on_error():
    class _Boom:
        @property
        def request(self):
            raise RuntimeError("boom")

        def __init__(self):
            self.aborted = False

        def abort(self):
            self.aborted = True

    boom = _Boom()
    _abort_remote_request(boom)  # must not raise
    assert boom.aborted is True


# ---------------------------------------------------------------------------
# Local-stylesheet inlining — styling without network, no file-read primitive
# ---------------------------------------------------------------------------


def _branded_midgard_dir() -> str:
    # backend/templates/reports/midgard holds pdf_layout.html + pdf_styles.css
    return str(
        (Path(__file__).resolve().parents[2] / "templates" / "reports" / "midgard").resolve()
    )


def test_inlines_same_dir_stylesheet():
    base = _branded_midgard_dir()
    html = '<head><link rel="stylesheet" href="pdf_styles.css" /></head>'
    out = _inline_local_stylesheets(html, base)
    assert "<link" not in out
    assert "<style>" in out
    assert "#00ff9d" in out  # a token from the real pdf_styles.css


@pytest.mark.parametrize(
    "href",
    [
        "../../../etc/passwd",  # traversal
        "/etc/passwd",  # absolute
        "http://169.254.169.254/x",  # remote / IMDS
        "https://evil/x.css",  # remote
        "data:text/css,body{}",  # already inline scheme
    ],
)
def test_dangerous_hrefs_dropped_not_fetched(href):
    base = _branded_midgard_dir()
    html = f'<link rel="stylesheet" href="{href}">'
    out = _inline_local_stylesheets(html, base)
    assert out == ""  # link dropped, nothing read


def test_no_base_url_is_noop():
    html = '<link rel="stylesheet" href="pdf_styles.css">'
    assert _inline_local_stylesheets(html, None) == html


def test_missing_file_dropped():
    base = _branded_midgard_dir()
    html = '<link rel="stylesheet" href="does_not_exist.css">'
    assert _inline_local_stylesheets(html, base) == ""
