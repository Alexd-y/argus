"""Unit tests for :mod:`src.payloads.context` (Backlog T3/T4).

Covers the two behaviours the payload-context value object is responsible for:

* :func:`select_encoding_pipeline` — sink-type routing that only ever returns a
  pipeline name the family actually declares (or ``None`` to keep the default),
  so it can never synthesise an "unknown encoding pipeline" error.
* :meth:`PayloadContext.to_parameters` — projection into the template
  placeholder map, including the IDOR neighbour derivation and the strict
  exclusion of ``auth_context`` secrets.
"""

from __future__ import annotations

from src.payloads.context import (
    DEFAULT_OAST_PLACEHOLDER,
    PayloadContext,
    SinkType,
    select_encoding_pipeline,
)

# ---------------------------------------------------------------------------
# select_encoding_pipeline
# ---------------------------------------------------------------------------


class TestSelectEncodingPipeline:
    def test_query_prefers_url_only_when_declared(self) -> None:
        assert select_encoding_pipeline({"identity", "url_only"}, SinkType.QUERY) == "url_only"

    def test_query_falls_back_to_identity_when_url_only_absent(self) -> None:
        # This is exactly the case the old hardcoded ``url_only`` broke: safe
        # families declare only ``identity``.
        assert select_encoding_pipeline({"identity"}, SinkType.QUERY) == "identity"

    def test_json_sink_stays_identity_even_if_url_only_available(self) -> None:
        # Percent-encoding a JSON body would corrupt the grammar, so JSON sinks
        # must never route to url_only.
        assert (
            select_encoding_pipeline({"identity", "url_only", "html_entity"}, SinkType.JSON)
            == "identity"
        )

    def test_html_sink_prefers_html_entity(self) -> None:
        assert (
            select_encoding_pipeline({"identity", "url_only", "html_entity"}, SinkType.HTML)
            == "html_entity"
        )

    def test_html_sink_falls_back_when_html_entity_absent(self) -> None:
        assert select_encoding_pipeline({"identity", "url_only"}, SinkType.HTML) == "identity"

    def test_returns_none_when_no_priority_matches(self) -> None:
        # A family declaring only url_only cannot satisfy a GENERIC (identity)
        # preference; None tells the builder to keep the family default.
        assert select_encoding_pipeline({"url_only"}, SinkType.GENERIC) is None

    def test_accepts_any_iterable_not_just_set(self) -> None:
        assert select_encoding_pipeline(["identity", "url_only"], SinkType.URL) == "url_only"


# ---------------------------------------------------------------------------
# PayloadContext.to_parameters
# ---------------------------------------------------------------------------


class TestToParameters:
    def test_projects_all_populated_fields(self) -> None:
        ctx = PayloadContext(
            sink_type=SinkType.QUERY,
            target_url="http://t/a?q=1",
            parameter_name="q",
            parameter_value="payload",
            canary="argusdead",
            oast_host="oob.example",
            baseline_id="42",
            target_domain="t",
        )
        params = ctx.to_parameters()
        assert params["url"] == "http://t/a?q=1"
        assert params["param"] == "q"
        assert params["user_input"] == "payload"
        assert params["canary"] == "argusdead"
        assert params["oast_host"] == "oob.example"
        assert params["baseline_id"] == "42"
        assert params["target_domain"] == "t"

    def test_omits_none_fields(self) -> None:
        params = PayloadContext(canary="c").to_parameters()
        assert "url" not in params
        assert "param" not in params
        assert "oast_host" not in params
        # Neighbour probes are always emitted so IDOR templates still build.
        assert "baseline_id_minus_one" in params
        assert "baseline_id_plus_one" in params

    def test_auth_context_never_leaks_into_parameters(self) -> None:
        ctx = PayloadContext(
            canary="c",
            auth_context={"cookie": "s3cr3t-session", "authorization": "Bearer t0k"},
        )
        params = ctx.to_parameters()
        assert "cookie" not in params
        assert "authorization" not in params
        assert "s3cr3t-session" not in params.values()
        assert "Bearer t0k" not in params.values()

    def test_numeric_neighbours_from_parameter_value(self) -> None:
        params = PayloadContext(parameter_value="42").to_parameters()
        assert params["baseline_id_minus_one"] == "41"
        assert params["baseline_id_plus_one"] == "43"

    def test_numeric_neighbours_fall_back_to_baseline_id(self) -> None:
        params = PayloadContext(parameter_value="not-a-number", baseline_id="7").to_parameters()
        assert params["baseline_id_minus_one"] == "6"
        assert params["baseline_id_plus_one"] == "8"

    def test_negative_numeric_neighbours(self) -> None:
        params = PayloadContext(parameter_value="-5").to_parameters()
        assert params["baseline_id_minus_one"] == "-6"
        assert params["baseline_id_plus_one"] == "-4"

    def test_non_numeric_context_uses_default_base(self) -> None:
        params = PayloadContext(parameter_value="abc").to_parameters()
        assert params["baseline_id_minus_one"] == "99999"
        assert params["baseline_id_plus_one"] == "100001"

    def test_empty_context_still_emits_neighbour_probes_only(self) -> None:
        params = PayloadContext().to_parameters()
        assert set(params) == {"baseline_id_minus_one", "baseline_id_plus_one"}


def test_default_oast_placeholder_is_non_resolving() -> None:
    # RFC 6761 reserves .invalid; it must never resolve so payloads stay inert.
    assert DEFAULT_OAST_PLACEHOLDER.endswith(".invalid")
