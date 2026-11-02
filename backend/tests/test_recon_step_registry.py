"""RECON-001 — step plan from mode and scan options (no tool I/O)."""

from src.core.config import Settings
from src.recon.recon_runtime import ReconRuntimeConfig, build_recon_runtime_config
from src.recon.step_registry import ReconStepId, plan_recon_steps


def test_full_mode_includes_nmap_and_http_surface() -> None:
    cfg = ReconRuntimeConfig(
        mode="full",
        active_depth=1,
        enable_content_discovery=False,
        deep_port_scan=False,
        js_analysis=False,
        screenshots=False,
        tool_selection=None,
        wordlist_path="",
        rate_limit_rps=10,
    )
    steps = plan_recon_steps(cfg)
    assert ReconStepId.NMAP_PORT_SCAN in steps
    assert ReconStepId.HTTP_SURFACE in steps
    assert ReconStepId.DIG in steps
    assert ReconStepId.DNS_DEPTH in steps
    assert ReconStepId.SUBDOMAIN_PASSIVE in steps


def test_mode_never_reduces_the_plan() -> None:
    # Policy: the plan is the full recon surface regardless of mode — mode (and
    # passive_only) never REMOVE a step. Even in "passive" the full surface runs.
    cfg = ReconRuntimeConfig(
        mode="passive",
        active_depth=1,
        enable_content_discovery=False,
        deep_port_scan=False,
        js_analysis=False,
        screenshots=False,
        tool_selection=None,
        wordlist_path="",
        rate_limit_rps=10,
    )
    steps = plan_recon_steps(cfg)
    for essential in (
        ReconStepId.NMAP_PORT_SCAN,
        ReconStepId.HTTP_SURFACE,
        ReconStepId.DIG,
        ReconStepId.DNS_DEPTH,
        ReconStepId.WHOIS,
        ReconStepId.SUBDOMAIN_PASSIVE,
        ReconStepId.KAL_DNS_BUNDLE,
        ReconStepId.SECURITY_HEADERS,
    ):
        assert essential in steps


def test_tool_selection_does_not_drop_base_ti_steps() -> None:
    # tool_selection is a picker for optional extras, NOT a global allow-list:
    # naming a subset of tools must never remove the base Target-Intelligence
    # steps. (Regression: an env tool_selection meant to enable extras was
    # silently dropping WHOIS/DIG/DNS/HTTP so every report's TI panel was blank.)
    cfg = ReconRuntimeConfig(
        mode="active",
        active_depth=1,
        enable_content_discovery=False,
        deep_port_scan=False,
        js_analysis=False,
        screenshots=False,
        tool_selection=frozenset({"nmap_port_scan", "dig"}),
        wordlist_path="",
        rate_limit_rps=10,
    )
    steps = plan_recon_steps(cfg)
    for essential in (
        ReconStepId.DIG,
        ReconStepId.WHOIS,
        ReconStepId.DNS_DEPTH,
        ReconStepId.CRTSH,
        ReconStepId.SUBDOMAIN_PASSIVE,
        ReconStepId.NMAP_PORT_SCAN,
        ReconStepId.HTTP_SURFACE,
    ):
        assert essential in steps


def test_optional_extras_only_tool_selection_keeps_full_ti_base() -> None:
    # Reproduces the live misconfiguration: RECON_TOOL_SELECTION listing ONLY the
    # heavy optional tools must still run the whole base TI foundation in full mode.
    cfg = ReconRuntimeConfig(
        mode="full",
        active_depth=1,
        enable_content_discovery=True,
        deep_port_scan=True,
        js_analysis=True,
        screenshots=True,
        tool_selection=frozenset(
            {"url_history", "content_discovery", "js_analysis", "asnmap", "screenshots", "deep_port_scan"}
        ),
        wordlist_path="",
        rate_limit_rps=10,
    )
    steps = plan_recon_steps(cfg)
    for essential in (
        ReconStepId.WHOIS,
        ReconStepId.DIG,
        ReconStepId.DNS_DEPTH,
        ReconStepId.HTTP_SURFACE,
        ReconStepId.CRTSH,
    ):
        assert essential in steps
    # and the selected optional extras are present too
    for extra in (
        ReconStepId.CONTENT_DISCOVERY,
        ReconStepId.JS_ANALYSIS,
        ReconStepId.ASN_MAP,
        ReconStepId.SCREENSHOTS,
        ReconStepId.DEEP_PORT_SCAN,
    ):
        assert extra in steps


def test_nested_recon_options_override_mode() -> None:
    cfg = build_recon_runtime_config(
        {"ports": "443", "recon": {"mode": "passive"}},
        app_settings=Settings(recon_mode="full", recon_passive_only=False),
    )
    # mode still resolves from options (config concern)...
    assert cfg.mode == "passive"
    # ...but the plan is never reduced by it: the full surface runs regardless.
    assert ReconStepId.NMAP_PORT_SCAN in plan_recon_steps(cfg)


def test_passive_only_override_in_options() -> None:
    cfg = build_recon_runtime_config(
        {"recon": {"passive_only": True, "mode": "active"}},
        app_settings=Settings(recon_mode="full"),
    )
    assert cfg.mode == "passive"


def test_full_with_flags_adds_optional_steps() -> None:
    cfg = ReconRuntimeConfig(
        mode="full",
        active_depth=1,
        enable_content_discovery=True,
        deep_port_scan=True,
        js_analysis=True,
        screenshots=True,
        tool_selection=None,
        wordlist_path="",
        rate_limit_rps=10,
    )
    steps = plan_recon_steps(cfg)
    assert ReconStepId.CONTENT_DISCOVERY in steps
    assert ReconStepId.JS_ANALYSIS in steps
    assert ReconStepId.ASN_MAP in steps
    assert ReconStepId.SCREENSHOTS in steps
    assert ReconStepId.DEEP_PORT_SCAN in steps


def test_active_mode_includes_nmap_http_and_dependency_manifests() -> None:
    cfg = ReconRuntimeConfig(
        mode="active",
        active_depth=1,
        enable_content_discovery=False,
        deep_port_scan=False,
        js_analysis=False,
        screenshots=False,
        tool_selection=None,
        wordlist_path="",
        rate_limit_rps=10,
    )
    steps = plan_recon_steps(cfg)
    assert ReconStepId.NMAP_PORT_SCAN in steps
    assert ReconStepId.HTTP_SURFACE in steps
    assert ReconStepId.DEPENDENCY_MANIFESTS in steps
    assert ReconStepId.DNS_DEPTH in steps
    assert ReconStepId.SUBDOMAIN_PASSIVE in steps
    assert ReconStepId.KAL_DNS_BUNDLE in steps


def test_nested_recon_overrides_top_level_recon_mode() -> None:
    cfg = build_recon_runtime_config(
        {
            "recon_mode": "passive",
            "recon": {"mode": "active"},
        },
        app_settings=Settings(recon_mode="full", recon_passive_only=False),
    )
    assert cfg.mode == "active"


def test_top_level_scan_options_override_settings_when_nested_missing() -> None:
    cfg = build_recon_runtime_config(
        {
            "recon_mode": "active",
            "recon_wordlist_path": "/from_scan_top",
            "recon_rate_limit": 25,
            "recon": {"active_depth": 3},
        },
        app_settings=Settings(
            recon_mode="passive",
            recon_wordlist_path="/from_env",
            recon_rate_limit=None,
            recon_rate_limit_per_second=5,
            recon_active_depth=0,
        ),
    )
    assert cfg.mode == "active"
    assert cfg.wordlist_path == "/from_scan_top"
    assert cfg.rate_limit_rps == 25
    assert cfg.active_depth == 3


def test_nested_recon_overrides_top_level_for_shared_keys() -> None:
    cfg = build_recon_runtime_config(
        {
            "recon_wordlist_path": "/top",
            "recon": {"wordlist_path": "/nested", "tool_selection": "dig, whois"},
        },
        app_settings=Settings(recon_wordlist_path="/env", recon_tool_selection="nmap_port_scan"),
    )
    assert cfg.wordlist_path == "/nested"
    assert cfg.tool_selection == frozenset({"dig", "whois"})


def test_tool_selection_list_in_recon_nested_parsed() -> None:
    cfg = build_recon_runtime_config(
        {"recon": {"tool_selection": ["CRTSH", "shodan"]}},
        app_settings=Settings(),
    )
    assert cfg.tool_selection == frozenset({"crtsh", "shodan"})


def test_settings_defaults_when_scan_options_empty() -> None:
    cfg = build_recon_runtime_config(
        None,
        app_settings=Settings(
            recon_mode="passive",
            recon_active_depth=2,
            recon_enable_content_discovery=True,
            recon_tool_selection="dig",
            recon_wordlist_path="/wl.txt",
            recon_rate_limit=7,
        ),
    )
    assert cfg.mode == "passive"
    assert cfg.active_depth == 2
    assert cfg.enable_content_discovery is True
    assert cfg.tool_selection == frozenset({"dig"})
    assert cfg.wordlist_path == "/wl.txt"
    assert cfg.rate_limit_rps == 7


def test_optional_extras_are_flag_gated_in_every_mode() -> None:
    # Extras are additive by their own flags and are no longer "full-only": the
    # same flags produce the same extras in active and full (mode never gates them).
    def _plan(mode: str):
        return plan_recon_steps(
            ReconRuntimeConfig(
                mode=mode,
                active_depth=1,
                enable_content_discovery=True,
                deep_port_scan=True,
                js_analysis=True,
                screenshots=True,
                tool_selection=None,
                wordlist_path="",
                rate_limit_rps=10,
            )
        )

    active_steps = _plan("active")
    full_steps = _plan("full")
    for s in (
        ReconStepId.CONTENT_DISCOVERY,
        ReconStepId.JS_ANALYSIS,
        ReconStepId.ASN_MAP,
        ReconStepId.SCREENSHOTS,
        ReconStepId.DEEP_PORT_SCAN,
    ):
        assert s in active_steps
        assert s in full_steps


def test_tool_selection_js_analysis_alias_selects_extra() -> None:
    cfg = ReconRuntimeConfig(
        mode="full",
        active_depth=1,
        enable_content_discovery=False,
        deep_port_scan=False,
        js_analysis=True,
        screenshots=False,
        tool_selection=frozenset({"js_analysis", "dig"}),
        wordlist_path="",
        rate_limit_rps=10,
    )
    steps = plan_recon_steps(cfg)
    # base TI always runs; js_analysis extra selected; unselected extras stay out
    assert ReconStepId.JS_ANALYSIS in steps
    assert ReconStepId.WHOIS in steps and ReconStepId.DIG in steps
    assert ReconStepId.CONTENT_DISCOVERY not in steps
    assert ReconStepId.SCREENSHOTS not in steps
    assert ReconStepId.DEEP_PORT_SCAN not in steps


def test_full_asnmap_disabled_omits_asn_map_step() -> None:
    cfg = ReconRuntimeConfig(
        mode="full",
        active_depth=1,
        enable_content_discovery=False,
        deep_port_scan=False,
        js_analysis=False,
        screenshots=False,
        tool_selection=None,
        wordlist_path="",
        rate_limit_rps=10,
        asnmap_enabled=False,
    )
    steps = plan_recon_steps(cfg)
    assert ReconStepId.ASN_MAP not in steps


def test_tool_selection_asnmap_alias_selects_asn_map() -> None:
    cfg = ReconRuntimeConfig(
        mode="full",
        active_depth=1,
        enable_content_discovery=False,
        deep_port_scan=False,
        js_analysis=False,
        screenshots=False,
        tool_selection=frozenset({"asnmap", "dig"}),
        wordlist_path="",
        rate_limit_rps=10,
    )
    steps = plan_recon_steps(cfg)
    assert ReconStepId.ASN_MAP in steps
    assert ReconStepId.WHOIS in steps and ReconStepId.DIG in steps
    assert ReconStepId.JS_ANALYSIS not in steps
    assert ReconStepId.SCREENSHOTS not in steps


def test_tool_selection_is_ignored_extras_governed_by_flags() -> None:
    # tool_selection no longer filters anything: extras are governed only by their
    # flags. asnmap defaults on, so ASN_MAP is present even though it is not named
    # in tool_selection; flag-off extras stay out; base always runs.
    cfg = ReconRuntimeConfig(
        mode="full",
        active_depth=1,
        enable_content_discovery=True,
        deep_port_scan=False,
        js_analysis=False,
        screenshots=False,
        tool_selection=frozenset({"url_history", "dig"}),
        wordlist_path="",
        rate_limit_rps=10,
    )
    steps = plan_recon_steps(cfg)
    assert ReconStepId.CONTENT_DISCOVERY in steps  # flag on
    assert ReconStepId.ASN_MAP in steps  # asnmap default on; tool_selection cannot exclude
    assert ReconStepId.JS_ANALYSIS not in steps  # flag off
    assert ReconStepId.SCREENSHOTS not in steps  # flag off
    assert ReconStepId.WHOIS in steps and ReconStepId.DIG in steps


def test_tool_selection_does_not_narrow_extras() -> None:
    # A narrow tool_selection must NOT cut any flag-enabled extra (no filtering).
    cfg = ReconRuntimeConfig(
        mode="full",
        active_depth=1,
        enable_content_discovery=True,
        deep_port_scan=True,
        js_analysis=True,
        screenshots=True,
        tool_selection=frozenset({"content_discovery", "dig"}),
        wordlist_path="",
        rate_limit_rps=10,
    )
    steps = plan_recon_steps(cfg)
    for extra in (
        ReconStepId.CONTENT_DISCOVERY,
        ReconStepId.JS_ANALYSIS,
        ReconStepId.ASN_MAP,
        ReconStepId.SCREENSHOTS,
        ReconStepId.DEEP_PORT_SCAN,
    ):
        assert extra in steps
    for essential in (ReconStepId.WHOIS, ReconStepId.DIG, ReconStepId.DNS_DEPTH, ReconStepId.HTTP_SURFACE):
        assert essential in steps
