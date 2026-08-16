"""Phase 5 — Compose/Helm image pins, Grafana §18 coverage, Nuclei commit pins."""

from __future__ import annotations

import json
from pathlib import Path

import yaml
from src.core.unified_ai_metrics import METRIC_ALIAS_MAP


def _repo_root() -> Path:
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "infra" / "pins" / "nuclei.yaml").is_file():
            return parent
    raise FileNotFoundError("repository root with infra/pins not found")


def _load_yaml(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def test_local_model_compose_images_are_pinned() -> None:
    root = _repo_root()
    pins = _load_yaml(root / "infra" / "pins" / "local-models.yaml")
    compose = _load_yaml(root / "infra" / "docker-compose.local-models.yml")
    dockerfile = (root / "infra" / "local-models" / "Dockerfile").read_text(encoding="utf-8")
    assert "vllm/vllm-openai:v0.8.5" in dockerfile
    assert ":latest" not in dockerfile
    for name, spec in pins["models"].items():
        service = compose["services"][name]
        image = str(service["image"])
        assert ":latest" not in image
        assert ":local" not in image
        assert spec["image"].split(":")[1] in image
        assert service["build"]["context"] == "./local-models"


def test_helm_local_model_tags_are_pinned() -> None:
    root = _repo_root()
    pins = _load_yaml(root / "infra" / "pins" / "local-models.yaml")
    values = _load_yaml(root / "infra" / "helm" / "argus" / "values.yaml")
    for name, spec in pins["models"].items():
        tag = str(values["localModels"][name]["image"]["tag"])
        assert tag == pins["image_tag"]
        assert tag != "latest"
        assert spec["image"].endswith(f":{tag}")


def test_grafana_dashboard_covers_section_18_metrics() -> None:
    root = _repo_root()
    dashboard_path = root / "infra" / "grafana" / "dashboards" / "unified-ai-rag-lab.json"
    helm_copy = root / "infra" / "helm" / "argus" / "dashboards" / "unified-ai-rag-lab.json"
    payload = dashboard_path.read_text(encoding="utf-8")
    assert payload == helm_copy.read_text(encoding="utf-8")
    dashboard = json.loads(payload)
    for panel in dashboard["panels"]:
        for target in panel.get("targets", []):
            legend = str(target.get("legendFormat") or "")
            assert "{{" not in legend
    for prom_name in METRIC_ALIAS_MAP.values():
        assert prom_name in payload, prom_name


def test_observability_compose_pins_grafana_and_prometheus() -> None:
    root = _repo_root()
    pins = _load_yaml(root / "infra" / "pins" / "local-models.yaml")
    compose = _load_yaml(root / "infra" / "docker-compose.observability.yml")
    scrape = (root / "infra" / "prometheus" / "prometheus.unified-ai.yml").read_text(
        encoding="utf-8"
    )
    assert "backend:8000" in scrape
    assert "/metrics" in scrape
    grafana = str(compose["services"]["grafana"]["image"])
    prometheus = str(compose["services"]["prometheus"]["image"])
    assert pins["grafana_image"].split(":")[1] in grafana
    assert pins["prometheus_image"].split(":")[1] in prometheus
    assert ":latest" not in grafana
    assert ":latest" not in prometheus


def test_nuclei_pins_match_adr() -> None:
    root = _repo_root()
    pins = _load_yaml(root / "infra" / "pins" / "nuclei.yaml")
    adr = (root / "ai_docs" / "develop" / "architecture" / "2026-08-15-adr-unified-ai-rag-lab.md").read_text(
        encoding="utf-8"
    )
    sandbox = (root / "infra" / "Dockerfile.sandbox").read_text(encoding="utf-8")
    assert pins["nuclei"]["tag"] == "v3.11.1"
    assert pins["nuclei"]["commit"] == "a8c88feb4a1c8e961b7902534ce3af97e9d524a4"
    assert pins["nuclei_templates"]["tag"] == "v10.4.7"
    assert pins["nuclei_templates"]["commit"] == "83234ce456da3e90dda86dfbc5e605e64a846df3"
    assert pins["nuclei"]["commit"] in adr
    assert pins["nuclei_templates"]["commit"] in adr
    assert pins["nuclei"]["commit"] in sandbox
    assert pins["nuclei_templates"]["commit"] in sandbox
