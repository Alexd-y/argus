"""H-1: Intelligence endpoints require auth."""

from __future__ import annotations


class TestIntelligenceRouterAuth:
    """Intelligence router must declare auth dependencies."""

    def test_intelligence_router_has_auth_dependency(self) -> None:
        from src.api.routers.intelligence import router

        assert len(router.dependencies) > 0, "Intelligence router must have auth dependencies"

    def test_intelligence_router_uses_get_required_auth(self) -> None:
        from src.api.routers.intelligence import router

        dep_names: list[str] = []
        for dep in router.dependencies:
            if hasattr(dep, "dependency") and hasattr(dep.dependency, "__name__"):
                dep_names.append(dep.dependency.__name__)
            else:
                dep_names.append(str(dep))

        assert any(
            "get_required_auth" in n for n in dep_names
        ), f"Expected get_required_auth in dependencies, got: {dep_names}"

    def test_intelligence_imports_auth_module(self) -> None:
        from pathlib import Path

        intel_src = (
            Path(__file__).resolve().parent.parent
            / "src"
            / "api"
            / "routers"
            / "intelligence.py"
        )
        text = intel_src.read_text(encoding="utf-8")
        assert "from src.core.auth import" in text
        assert "get_required_auth" in text
