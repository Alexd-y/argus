"""Valhalla report sections — decomposition of the ``valhalla_report_context`` monolith.

Wave 4 / Stage 6 (R-6.3.1/3): the 8k-line ``valhalla_report_context`` module is being
split section by section into this package, each submodule owning one cohesive report
section with its own tests. The monolith re-exports every moved symbol, so external
imports (``from src.reports.valhalla_report_context import …``) keep working unchanged
while the code moves out from under it.
"""
