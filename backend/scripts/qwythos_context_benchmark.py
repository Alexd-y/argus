"""CLI wrapper for Qwythos 8k/32k/64k context benchmark (DoD §22)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.llm.qwythos_benchmark import benchmark_summary, run_qwythos_benchmark


def main() -> int:
    results = run_qwythos_benchmark()
    print(json.dumps(benchmark_summary(results), indent=2))
    return 0 if all(item.accepted for item in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
