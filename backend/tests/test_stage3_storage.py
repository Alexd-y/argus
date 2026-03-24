"""Stage 3 storage — root file list and import fallbacks."""

import builtins
from unittest.mock import patch

from src.recon.stage3_storage import _STAGE3_STATIC_FILES, get_stage3_root_files


def test_get_stage3_root_files_fallback_on_registry_import_error() -> None:
    real_import = builtins.__import__

    def guarded_import(name: str, *args: object, **kwargs: object) -> object:
        if name == "src.recon.vulnerability_analysis.ai_task_registry":
            raise ImportError("simulated missing VA task registry")
        return real_import(name, *args, **kwargs)

    with patch("builtins.__import__", side_effect=guarded_import):
        assert get_stage3_root_files() == tuple(_STAGE3_STATIC_FILES)
