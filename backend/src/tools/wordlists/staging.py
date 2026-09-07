"""Materialize a CredentialTestPlan into a sandbox input dir for brute-force tools.

The hydra/medusa/patator templates read ``{in_dir}/users.txt`` and
``{in_dir}/pass.txt`` (and this module adds ``credentials.txt`` for user:pass
pair lists). :func:`plan_wordlist_staging` turns a resolved
:class:`CredentialTestPlan` into the concrete file operations, and
:func:`materialize_staging` writes them into the tool's input directory.

Split from the network/registry layer so the file-op plan is pure and
unit-testable; the exploitation executor is the thin runtime consumer that
calls ``materialize_staging(plan_wordlist_staging(plan), in_dir)`` before
dispatching the auth tool.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path

from src.tools.wordlists.credential_plan import CredentialTestPlan

# Canonical in_dir filenames the brute-force tool templates expect.
USERS_FILE = "users.txt"
PASS_FILE = "pass.txt"
CREDENTIALS_FILE = "credentials.txt"


@dataclass(frozen=True)
class WordlistStage:
    """One file to place in the tool input dir: copy ``source`` or write ``content``."""

    dest_name: str
    source: Path | None = None
    content: str | None = None


def plan_wordlist_staging(plan: CredentialTestPlan) -> list[WordlistStage]:
    """Return the ordered file-stage operations for a credential test plan.

    * usernames — a resolved username wordlist file, else inline usernames
      materialized as ``users.txt`` content;
    * passwords — the resolved password wordlist as ``pass.txt``;
    * pairs — a resolved user:pass default-credentials list as ``credentials.txt``.
    """
    if not plan.enabled:
        return []

    stages: list[WordlistStage] = []
    if plan.username_path is not None:
        stages.append(WordlistStage(USERS_FILE, source=plan.username_path))
    elif plan.inline_usernames:
        stages.append(
            WordlistStage(USERS_FILE, content="\n".join(plan.inline_usernames) + "\n")
        )
    if plan.password_path is not None:
        stages.append(WordlistStage(PASS_FILE, source=plan.password_path))
    if plan.credential_pair_path is not None:
        stages.append(WordlistStage(CREDENTIALS_FILE, source=plan.credential_pair_path))
    return stages


def materialize_staging(stages: list[WordlistStage], in_dir: Path) -> list[Path]:
    """Write/copy staged wordlists into ``in_dir``; return the created paths."""
    in_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for stage in stages:
        dest = in_dir / stage.dest_name
        if stage.content is not None:
            dest.write_text(stage.content, encoding="utf-8")
        elif stage.source is not None:
            shutil.copyfile(stage.source, dest)
        else:  # pragma: no cover — defensive; a stage always has one source
            continue
        written.append(dest)
    return written


__all__ = [
    "CREDENTIALS_FILE",
    "PASS_FILE",
    "USERS_FILE",
    "WordlistStage",
    "materialize_staging",
    "plan_wordlist_staging",
]
