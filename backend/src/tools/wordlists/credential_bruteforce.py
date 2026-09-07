"""Build the sandbox brute-force command for credential testing (WSTG-ATHN-02/03).

Pure command/argv construction for THC-Hydra HTTP form login brute-force, driven
by a resolved :class:`CredentialTestPlan` (bounded wordlists) plus a
:class:`LoginFormSpec` (discovered login endpoint + form shape). Kept pure and
unit-testable; the exploitation runtime is the thin consumer that (1) stages the
plan's wordlists into the sandbox, (2) builds the argv here, (3) runs it via
``docker exec`` — exactly like the other tool branches in
``exploitation_executor``.

Brute-force is authorized only for Full Surface (enforced upstream in
``credential_testing_policy``); this builder additionally returns ``None``
(safe skip) whenever the plan is disabled or the login form is not specified, so
a run without a discovered login endpoint never dispatches a malformed attack.
"""

from __future__ import annotations

from dataclasses import dataclass

from src.tools.wordlists.credential_plan import CredentialTestPlan

DEFAULT_SANDBOX = "argus-sandbox"
# Where wl-runtime staging (materialize_staging) places the wordlists *inside*
# the sandbox container before the command runs.
DEFAULT_STAGED_DIR = "/tmp/argus_creds"
_HYDRA_OUTPUT = "/tmp/argus_hydra.out"
# Bounded concurrency — matches the catalog hydra template (-t 4, -f, -I).
_HYDRA_THREADS = "4"


@dataclass(frozen=True)
class LoginFormSpec:
    """Discovered login endpoint + form shape for HTTP(S) form brute-force."""

    host: str
    port: int
    path: str
    #: Body with Hydra placeholders, e.g. ``username=^USER^&password=^PASS^``.
    body_template: str
    #: Substring marking a FAILED login (Hydra ``F=`` condition), e.g. ``Invalid``.
    failure_marker: str
    scheme: str = "https"

    def is_valid(self) -> bool:
        return bool(
            self.host
            and self.path
            and "^USER^" in self.body_template
            and "^PASS^" in self.body_template
            and self.failure_marker
            and self.scheme in ("http", "https")
            and 1 <= self.port <= 65535
        )


def build_hydra_argv(
    plan: CredentialTestPlan,
    form: LoginFormSpec,
    *,
    sandbox: str = DEFAULT_SANDBOX,
    staged_dir: str = DEFAULT_STAGED_DIR,
) -> list[str] | None:
    """Return the ``docker exec`` Hydra argv, or ``None`` to safely skip.

    ``None`` is returned when the plan is disabled or the login form is invalid
    (e.g. no login endpoint discovered) — the caller then records a skip rather
    than dispatching a malformed brute-force.
    """
    if not plan.enabled or not form.is_valid():
        return None

    service = f"{form.scheme}-post-form"
    form_str = f"{form.path}:{form.body_template}:F={form.failure_marker}"

    argv: list[str] = ["docker", "exec", sandbox, "hydra"]
    # Prefer a combined user:pass list (fewer attempts) when available.
    if plan.credential_pair_path is not None:
        argv += ["-C", f"{staged_dir}/credentials.txt"]
    else:
        argv += ["-L", f"{staged_dir}/users.txt", "-P", f"{staged_dir}/pass.txt"]

    argv += [
        "-t", _HYDRA_THREADS,  # bounded concurrency
        "-f",                  # stop on first valid credential
        "-I",                  # ignore restore file (deterministic)
        "-o", _HYDRA_OUTPUT,
        "-s", str(form.port),
        form.host,
        service,
        form_str,
    ]
    return argv


__all__ = ["DEFAULT_SANDBOX", "DEFAULT_STAGED_DIR", "LoginFormSpec", "build_hydra_argv"]
