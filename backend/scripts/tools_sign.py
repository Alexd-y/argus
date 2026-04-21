"""CLI utility for managing the ARGUS tool catalog signing workflow.

Three sub-commands, all argparse-driven so the tool can be wired into CI:

* ``--generate-keys --out backend/config/tools/_keys/``
    Generates a fresh Ed25519 development keypair under ``out``. Emits the
    public ``<key_id>.ed25519.pub`` (where ``key_id`` is the first 16 hex
    chars of ``sha256(pub_bytes)``) and the private ``dev_signing.ed25519.priv``
    (chmod 0600 on POSIX). Production keys are NEVER generated this way —
    they are minted in the HSM / KMS and mounted via Kubernetes Secret /
    CSI, see ``backend/config/tools/_keys/README.md``.

* ``--sign --key <priv> --tools-dir <dir> --out <SIGNATURES>``
    Recomputes the SHA-256 + Ed25519 signature for every ``*.yaml`` under
    ``tools-dir`` and rewrites ``out`` (atomic, sorted by relative path).

* ``--verify --tools-dir <dir> --signatures <SIGNATURES> --keys-dir <keys>``
    Verifies every YAML under ``tools-dir`` against the manifest. Exits
    non-zero on any mismatch and prints a single-line structured error per
    failing entry. Stack traces are NEVER leaked.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import sys
from collections.abc import Sequence
from pathlib import Path

# Make ``backend/`` importable when invoked as ``python backend/scripts/tools_sign.py``
_BACKEND_ROOT = Path(__file__).resolve().parent.parent
if str(_BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(_BACKEND_ROOT))

from src.sandbox.signing import (  # noqa: E402  (sys.path tweak above)
    KeyManager,
    KeyNotFoundError,
    SignatureError,
    SignatureRecord,
    SignaturesFile,
    load_private_key_bytes,
    public_key_id,
    sign_blob,
)


_logger = logging.getLogger("tools_sign")


# ---------------------------------------------------------------------------
# Output helpers (single-line structured logs; no stack traces)
# ---------------------------------------------------------------------------


def _emit(event: str, **fields: object) -> None:
    """Print one JSON line per event. Unicode-safe and grep-friendly."""
    record = {"event": event, **fields}
    print(json.dumps(record, sort_keys=True, ensure_ascii=False), file=sys.stdout)


def _fail(event: str, **fields: object) -> int:
    record = {"event": event, **fields}
    print(json.dumps(record, sort_keys=True, ensure_ascii=False), file=sys.stderr)
    return 1


# ---------------------------------------------------------------------------
# Sub-command: --generate-keys
# ---------------------------------------------------------------------------


def _cmd_generate(out_dir: Path, name: str) -> int:
    out_dir.mkdir(parents=True, exist_ok=True)
    try:
        priv_path, pub_path, key_id = KeyManager.generate_dev_keypair(out_dir, name=name)
    except SignatureError as exc:
        return _fail("generate_keys.error", reason=str(exc), out_dir=str(out_dir))
    _emit(
        "generate_keys.ok",
        key_id=key_id,
        public_key_path=str(pub_path),
        private_key_path=str(priv_path),
        warning="dev keypair only - production keys must come from the HSM / Vault / k8s Secret",
    )
    return 0


# ---------------------------------------------------------------------------
# Sub-command: --sign
# ---------------------------------------------------------------------------


def _iter_yaml(tools_dir: Path) -> list[Path]:
    return sorted(p for p in tools_dir.glob("*.yaml") if p.is_file())


def _cmd_sign(key_path: Path, tools_dir: Path, out_path: Path) -> int:
    if not key_path.is_file():
        return _fail("sign.error", reason="private key file not found", key_path=str(key_path))
    if not tools_dir.is_dir():
        return _fail("sign.error", reason="tools dir does not exist", tools_dir=str(tools_dir))

    try:
        private_key = load_private_key_bytes(key_path.read_bytes())
    except SignatureError as exc:
        return _fail("sign.error", reason=str(exc), key_path=str(key_path))
    except OSError as exc:
        return _fail("sign.error", reason="failed to read private key", key_path=str(key_path), os_error=exc.strerror)

    key_id = public_key_id(private_key.public_key())
    signatures = SignaturesFile()
    yaml_paths = _iter_yaml(tools_dir)
    for yaml_path in yaml_paths:
        try:
            yaml_bytes = yaml_path.read_bytes()
        except OSError as exc:
            return _fail(
                "sign.error",
                reason="failed to read YAML",
                yaml=yaml_path.name,
                os_error=exc.strerror,
            )
        rel = yaml_path.relative_to(tools_dir).as_posix()
        sha = hashlib.sha256(yaml_bytes).hexdigest()
        try:
            signature_b64 = sign_blob(private_key, yaml_bytes)
            record = SignatureRecord(
                sha256_hex=sha,
                relative_path=rel,
                signature_b64=signature_b64,
                public_key_id=key_id,
            )
        except SignatureError as exc:
            return _fail("sign.error", reason=str(exc), yaml=rel)
        signatures.upsert(record)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        signatures.write(out_path)
    except OSError as exc:
        return _fail("sign.error", reason="failed to write SIGNATURES", out=str(out_path), os_error=exc.strerror)

    _emit(
        "sign.ok",
        signed_count=len(yaml_paths),
        key_id=key_id,
        signatures_path=str(out_path),
    )
    return 0


# ---------------------------------------------------------------------------
# Sub-command: --verify
# ---------------------------------------------------------------------------


def _cmd_verify(tools_dir: Path, signatures_path: Path, keys_dir: Path) -> int:
    if not tools_dir.is_dir():
        return _fail("verify.error", reason="tools dir does not exist", tools_dir=str(tools_dir))
    if not signatures_path.is_file():
        return _fail(
            "verify.error",
            reason="SIGNATURES file does not exist",
            signatures=str(signatures_path),
        )
    if not keys_dir.is_dir():
        return _fail("verify.error", reason="keys dir does not exist", keys_dir=str(keys_dir))

    try:
        signatures = SignaturesFile.from_file(signatures_path)
    except SignatureError as exc:
        return _fail("verify.error", reason=str(exc), signatures=str(signatures_path))

    keys = KeyManager(keys_dir)
    try:
        keys.load()
    except SignatureError as exc:
        return _fail("verify.error", reason=str(exc), keys_dir=str(keys_dir))

    yaml_paths = _iter_yaml(tools_dir)
    failures: list[str] = []

    expected_paths = {p.relative_to(tools_dir).as_posix() for p in yaml_paths}
    extra_in_manifest = sorted(set(signatures.records) - expected_paths)
    for stale in extra_in_manifest:
        _fail("verify.error", reason="manifest references missing YAML", yaml=stale)
        failures.append(stale)

    for yaml_path in yaml_paths:
        rel = yaml_path.relative_to(tools_dir).as_posix()
        try:
            yaml_bytes = yaml_path.read_bytes()
        except OSError as exc:
            _fail("verify.error", reason="failed to read YAML", yaml=rel, os_error=exc.strerror)
            failures.append(rel)
            continue
        try:
            signatures.verify_one(
                relative_path=rel,
                yaml_bytes=yaml_bytes,
                public_key_resolver=keys.get,
            )
        except (SignatureError, KeyNotFoundError) as exc:
            _fail("verify.error", reason=str(exc), yaml=rel)
            failures.append(rel)
            continue
        _emit("verify.entry_ok", yaml=rel)

    if failures:
        return _fail(
            "verify.failed",
            reason="one or more entries failed verification",
            failures=sorted(set(failures)),
        )
    _emit(
        "verify.ok",
        verified_count=len(yaml_paths),
        signatures_path=str(signatures_path),
    )
    return 0


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tools_sign",
        description="Manage Ed25519 signatures for the ARGUS tool catalog.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    gen = sub.add_parser("generate-keys", help="Generate a dev Ed25519 keypair.")
    gen.add_argument("--out", required=True, type=Path, help="Output directory for keys.")
    gen.add_argument("--name", default="dev_signing", help="Private key filename stem.")

    sign = sub.add_parser("sign", help="Recompute SIGNATURES for all YAMLs.")
    sign.add_argument("--key", required=True, type=Path, help="Private key path.")
    sign.add_argument("--tools-dir", required=True, type=Path, help="Tools YAML directory.")
    sign.add_argument("--out", required=True, type=Path, help="SIGNATURES output path.")

    ver = sub.add_parser("verify", help="Verify SIGNATURES against the YAML catalog.")
    ver.add_argument("--tools-dir", required=True, type=Path, help="Tools YAML directory.")
    ver.add_argument("--signatures", required=True, type=Path, help="SIGNATURES file.")
    ver.add_argument("--keys-dir", required=True, type=Path, help="Public keys directory.")
    return parser


def _parse_legacy_flags(argv: Sequence[str]) -> Sequence[str]:
    """Translate the documented flag-style invocation into sub-commands.

    The cycle plan documents the flag-style form (``--generate-keys``,
    ``--sign``, ``--verify``) used in CI scripts; argparse sub-commands are
    cleaner internally. This shim accepts either form so existing operator
    docs keep working.
    """
    if not argv:
        return argv
    head = argv[0]
    if head == "--generate-keys":
        return ["generate-keys", *argv[1:]]
    if head == "--sign":
        return ["sign", *argv[1:]]
    if head == "--verify":
        return ["verify", *argv[1:]]
    return argv


def main(argv: Sequence[str] | None = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    raw = list(_parse_legacy_flags(raw))
    parser = _build_parser()
    args = parser.parse_args(raw)

    if args.command == "generate-keys":
        return _cmd_generate(out_dir=args.out, name=args.name)
    if args.command == "sign":
        return _cmd_sign(key_path=args.key, tools_dir=args.tools_dir, out_path=args.out)
    if args.command == "verify":
        return _cmd_verify(
            tools_dir=args.tools_dir,
            signatures_path=args.signatures,
            keys_dir=args.keys_dir,
        )
    parser.error(f"unknown command {args.command!r}")
    return 2  # unreachable, parser.error exits


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
