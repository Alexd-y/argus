"""CLI utility for the ARGUS playbook catalog signing workflow.

Mirrors :mod:`backend.scripts.payloads_sign` but operates on the playbook
catalog under ``backend/config/playbooks/`` — which, unlike the flat payload
catalog, is organised into per-category subdirectories. Discovery is therefore
**recursive** (``rglob``) and the signed relative path includes the category
segment (e.g. ``authorization/idor.cross-user-read.yaml``).

Three argparse sub-commands (CI-friendly):

* ``generate-keys --out backend/config/playbooks/_keys/``
    Generates a fresh Ed25519 dev keypair. Production keys never come from here.

* ``sign --key <priv> --playbooks-dir <dir> --out <SIGNATURES>``
    Recomputes SHA-256 + Ed25519 signature for every ``*.yaml`` under
    ``playbooks-dir`` (recursively, excluding ``_keys/``) and rewrites ``out``.

* ``verify --playbooks-dir <dir> --signatures <SIGNATURES> --keys-dir <keys>``
    Verifies every YAML against the manifest. Exits non-zero on any mismatch;
    stack traces are never leaked.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import sys
from collections.abc import Sequence
from pathlib import Path

# Allow `python backend/scripts/playbooks_sign.py ...` invocation.
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

_logger = logging.getLogger("playbooks_sign")
_KEYS_DIRNAME = "_keys"


def _emit(event: str, **fields: object) -> None:
    print(json.dumps({"event": event, **fields}, sort_keys=True, ensure_ascii=False))


def _fail(event: str, **fields: object) -> int:
    print(
        json.dumps({"event": event, **fields}, sort_keys=True, ensure_ascii=False),
        file=sys.stderr,
    )
    return 1


def _iter_yaml(playbooks_dir: Path) -> list[Path]:
    """Recursively collect ``*.yaml`` files, excluding the ``_keys`` dir."""
    return sorted(
        p
        for p in playbooks_dir.rglob("*.yaml")
        if p.is_file() and _KEYS_DIRNAME not in p.relative_to(playbooks_dir).parts
    )


# ---------------------------------------------------------------------------
# generate-keys
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
        warning=(
            "dev keypair only - production keys must come from the HSM / Vault / "
            "k8s Secret. Delete the private key after signing."
        ),
    )
    return 0


# ---------------------------------------------------------------------------
# sign
# ---------------------------------------------------------------------------


def _cmd_sign(key_path: Path, playbooks_dir: Path, out_path: Path) -> int:
    if not key_path.is_file():
        return _fail("sign.error", reason="private key file not found", key_path=str(key_path))
    if not playbooks_dir.is_dir():
        return _fail(
            "sign.error", reason="playbooks dir does not exist", playbooks_dir=str(playbooks_dir)
        )

    try:
        private_key = load_private_key_bytes(key_path.read_bytes())
    except SignatureError as exc:
        return _fail("sign.error", reason=str(exc), key_path=str(key_path))
    except OSError as exc:
        return _fail(
            "sign.error",
            reason="failed to read private key",
            key_path=str(key_path),
            os_error=exc.strerror,
        )

    key_id = public_key_id(private_key.public_key())
    signatures = SignaturesFile()
    yaml_paths = _iter_yaml(playbooks_dir)
    if not yaml_paths:
        return _fail(
            "sign.error", reason="no YAML descriptors found", playbooks_dir=str(playbooks_dir)
        )

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
        rel = yaml_path.relative_to(playbooks_dir).as_posix()
        try:
            record = SignatureRecord(
                sha256_hex=hashlib.sha256(yaml_bytes).hexdigest(),
                relative_path=rel,
                signature_b64=sign_blob(private_key, yaml_bytes),
                public_key_id=key_id,
            )
        except SignatureError as exc:
            return _fail("sign.error", reason=str(exc), yaml=rel)
        signatures.upsert(record)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        signatures.write(out_path)
    except OSError as exc:
        return _fail(
            "sign.error",
            reason="failed to write SIGNATURES",
            out=str(out_path),
            os_error=exc.strerror,
        )

    _emit("sign.ok", signed_count=len(yaml_paths), key_id=key_id, signatures_path=str(out_path))
    return 0


# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------


def _cmd_verify(playbooks_dir: Path, signatures_path: Path, keys_dir: Path) -> int:
    if not playbooks_dir.is_dir():
        return _fail(
            "verify.error", reason="playbooks dir does not exist", playbooks_dir=str(playbooks_dir)
        )
    if not signatures_path.is_file():
        return _fail(
            "verify.error", reason="SIGNATURES file does not exist", signatures=str(signatures_path)
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

    yaml_paths = _iter_yaml(playbooks_dir)
    failures: list[str] = []

    expected_paths = {p.relative_to(playbooks_dir).as_posix() for p in yaml_paths}
    for stale in sorted(set(signatures.records) - expected_paths):
        _fail("verify.error", reason="manifest references missing YAML", yaml=stale)
        failures.append(stale)

    for yaml_path in yaml_paths:
        rel = yaml_path.relative_to(playbooks_dir).as_posix()
        try:
            yaml_bytes = yaml_path.read_bytes()
        except OSError as exc:
            _fail("verify.error", reason="failed to read YAML", yaml=rel, os_error=exc.strerror)
            failures.append(rel)
            continue
        try:
            signatures.verify_one(
                relative_path=rel, yaml_bytes=yaml_bytes, public_key_resolver=keys.get
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
    _emit("verify.ok", verified_count=len(yaml_paths), signatures_path=str(signatures_path))
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="playbooks_sign",
        description="Manage Ed25519 signatures for the ARGUS playbook catalog.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    gen = sub.add_parser("generate-keys", help="Generate a dev Ed25519 keypair.")
    gen.add_argument("--out", required=True, type=Path, help="Output directory for keys.")
    gen.add_argument("--name", default="dev_signing", help="Private key filename stem.")

    sign = sub.add_parser("sign", help="Recompute SIGNATURES for all playbook YAMLs.")
    sign.add_argument("--key", required=True, type=Path, help="Private key path.")
    sign.add_argument("--playbooks-dir", required=True, type=Path, help="Playbooks YAML directory.")
    sign.add_argument("--out", required=True, type=Path, help="SIGNATURES output path.")

    ver = sub.add_parser("verify", help="Verify SIGNATURES against the playbook catalog.")
    ver.add_argument("--playbooks-dir", required=True, type=Path, help="Playbooks YAML directory.")
    ver.add_argument("--signatures", required=True, type=Path, help="SIGNATURES file.")
    ver.add_argument("--keys-dir", required=True, type=Path, help="Public keys directory.")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(list(sys.argv[1:] if argv is None else argv))

    if args.command == "generate-keys":
        return _cmd_generate(out_dir=args.out, name=args.name)
    if args.command == "sign":
        return _cmd_sign(key_path=args.key, playbooks_dir=args.playbooks_dir, out_path=args.out)
    if args.command == "verify":
        return _cmd_verify(
            playbooks_dir=args.playbooks_dir,
            signatures_path=args.signatures,
            keys_dir=args.keys_dir,
        )
    parser.error(f"unknown command {args.command!r}")
    return 2


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
