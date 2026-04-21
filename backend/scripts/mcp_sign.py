"""CLI utility for managing the ARGUS MCP server config signing workflow.

Mirrors :mod:`backend.scripts.prompts_sign` and :mod:`backend.scripts.tools_sign`
but operates on ``backend/config/mcp/*.yaml`` and the matching ``SIGNATURES`` /
``_keys/`` directory. Three sub-commands, all argparse-driven so the tool
can be wired into CI:

* ``generate-keys --out backend/config/mcp/_keys/``
    Generates a fresh Ed25519 development keypair under ``out``. Emits the
    public ``<key_id>.ed25519.pub`` and the private
    ``dev_signing.ed25519.priv`` (chmod 0600 on POSIX). Production keys
    NEVER come from this command.

* ``sign --key <priv> --mcp-dir <dir> --out <SIGNATURES>``
    Recomputes SHA-256 + Ed25519 signature for every ``*.yaml`` under
    ``mcp-dir`` and rewrites ``out`` (atomic, sorted by relative path).

* ``verify --mcp-dir <dir> --signatures <SIGNATURES> --keys-dir <keys>``
    Verifies every YAML under ``mcp-dir`` against the manifest. Exits
    non-zero on any mismatch and emits one structured JSON line per failing
    entry. Stack traces are NEVER leaked.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import sys
from collections.abc import Sequence
from pathlib import Path

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

_logger = logging.getLogger("mcp_sign")


def _emit(event: str, **fields: object) -> None:
    record = {"event": event, **fields}
    print(json.dumps(record, sort_keys=True, ensure_ascii=False), file=sys.stdout)


def _fail(event: str, **fields: object) -> int:
    record = {"event": event, **fields}
    print(json.dumps(record, sort_keys=True, ensure_ascii=False), file=sys.stderr)
    return 1


def _cmd_generate(out_dir: Path, name: str) -> int:
    out_dir.mkdir(parents=True, exist_ok=True)
    try:
        priv_path, pub_path, key_id = KeyManager.generate_dev_keypair(
            out_dir, name=name
        )
    except SignatureError as exc:
        return _fail("generate_keys.error", reason=str(exc), out_dir=str(out_dir))
    _emit(
        "generate_keys.ok",
        key_id=key_id,
        public_key_path=str(pub_path),
        private_key_path=str(priv_path),
        warning=(
            "dev keypair only - production keys must come from the HSM / "
            "Vault / k8s Secret. Delete the private key after signing if you "
            "do not plan to rotate again."
        ),
    )
    return 0


def _iter_yaml(mcp_dir: Path) -> list[Path]:
    return sorted(p for p in mcp_dir.glob("*.yaml") if p.is_file())


def _cmd_sign(key_path: Path, mcp_dir: Path, out_path: Path) -> int:
    if not key_path.is_file():
        return _fail(
            "sign.error", reason="private key file not found", key_path=str(key_path)
        )
    if not mcp_dir.is_dir():
        return _fail(
            "sign.error",
            reason="mcp dir does not exist",
            mcp_dir=str(mcp_dir),
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
    yaml_paths = _iter_yaml(mcp_dir)
    if not yaml_paths:
        return _fail(
            "sign.error",
            reason="no YAML descriptors found",
            mcp_dir=str(mcp_dir),
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
        rel = yaml_path.relative_to(mcp_dir).as_posix()
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
        return _fail(
            "sign.error",
            reason="failed to write SIGNATURES",
            out=str(out_path),
            os_error=exc.strerror,
        )

    _emit(
        "sign.ok",
        signed_count=len(yaml_paths),
        key_id=key_id,
        signatures_path=str(out_path),
    )
    return 0


def _cmd_verify(mcp_dir: Path, signatures_path: Path, keys_dir: Path) -> int:
    if not mcp_dir.is_dir():
        return _fail(
            "verify.error",
            reason="mcp dir does not exist",
            mcp_dir=str(mcp_dir),
        )
    if not signatures_path.is_file():
        return _fail(
            "verify.error",
            reason="SIGNATURES file does not exist",
            signatures=str(signatures_path),
        )
    if not keys_dir.is_dir():
        return _fail(
            "verify.error", reason="keys dir does not exist", keys_dir=str(keys_dir)
        )

    try:
        signatures = SignaturesFile.from_file(signatures_path)
    except SignatureError as exc:
        return _fail("verify.error", reason=str(exc), signatures=str(signatures_path))

    keys = KeyManager(keys_dir)
    try:
        keys.load()
    except SignatureError as exc:
        return _fail("verify.error", reason=str(exc), keys_dir=str(keys_dir))

    yaml_paths = _iter_yaml(mcp_dir)
    failures: list[str] = []

    expected_paths = {p.relative_to(mcp_dir).as_posix() for p in yaml_paths}
    extra_in_manifest = sorted(set(signatures.records) - expected_paths)
    for stale in extra_in_manifest:
        _fail("verify.error", reason="manifest references missing YAML", yaml=stale)
        failures.append(stale)

    for yaml_path in yaml_paths:
        rel = yaml_path.relative_to(mcp_dir).as_posix()
        try:
            yaml_bytes = yaml_path.read_bytes()
        except OSError as exc:
            _fail(
                "verify.error",
                reason="failed to read YAML",
                yaml=rel,
                os_error=exc.strerror,
            )
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


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp_sign",
        description="Manage Ed25519 signatures for the ARGUS MCP server config.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    gen = sub.add_parser("generate-keys", help="Generate a dev Ed25519 keypair.")
    gen.add_argument(
        "--out", required=True, type=Path, help="Output directory for keys."
    )
    gen.add_argument("--name", default="dev_signing", help="Private key filename stem.")

    sign = sub.add_parser("sign", help="Recompute SIGNATURES for all YAMLs.")
    sign.add_argument("--key", required=True, type=Path, help="Path to private key.")
    sign.add_argument(
        "--mcp-dir",
        default=Path("backend/config/mcp"),
        type=Path,
        help="Directory containing MCP config YAMLs.",
    )
    sign.add_argument(
        "--out",
        default=Path("backend/config/mcp/SIGNATURES"),
        type=Path,
        help="Output SIGNATURES file path.",
    )

    verify = sub.add_parser(
        "verify", help="Verify SIGNATURES against current YAMLs and keys."
    )
    verify.add_argument(
        "--mcp-dir",
        default=Path("backend/config/mcp"),
        type=Path,
        help="Directory containing MCP config YAMLs.",
    )
    verify.add_argument(
        "--signatures",
        default=Path("backend/config/mcp/SIGNATURES"),
        type=Path,
        help="Path to SIGNATURES manifest.",
    )
    verify.add_argument(
        "--keys-dir",
        default=Path("backend/config/mcp/_keys"),
        type=Path,
        help="Directory holding *.ed25519.pub keys.",
    )

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "generate-keys":
        return _cmd_generate(args.out, args.name)
    if args.command == "sign":
        return _cmd_sign(args.key, args.mcp_dir, args.out)
    if args.command == "verify":
        return _cmd_verify(args.mcp_dir, args.signatures, args.keys_dir)

    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
