"""Ed25519 signing service for the ARGUS tool catalog (Backlog/dev1_md §3, §18).

Every YAML descriptor under ``backend/config/tools/`` MUST be accompanied by a
record in ``backend/config/tools/SIGNATURES``. The application is *fail-closed*:
:class:`ToolRegistry.load` (in :mod:`src.sandbox.tool_registry`) refuses to start
when any descriptor is unsigned, signed by an unknown key, or has been tampered
with.

This module provides the cryptographic primitives:

* :class:`KeyManager` — discovers Ed25519 public keys under a directory
  (e.g. ``backend/config/tools/_keys/``). Keys are stored as raw 32-byte files
  named ``<key_id>.ed25519.pub``; ``key_id`` is the first 16 hex chars of the
  SHA-256 of the public key bytes. The dev keypair generator is a convenience
  for local development; production keys are mounted from a Kubernetes Secret /
  CSI volume and never live in the repo.
* :func:`sign_blob` / :func:`verify_blob` — pure functional Ed25519 signing /
  verification helpers (base64 over the signature only, never over the payload).
* :func:`compute_yaml_hash` — canonical SHA-256 of the raw bytes of a YAML
  file (no normalisation; signatures bind the bytes-on-disk).
* :class:`SignaturesFile` — parser / writer for the line-based ``SIGNATURES``
  manifest with strict format validation and integrity verification.

All errors are explicit subclasses of :class:`SignatureError` so callers can
log a structured event without leaking key material or payload contents.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import io
import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


_ED25519_RAW_KEY_LEN = 32
_ED25519_SIG_LEN = 64
_KEY_ID_LEN = 16
_PUBLIC_KEY_FILENAME_RE = re.compile(r"^([0-9a-f]{16})\.ed25519\.pub$")
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_KEY_ID_RE = re.compile(r"^[0-9a-f]{16}$")
_REL_PATH_RE = re.compile(r"^[A-Za-z0-9._/-]{1,256}$")


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class SignatureError(Exception):
    """Base class for all signing / verification errors raised by this module."""


class KeyNotFoundError(SignatureError):
    """Raised when a referenced ``public_key_id`` is not present in the keys dir."""


class IntegrityError(SignatureError):
    """Raised when a payload's SHA-256 / signature does not match the manifest."""


# ---------------------------------------------------------------------------
# Key utilities
# ---------------------------------------------------------------------------


def public_key_id(public_key: Ed25519PublicKey) -> str:
    """Return the canonical 16-hex-char id for an Ed25519 public key.

    The id is the first 16 hex chars of ``sha256(raw_public_key_bytes)``. This
    short id is what the ``SIGNATURES`` manifest carries on every record.
    """
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return hashlib.sha256(raw).hexdigest()[:_KEY_ID_LEN]


def load_public_key_bytes(raw: bytes) -> Ed25519PublicKey:
    """Load an Ed25519 public key from raw 32-byte material.

    Raises :class:`SignatureError` on malformed input. PEM-encoded keys are
    detected by their ``-----BEGIN`` prefix and routed through
    ``cryptography.hazmat.primitives.serialization.load_pem_public_key``.
    """
    if raw.startswith(b"-----BEGIN"):
        try:
            loaded = serialization.load_pem_public_key(raw)
        except (ValueError, TypeError) as exc:
            raise SignatureError("invalid PEM-encoded Ed25519 public key") from exc
        if not isinstance(loaded, Ed25519PublicKey):
            raise SignatureError(
                f"PEM key is not an Ed25519 public key (got {type(loaded).__name__})"
            )
        return loaded
    if len(raw) != _ED25519_RAW_KEY_LEN:
        raise SignatureError(
            f"raw Ed25519 public key must be {_ED25519_RAW_KEY_LEN} bytes, got {len(raw)}"
        )
    try:
        return Ed25519PublicKey.from_public_bytes(raw)
    except (ValueError, TypeError) as exc:
        raise SignatureError("malformed Ed25519 public key bytes") from exc


def load_private_key_bytes(raw: bytes) -> Ed25519PrivateKey:
    """Load an Ed25519 private key from raw 32-byte material or PEM."""
    if raw.startswith(b"-----BEGIN"):
        try:
            loaded = serialization.load_pem_private_key(raw, password=None)
        except (ValueError, TypeError) as exc:
            raise SignatureError("invalid PEM-encoded Ed25519 private key") from exc
        if not isinstance(loaded, Ed25519PrivateKey):
            raise SignatureError(
                f"PEM key is not an Ed25519 private key (got {type(loaded).__name__})"
            )
        return loaded
    if len(raw) != _ED25519_RAW_KEY_LEN:
        raise SignatureError(
            f"raw Ed25519 private key must be {_ED25519_RAW_KEY_LEN} bytes, got {len(raw)}"
        )
    try:
        return Ed25519PrivateKey.from_private_bytes(raw)
    except (ValueError, TypeError) as exc:
        raise SignatureError("malformed Ed25519 private key bytes") from exc


# ---------------------------------------------------------------------------
# Functional signing helpers
# ---------------------------------------------------------------------------


def sign_blob(private_key: Ed25519PrivateKey, payload: bytes) -> str:
    """Return the base64-encoded Ed25519 signature of ``payload``.

    Pure-functional; the input bytes are never logged. The signature is
    always 64 bytes raw → 88 chars base64 (with 1-char padding ``=``).
    """
    signature = private_key.sign(payload)
    return base64.b64encode(signature).decode("ascii")


def verify_blob(
    public_key: Ed25519PublicKey, payload: bytes, signature_b64: str
) -> bool:
    """Verify an Ed25519 ``signature_b64`` (base64) over ``payload``.

    Returns ``True`` on a valid signature; ``False`` on any verification
    failure (wrong key, tampered payload, malformed signature). Never raises
    for normal mismatch — only for input that cannot even be base64-decoded.
    """
    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except (binascii.Error, ValueError):
        return False
    if len(signature) != _ED25519_SIG_LEN:
        return False
    try:
        public_key.verify(signature, payload)
    except InvalidSignature:
        return False
    return True


def compute_yaml_hash(yaml_path: Path) -> str:
    """Return the lowercase hex SHA-256 of a YAML file's raw bytes.

    The hash is computed on bytes-on-disk with no normalisation: signatures
    bind exactly the file the operator inspects. Buffered read keeps memory
    use bounded for large catalogs.
    """
    digest = hashlib.sha256()
    with yaml_path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(64 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


# ---------------------------------------------------------------------------
# KeyManager
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _LoadedKey:
    """Internal record bundling a public key with its short id."""

    key_id: str
    public_key: Ed25519PublicKey


class KeyManager:
    """Filesystem-backed Ed25519 public-key store.

    Discovers ``<key_id>.ed25519.pub`` files (raw 32-byte) and / or
    ``<key_id>.ed25519.pub.pem`` files under the configured directory and
    indexes them by their canonical 16-hex-char id. Lookup is O(1).

    Production deployments mount keys via a Kubernetes Secret / CSI volume;
    development workflows use :meth:`generate_dev_keypair` to create a fresh
    pair under ``backend/config/tools/_keys/``. Private keys are NEVER
    indexed by this class — only public keys are loaded.
    """

    def __init__(self, keys_dir: Path) -> None:
        self._keys_dir = keys_dir
        self._index: dict[str, Ed25519PublicKey] = {}

    @property
    def keys_dir(self) -> Path:
        """Directory the manager scans for public keys."""
        return self._keys_dir

    @property
    def loaded_key_ids(self) -> tuple[str, ...]:
        """Return the loaded ``key_id``s in deterministic order."""
        return tuple(sorted(self._index))

    def load(self) -> int:
        """Discover and load every Ed25519 public key under :attr:`keys_dir`.

        Returns the number of keys loaded. Idempotent: callers may invoke
        :meth:`load` multiple times to pick up rotations. Raises
        :class:`SignatureError` only on malformed key material; missing
        directories yield zero keys (and are reported by the registry layer).
        """
        self._index.clear()
        if not self._keys_dir.exists():
            return 0
        loaded = 0
        for entry in sorted(self._keys_dir.iterdir()):
            if not entry.is_file():
                continue
            if not entry.name.endswith(".ed25519.pub"):
                continue
            match = _PUBLIC_KEY_FILENAME_RE.match(entry.name)
            raw = entry.read_bytes()
            public_key = load_public_key_bytes(raw)
            actual_id = public_key_id(public_key)
            if match is not None and match.group(1) != actual_id:
                raise SignatureError(
                    f"public key id mismatch for {entry.name!s}: "
                    f"file claims {match.group(1)}, actual {actual_id}"
                )
            if actual_id in self._index:
                raise SignatureError(
                    f"duplicate public_key_id {actual_id} in {self._keys_dir}"
                )
            self._index[actual_id] = public_key
            loaded += 1
        return loaded

    def get(self, key_id: str) -> Ed25519PublicKey:
        """Return the public key for ``key_id`` or raise :class:`KeyNotFoundError`."""
        if not _KEY_ID_RE.fullmatch(key_id):
            raise KeyNotFoundError(f"public_key_id {key_id!r} is malformed")
        try:
            return self._index[key_id]
        except KeyError as exc:
            raise KeyNotFoundError(
                f"public_key_id {key_id} is not present under {self._keys_dir}"
            ) from exc

    @staticmethod
    def generate_dev_keypair(
        out_dir: Path, name: str = "dev_signing"
    ) -> tuple[Path, Path, str]:
        """Generate a fresh Ed25519 dev keypair under ``out_dir``.

        Returns ``(private_key_path, public_key_path, key_id)``. Files are
        written with ``0o600`` (private) / ``0o644`` (public) permissions on
        POSIX; on Windows the platform-default ACLs apply. The public key
        filename embeds the canonical key id so :meth:`load` picks it up.

        Raises :class:`SignatureError` if ``out_dir`` does not exist; this is
        an explicit callout so dev tooling does not silently scatter keys.
        """
        if not out_dir.exists():
            raise SignatureError(f"keys output directory {out_dir!s} does not exist")
        if not out_dir.is_dir():
            raise SignatureError(f"keys output path {out_dir!s} is not a directory")

        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        kid = public_key_id(public_key)

        priv_path = out_dir / f"{name}.ed25519.priv"
        pub_path = out_dir / f"{kid}.ed25519.pub"

        priv_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pub_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

        priv_path.write_bytes(priv_bytes)
        pub_path.write_bytes(pub_bytes)
        try:
            priv_path.chmod(0o600)
            pub_path.chmod(0o644)
        except (OSError, NotImplementedError):
            # Windows / restricted filesystems — permissions are an
            # ops-level concern; the dev README documents the fallback.
            pass
        return priv_path, pub_path, kid


# ---------------------------------------------------------------------------
# SIGNATURES file model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SignatureRecord:
    """One line of the ``SIGNATURES`` manifest."""

    sha256_hex: str
    relative_path: str
    signature_b64: str
    public_key_id: str

    def __post_init__(self) -> None:
        if not _HEX64_RE.fullmatch(self.sha256_hex):
            raise SignatureError(
                f"sha256_hex must be 64 lowercase hex chars, got {self.sha256_hex!r}"
            )
        if not _REL_PATH_RE.fullmatch(self.relative_path):
            raise SignatureError(
                f"relative_path {self.relative_path!r} contains illegal characters"
            )
        if "/.." in self.relative_path or self.relative_path.startswith(".."):
            raise SignatureError(
                "relative_path must not traverse out of the catalog dir"
            )
        if self.relative_path.startswith("/"):
            raise SignatureError(
                "relative_path must be a relative POSIX path (no leading /)"
            )
        try:
            decoded = base64.b64decode(self.signature_b64, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise SignatureError("signature_b64 is not valid base64") from exc
        if len(decoded) != _ED25519_SIG_LEN:
            raise SignatureError(
                f"Ed25519 signatures decode to {_ED25519_SIG_LEN} bytes, got {len(decoded)}"
            )
        if not _KEY_ID_RE.fullmatch(self.public_key_id):
            raise SignatureError(f"public_key_id {self.public_key_id!r} is malformed")

    def serialize(self) -> str:
        """Render the record as one whitespace-separated line (no trailing \\n)."""
        return f"{self.sha256_hex}  {self.relative_path}  {self.signature_b64}  {self.public_key_id}"


_HEADER_LINES: tuple[str, ...] = (
    "# ARGUS tool catalog signatures",
    "# format: <sha256_hex>  <yaml_path_rel_to_config_tools>  <ed25519_signature_b64>  <public_key_id>",
    "# generated by: python backend/scripts/tools_sign.py --sign",
)


class SignaturesFile:
    """Parser / writer for the ``backend/config/tools/SIGNATURES`` manifest.

    Format (one record per non-comment, non-blank line, whitespace-separated)::

        <sha256_hex>  <relative_yaml_path>  <ed25519_signature_b64>  <public_key_id>

    Lines starting with ``#`` and empty lines are preserved on round-trip
    *only* when they appear before any record (header comments). The
    canonical writer always re-emits the header from :data:`_HEADER_LINES`.
    """

    def __init__(self, records: dict[str, SignatureRecord] | None = None) -> None:
        self._records: dict[str, SignatureRecord] = dict(records or {})

    @property
    def records(self) -> dict[str, SignatureRecord]:
        """Return a shallow copy of the records dict (keyed by relative path)."""
        return dict(self._records)

    def __len__(self) -> int:
        return len(self._records)

    def __contains__(self, relative_path: object) -> bool:
        return isinstance(relative_path, str) and relative_path in self._records

    def get(self, relative_path: str) -> SignatureRecord | None:
        """Return the record for ``relative_path`` or ``None`` if absent."""
        return self._records.get(relative_path)

    @classmethod
    def parse(cls, text: str) -> SignaturesFile:
        """Parse the textual ``SIGNATURES`` manifest into a strict model.

        Raises :class:`SignatureError` on malformed lines, duplicate paths,
        or any record that fails its individual validators.
        """
        records: dict[str, SignatureRecord] = {}
        for lineno, raw_line in enumerate(text.splitlines(), start=1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) != 4:
                raise SignatureError(
                    f"SIGNATURES line {lineno}: expected 4 whitespace-separated fields, "
                    f"got {len(parts)}"
                )
            sha256_hex, relative_path, signature_b64, key_id = parts
            record = SignatureRecord(
                sha256_hex=sha256_hex.lower(),
                relative_path=relative_path,
                signature_b64=signature_b64,
                public_key_id=key_id.lower(),
            )
            if record.relative_path in records:
                raise SignatureError(
                    f"SIGNATURES line {lineno}: duplicate entry for {record.relative_path!r}"
                )
            records[record.relative_path] = record
        return cls(records)

    @classmethod
    def from_file(cls, path: Path) -> SignaturesFile:
        """Load the ``SIGNATURES`` manifest from disk."""
        if not path.exists():
            raise SignatureError(f"SIGNATURES file {path!s} does not exist")
        return cls.parse(path.read_text(encoding="utf-8"))

    def write(self, path: Path) -> None:
        """Write the manifest to ``path`` atomically (header + sorted records)."""
        buf = io.StringIO()
        for header in _HEADER_LINES:
            buf.write(header + "\n")
        for relative_path in sorted(self._records):
            buf.write(self._records[relative_path].serialize() + "\n")
        tmp_path = path.with_suffix(path.suffix + ".tmp")
        tmp_path.write_text(buf.getvalue(), encoding="utf-8")
        tmp_path.replace(path)

    def upsert(self, record: SignatureRecord) -> None:
        """Insert or overwrite the record for ``record.relative_path``."""
        self._records[record.relative_path] = record

    def verify_one(
        self,
        relative_path: str,
        yaml_bytes: bytes,
        public_key_resolver: Callable[[str], Ed25519PublicKey],
    ) -> SignatureRecord:
        """Verify the ``relative_path`` entry against ``yaml_bytes``.

        Resolves the public key via ``public_key_resolver(public_key_id)``.
        Returns the matching :class:`SignatureRecord` on success; raises
        :class:`KeyNotFoundError` for unknown keys and :class:`IntegrityError`
        for any hash / signature mismatch.
        """
        record = self._records.get(relative_path)
        if record is None:
            raise IntegrityError(f"no SIGNATURES entry for {relative_path!r}")
        actual_hash = hashlib.sha256(yaml_bytes).hexdigest()
        if actual_hash != record.sha256_hex:
            raise IntegrityError(
                f"sha256 mismatch for {relative_path!r}: "
                f"manifest={record.sha256_hex} actual={actual_hash}"
            )
        public_key = public_key_resolver(record.public_key_id)
        if not verify_blob(public_key, yaml_bytes, record.signature_b64):
            raise IntegrityError(
                f"Ed25519 signature mismatch for {relative_path!r} "
                f"(key_id={record.public_key_id})"
            )
        return record
