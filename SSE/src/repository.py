"""
repository.py
=============

The high-level orchestration layer the UI talks to. It wires together:

    key management  (load/generate master secret, derive keys)
    crypto          (AES-GCM encrypt/decrypt)
    document_processor (validate + extract text)
    index           (build + query HMAC tokens)
    database        (metadata + token storage)
    file storage    (write/read .enc blobs on disk)

The UI should only ever need this module plus the custom exception types.
"""

from __future__ import annotations

import os
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from dotenv import load_dotenv

from . import crypto, document_processor, index
from .crypto import CryptoError, KeySet
from .database import Database, DatabaseError, DocumentRecord
from .document_processor import (
    FileTooLargeError,
    UnsupportedFileError,
)

# --- Paths (relative to the project root, i.e. this file's grandparent) -----

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DATA_DIR = _PROJECT_ROOT / "data"
DEFAULT_ENCRYPTED_DIR = DEFAULT_DATA_DIR / "encrypted_documents"
DEFAULT_DB_PATH = DEFAULT_DATA_DIR / "repository.db"
DEFAULT_KEY_FILE = DEFAULT_DATA_DIR / "master.key"

_MASTER_KEY_ENV = "SSE_MASTER_KEY"


class RepositoryError(Exception):
    """Generic repository failure surfaced to the UI with a friendly message."""


class DuplicateDocumentError(RepositoryError):
    """Raised when a document with the same filename already exists."""


@dataclass(frozen=True)
class UploadResult:
    """Summary returned to the UI after a successful upload."""

    document_id: int
    original_filename: str
    encrypted_filename: str
    file_size: int
    token_count: int


@dataclass(frozen=True)
class SearchHit:
    """One matching document in a search result."""

    document_id: int
    original_filename: str
    file_size: int
    uploaded_at: str


# --- Key management ---------------------------------------------------------

def load_or_create_master_key(
    key_file: Path = DEFAULT_KEY_FILE,
) -> bytes:
    """
    Resolve the 32-byte master secret for this prototype.

    Resolution order (first hit wins):
        1. SSE_MASTER_KEY env var (hex) -- loaded from .env if present.
        2. A local key file (data/master.key, hex) created on first run.

    SIMPLIFICATION: a single local master key for a single user. A production
    system would use a real KMS / HSM and per-user keys. The key file and .env
    are git-ignored so secrets never get committed.

    Returns:
        The 32-byte master secret.

    Raises:
        RepositoryError: if an env-provided key is malformed.
    """
    # 1. Environment variable (optionally from a .env file).
    load_dotenv(_PROJECT_ROOT / ".env")
    env_val = os.environ.get(_MASTER_KEY_ENV, "").strip()
    if env_val and env_val != "0" * (crypto.MASTER_KEY_BYTES * 2):
        try:
            key = bytes.fromhex(env_val)
        except ValueError as exc:
            raise RepositoryError(
                f"{_MASTER_KEY_ENV} is not valid hex."
            ) from exc
        if len(key) != crypto.MASTER_KEY_BYTES:
            raise RepositoryError(
                f"{_MASTER_KEY_ENV} must decode to {crypto.MASTER_KEY_BYTES} bytes."
            )
        return key

    # 2. Local key file.
    key_file = Path(key_file)
    if key_file.exists():
        text = key_file.read_text(encoding="utf-8").strip()
        try:
            key = bytes.fromhex(text)
        except ValueError as exc:
            raise RepositoryError(
                "Local master key file is corrupted. Delete data/master.key to "
                "regenerate (existing encrypted documents will become unreadable)."
            ) from exc
        if len(key) != crypto.MASTER_KEY_BYTES:
            raise RepositoryError("Local master key file has an invalid length.")
        return key

    # Generate a fresh key and persist it with restrictive permissions.
    key = crypto.generate_master_key()
    key_file.parent.mkdir(parents=True, exist_ok=True)
    key_file.write_text(key.hex(), encoding="utf-8")
    try:
        os.chmod(key_file, 0o600)
    except OSError:
        # Best effort on platforms that don't support chmod semantics.
        pass
    return key


class Repository:
    """
    Facade over the whole SSE pipeline.

    Typical usage:
        repo = Repository()
        repo.upload_document("notes.txt", raw_bytes)
        hits = repo.search("encryption")
        text = repo.decrypt_document(hits[0].document_id)
    """

    def __init__(
        self,
        db_path: Path = DEFAULT_DB_PATH,
        encrypted_dir: Path = DEFAULT_ENCRYPTED_DIR,
        key_file: Path = DEFAULT_KEY_FILE,
    ) -> None:
        self.encrypted_dir = Path(encrypted_dir)
        self.encrypted_dir.mkdir(parents=True, exist_ok=True)
        self.db = Database(db_path)
        master_key = load_or_create_master_key(key_file)
        self._keys: KeySet = crypto.derive_keys(master_key)

    # --- Upload ------------------------------------------------------------

    def upload_document(self, filename: str, raw_bytes: bytes) -> UploadResult:
        """
        Validate, encrypt, store, and index a document end-to-end.

        Steps: validate type/size -> check duplicate -> extract text ->
        AES-GCM encrypt -> write .enc file -> insert metadata ->
        build + store HMAC search tokens.

        Raises:
            UnsupportedFileError, FileTooLargeError: validation failures.
            DuplicateDocumentError: filename already in the repository.
            RepositoryError: for storage/crypto/database failures.
        """
        document_processor.validate_upload(filename, len(raw_bytes))

        if self.db.document_exists(filename):
            raise DuplicateDocumentError(
                f"A document named '{filename}' already exists in the repository."
            )

        # Extract plaintext (also enforces supported type).
        text = document_processor.extract_text(raw_bytes, filename)

        # Encrypt the ORIGINAL bytes (so decryption returns the exact file).
        try:
            blob = crypto.encrypt_document(raw_bytes, self._keys.encryption_key)
        except CryptoError as exc:
            raise RepositoryError(f"Encryption failed: {exc}") from exc

        # Write the encrypted blob under a random opaque filename.
        encrypted_filename = f"{uuid.uuid4().hex}.enc"
        encrypted_path = self.encrypted_dir / encrypted_filename
        try:
            encrypted_path.write_bytes(blob)
        except OSError as exc:
            raise RepositoryError(f"Could not write encrypted file: {exc}") from exc

        # Insert metadata. If this fails, clean up the orphaned file.
        try:
            document_id = self.db.add_document(
                original_filename=filename,
                encrypted_filename=encrypted_filename,
                file_size=len(raw_bytes),
                uploaded_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
                mime_type=_guess_mime(filename),
            )
        except DatabaseError as exc:
            encrypted_path.unlink(missing_ok=True)
            raise RepositoryError(f"Could not save document metadata: {exc}") from exc

        # Build and store the searchable index for this document.
        try:
            token_count = index.index_document(
                self.db, document_id, text, self._keys.search_key
            )
        except DatabaseError as exc:
            raise RepositoryError(f"Could not build search index: {exc}") from exc

        return UploadResult(
            document_id=document_id,
            original_filename=filename,
            encrypted_filename=encrypted_filename,
            file_size=len(raw_bytes),
            token_count=token_count,
        )

    # --- Search ------------------------------------------------------------

    def search(self, raw_query: str) -> List[SearchHit]:
        """
        Search the encrypted index and return matching documents.

        Raises:
            RepositoryError: for database failures.
        """
        try:
            ids = index.search(self.db, raw_query, self._keys.search_key)
            records = self.db.get_documents(ids)
        except DatabaseError as exc:
            raise RepositoryError(f"Search failed: {exc}") from exc
        return [
            SearchHit(
                document_id=r.id,
                original_filename=r.original_filename,
                file_size=r.file_size,
                uploaded_at=r.uploaded_at,
            )
            for r in records
        ]

    # --- Decrypt -----------------------------------------------------------

    def decrypt_document(self, document_id: int) -> str:
        """
        Load, decrypt and authenticate a document, returning its text.

        Raises:
            RepositoryError: if the document is missing, the file is gone, or
                             decryption/authentication fails (tamper/wrong key).
        """
        record = self.db.get_document(document_id)
        if record is None:
            raise RepositoryError("Document not found in the repository.")

        encrypted_path = self.encrypted_dir / record.encrypted_filename
        if not encrypted_path.exists():
            raise RepositoryError("Encrypted file is missing from storage.")

        try:
            blob = encrypted_path.read_bytes()
        except OSError as exc:
            raise RepositoryError(f"Could not read encrypted file: {exc}") from exc

        try:
            plaintext = crypto.decrypt_document(blob, self._keys.encryption_key)
        except CryptoError as exc:
            # Friendly message; do not leak a traceback to the UI.
            raise RepositoryError(
                "Unable to decrypt this document. The encrypted file may have "
                "been modified or the key may be invalid."
            ) from exc

        return plaintext.decode("utf-8", errors="replace")

    # --- Metadata / stats --------------------------------------------------

    def list_documents(self) -> List[DocumentRecord]:
        """Return all stored document metadata records."""
        return self.db.list_documents()

    def get_document(self, document_id: int) -> Optional[DocumentRecord]:
        """Return a single document's metadata, or None."""
        return self.db.get_document(document_id)

    def stats(self) -> dict:
        """
        Return dashboard statistics.

        Keys: document_count, keyword_count, repository_size_bytes,
              encryption, search_index.
        """
        doc_count = self.db.count_documents()
        token_count = self.db.count_unique_tokens()
        size = _dir_size(self.encrypted_dir)
        return {
            "document_count": doc_count,
            "keyword_count": token_count,
            "repository_size_bytes": size,
            "encryption": "AES-256-GCM",
            "search_index": "HMAC-SHA256",
        }

    def sample_tokens(self, limit: int = 5) -> List[str]:
        """Return a few stored HMAC tokens for the 'what the server sees' demo."""
        return self.db.sample_tokens(limit)

    def read_encrypted_preview(self, document_id: int, num_bytes: int = 64) -> bytes:
        """
        Return the first `num_bytes` of a document's encrypted file.

        Used by the UI to visually demonstrate that stored data is unreadable
        binary rather than plaintext.
        """
        record = self.db.get_document(document_id)
        if record is None:
            raise RepositoryError("Document not found.")
        path = self.encrypted_dir / record.encrypted_filename
        if not path.exists():
            raise RepositoryError("Encrypted file is missing from storage.")
        with path.open("rb") as fh:
            return fh.read(num_bytes)


# --- small helpers ----------------------------------------------------------

def _guess_mime(filename: str) -> str:
    ext = document_processor.get_extension(filename)
    return {".txt": "text/plain", ".md": "text/markdown"}.get(ext, "application/octet-stream")


def _dir_size(directory: Path) -> int:
    """Total size in bytes of all .enc files in a directory."""
    total = 0
    if directory.exists():
        for p in directory.glob("*.enc"):
            try:
                total += p.stat().st_size
            except OSError:
                pass
    return total


def format_size(num_bytes: int) -> str:
    """Human-readable size string (e.g. '2.1 KB')."""
    size = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            if unit == "B":
                return f"{int(size)} {unit}"
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} GB"
