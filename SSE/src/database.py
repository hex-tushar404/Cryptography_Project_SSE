"""
database.py
===========

Thin SQLite wrapper. All SQL lives here; every query is parameterized so raw
user input can never be concatenated into a statement.

Tables
------
documents        one row per stored (encrypted) document + its metadata
search_index     many rows per document: (search_token -> document_id)

The database stores NO plaintext document content and NO plaintext keywords.
Only metadata and opaque HMAC search tokens are persisted.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional


@dataclass(frozen=True)
class DocumentRecord:
    """A row from the `documents` table."""

    id: int
    original_filename: str
    encrypted_filename: str
    file_size: int
    uploaded_at: str
    mime_type: str


class DatabaseError(Exception):
    """Raised for database-level failures surfaced to the app layer."""


class Database:
    """
    Manages the SQLite connection and schema.

    A new short-lived connection is opened per operation via a context helper,
    which keeps things simple and thread-friendly for Streamlit.
    """

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        """Open a connection with foreign keys and row access by name."""
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        return conn

    def _init_schema(self) -> None:
        """Create tables and indexes if they do not already exist."""
        try:
            with self._connect() as conn:
                conn.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS documents (
                        id                 INTEGER PRIMARY KEY AUTOINCREMENT,
                        original_filename  TEXT    NOT NULL,
                        encrypted_filename TEXT    NOT NULL UNIQUE,
                        file_size          INTEGER NOT NULL,
                        uploaded_at        TEXT    NOT NULL,
                        mime_type          TEXT    NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS search_index (
                        search_token TEXT    NOT NULL,
                        document_id  INTEGER NOT NULL,
                        PRIMARY KEY (search_token, document_id),
                        FOREIGN KEY (document_id)
                            REFERENCES documents(id) ON DELETE CASCADE
                    );

                    CREATE INDEX IF NOT EXISTS idx_search_token
                        ON search_index(search_token);

                    CREATE INDEX IF NOT EXISTS idx_documents_filename
                        ON documents(original_filename);
                    """
                )
        except sqlite3.Error as exc:
            raise DatabaseError(f"Failed to initialize database: {exc}") from exc

    # --- documents table ---------------------------------------------------

    def add_document(
        self,
        original_filename: str,
        encrypted_filename: str,
        file_size: int,
        uploaded_at: str,
        mime_type: str,
    ) -> int:
        """Insert a document row and return its new id."""
        try:
            with self._connect() as conn:
                cur = conn.execute(
                    """
                    INSERT INTO documents
                        (original_filename, encrypted_filename, file_size,
                         uploaded_at, mime_type)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (original_filename, encrypted_filename, file_size,
                     uploaded_at, mime_type),
                )
                return int(cur.lastrowid)
        except sqlite3.Error as exc:
            raise DatabaseError(f"Failed to add document: {exc}") from exc

    def document_exists(self, original_filename: str) -> bool:
        """Return True if a document with this original filename exists."""
        try:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT 1 FROM documents WHERE original_filename = ? LIMIT 1",
                    (original_filename,),
                ).fetchone()
                return row is not None
        except sqlite3.Error as exc:
            raise DatabaseError(f"Failed to check document: {exc}") from exc

    def get_document(self, document_id: int) -> Optional[DocumentRecord]:
        """Fetch a single document by id, or None if not found."""
        try:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT * FROM documents WHERE id = ?",
                    (document_id,),
                ).fetchone()
                return self._row_to_record(row) if row else None
        except sqlite3.Error as exc:
            raise DatabaseError(f"Failed to fetch document: {exc}") from exc

    def get_documents(self, document_ids: List[int]) -> List[DocumentRecord]:
        """Fetch multiple documents by id (order follows the id list)."""
        if not document_ids:
            return []
        placeholders = ",".join("?" for _ in document_ids)
        try:
            with self._connect() as conn:
                rows = conn.execute(
                    f"SELECT * FROM documents WHERE id IN ({placeholders})",
                    tuple(document_ids),
                ).fetchall()
        except sqlite3.Error as exc:
            raise DatabaseError(f"Failed to fetch documents: {exc}") from exc
        by_id = {row["id"]: self._row_to_record(row) for row in rows}
        return [by_id[i] for i in document_ids if i in by_id]

    def list_documents(self) -> List[DocumentRecord]:
        """Return all documents ordered by newest upload first."""
        try:
            with self._connect() as conn:
                rows = conn.execute(
                    "SELECT * FROM documents ORDER BY id DESC"
                ).fetchall()
                return [self._row_to_record(r) for r in rows]
        except sqlite3.Error as exc:
            raise DatabaseError(f"Failed to list documents: {exc}") from exc

    def count_documents(self) -> int:
        """Return the number of stored documents."""
        try:
            with self._connect() as conn:
                row = conn.execute("SELECT COUNT(*) AS n FROM documents").fetchone()
                return int(row["n"])
        except sqlite3.Error as exc:
            raise DatabaseError(f"Failed to count documents: {exc}") from exc

    # --- search_index table ------------------------------------------------

    def add_search_tokens(self, document_id: int, tokens: List[str]) -> None:
        """
        Insert (search_token -> document_id) rows for a document.

        Uses INSERT OR IGNORE so duplicate (token, doc) pairs are harmless.
        """
        if not tokens:
            return
        try:
            with self._connect() as conn:
                conn.executemany(
                    """
                    INSERT OR IGNORE INTO search_index (search_token, document_id)
                    VALUES (?, ?)
                    """,
                    [(token, document_id) for token in tokens],
                )
        except sqlite3.Error as exc:
            raise DatabaseError(f"Failed to add search tokens: {exc}") from exc

    def find_documents_by_token(self, token: str) -> List[int]:
        """Return document ids whose index contains the given search token."""
        try:
            with self._connect() as conn:
                rows = conn.execute(
                    "SELECT document_id FROM search_index WHERE search_token = ?",
                    (token,),
                ).fetchall()
                return [int(r["document_id"]) for r in rows]
        except sqlite3.Error as exc:
            raise DatabaseError(f"Failed to search index: {exc}") from exc

    def count_unique_tokens(self) -> int:
        """Return the number of distinct search tokens in the index."""
        try:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT COUNT(DISTINCT search_token) AS n FROM search_index"
                ).fetchone()
                return int(row["n"])
        except sqlite3.Error as exc:
            raise DatabaseError(f"Failed to count tokens: {exc}") from exc

    def sample_tokens(self, limit: int = 5) -> List[str]:
        """Return a few search tokens (for the 'what the server sees' demo)."""
        try:
            with self._connect() as conn:
                rows = conn.execute(
                    "SELECT DISTINCT search_token FROM search_index LIMIT ?",
                    (limit,),
                ).fetchall()
                return [r["search_token"] for r in rows]
        except sqlite3.Error as exc:
            raise DatabaseError(f"Failed to sample tokens: {exc}") from exc

    # --- helpers -----------------------------------------------------------

    @staticmethod
    def _row_to_record(row: sqlite3.Row) -> DocumentRecord:
        return DocumentRecord(
            id=int(row["id"]),
            original_filename=row["original_filename"],
            encrypted_filename=row["encrypted_filename"],
            file_size=int(row["file_size"]),
            uploaded_at=row["uploaded_at"],
            mime_type=row["mime_type"],
        )
