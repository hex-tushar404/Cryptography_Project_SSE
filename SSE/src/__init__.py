"""
Searchable Symmetric Encryption (SSE) document repository.

Educational mini-project. Package modules:

    crypto              key derivation, AES-256-GCM, HMAC-SHA256 tokens
    document_processor  text extraction + keyword normalization
    database            SQLite schema and parameterized queries
    index               searchable index build + query
    repository          high-level orchestration of upload/search/decrypt
"""

__all__ = [
    "crypto",
    "document_processor",
    "database",
    "index",
    "repository",
]
