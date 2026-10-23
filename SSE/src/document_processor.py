"""
document_processor.py
=====================

Turns a raw uploaded file into (a) plaintext text and (b) a clean set of
unique keywords that the index layer will convert into HMAC search tokens.

Supported formats (v1): .txt and .md
The extraction step is intentionally isolated so PDF / DOCX extraction can be
added later by extending `extract_text` without touching the rest of the app.

Normalization pipeline for keywords:
    lowercase  ->  strip punctuation  ->  split on whitespace
    ->  drop very short tokens  ->  drop stop words  ->  unique set
"""

from __future__ import annotations

import re
from typing import List, Set

# File formats we can currently extract text from.
SUPPORTED_EXTENSIONS = {".txt", ".md"}

# Maximum accepted upload size (bytes). 5 MB keeps the classroom demo snappy.
MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024

# Tokens shorter than this are ignored (removes single characters, noise).
MIN_TOKEN_LENGTH = 2

# A small, dependency-free English stop-word list. Removing these keeps the
# index focused on meaningful keywords for the demo.
STOP_WORDS: Set[str] = {
    "a", "an", "the", "and", "or", "but", "if", "then", "else", "of", "to",
    "in", "on", "at", "by", "for", "with", "as", "is", "are", "was", "were",
    "be", "been", "being", "it", "its", "this", "that", "these", "those",
    "from", "into", "can", "could", "will", "would", "should", "may", "might",
    "do", "does", "did", "has", "have", "had", "not", "no", "so", "such",
    "than", "too", "very", "up", "down", "out", "over", "under", "again",
    "we", "you", "they", "he", "she", "i", "them", "us", "our", "your",
    "use", "used", "using", "uses",
}


class UnsupportedFileError(Exception):
    """Raised when the uploaded file type is not supported."""


class FileTooLargeError(Exception):
    """Raised when the uploaded file exceeds MAX_FILE_SIZE_BYTES."""


def get_extension(filename: str) -> str:
    """Return the lowercase file extension including the dot (e.g. '.txt')."""
    match = re.search(r"(\.[A-Za-z0-9]+)$", filename.strip())
    return match.group(1).lower() if match else ""


def is_supported(filename: str) -> bool:
    """Return True if the filename has a supported extension."""
    return get_extension(filename) in SUPPORTED_EXTENSIONS


def validate_upload(filename: str, size_bytes: int) -> None:
    """
    Validate an upload's type and size before any processing.

    Raises:
        UnsupportedFileError: if the extension is not .txt or .md.
        FileTooLargeError:    if the file is larger than MAX_FILE_SIZE_BYTES.
    """
    if not is_supported(filename):
        raise UnsupportedFileError(
            "Currently supported formats: TXT and Markdown."
        )
    if size_bytes > MAX_FILE_SIZE_BYTES:
        raise FileTooLargeError(
            f"File is too large. Maximum size is "
            f"{MAX_FILE_SIZE_BYTES // (1024 * 1024)} MB."
        )


def extract_text(raw_bytes: bytes, filename: str) -> str:
    """
    Extract plaintext from raw file bytes based on its extension.

    For .txt and .md we decode as UTF-8 (replacing undecodable bytes so a
    stray byte never crashes the demo). This is the single extension point
    for future formats like PDF.

    Args:
        raw_bytes: the uploaded file's bytes.
        filename:  original filename (used to pick the extractor).

    Returns:
        The document text as a string.

    Raises:
        UnsupportedFileError: if the extension is not supported.
    """
    ext = get_extension(filename)
    if ext not in SUPPORTED_EXTENSIONS:
        raise UnsupportedFileError("Currently supported formats: TXT and Markdown.")
    # .txt and .md are both plain text.
    return raw_bytes.decode("utf-8", errors="replace")


def normalize_text(text: str) -> List[str]:
    """
    Normalize text into an ordered list of candidate keyword tokens.

    Steps: lowercase, replace any non-alphanumeric character with a space,
    split on whitespace. Ordering is preserved (useful for future phrase
    features); de-duplication happens in extract_keywords.
    """
    lowered = text.lower()
    # Keep letters and digits; everything else becomes a separator.
    cleaned = re.sub(r"[^a-z0-9]+", " ", lowered)
    return [tok for tok in cleaned.split() if tok]


def extract_keywords(text: str) -> List[str]:
    """
    Produce the unique, filtered keyword set for a document.

    Applies length filtering and stop-word removal, then returns unique tokens
    in first-seen order (deterministic, nice for display/debugging).

    Example:
        "Cryptography protects information using AES encryption."
        -> ["cryptography", "protects", "information", "using", "aes", "encryption"]
    """
    seen: Set[str] = set()
    keywords: List[str] = []
    for token in normalize_text(text):
        if len(token) < MIN_TOKEN_LENGTH:
            continue
        if token in STOP_WORDS:
            continue
        if token in seen:
            continue
        seen.add(token)
        keywords.append(token)
    return keywords


def normalize_query_term(term: str) -> str:
    """
    Normalize a single user-entered search term the same way keywords are
    normalized, so a query matches the stored tokens.

    Returns the first normalized token, or an empty string if nothing usable
    remains (e.g. the user typed only punctuation).
    """
    tokens = normalize_text(term)
    return tokens[0] if tokens else ""
