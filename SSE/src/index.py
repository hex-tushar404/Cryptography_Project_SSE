"""
index.py
========

The searchable-index logic: the bridge between plaintext keywords (which never
leave the client) and the opaque HMAC tokens stored in SQLite.

Build side (upload):
    keywords -> [HMAC-SHA256(search_key, kw) for kw in keywords] -> store tokens

Query side (search):
    user query -> normalize each term -> HMAC token per term
               -> look up document ids -> combine (AND / OR)

v1 default is single-term exact search. Multi-term AND/OR is implemented here
in a small, self-contained way so the UI can offer it without extra complexity.
"""

from __future__ import annotations

from typing import List

from . import crypto, document_processor
from .database import Database


def build_tokens(keywords: List[str], search_key: bytes) -> List[str]:
    """
    Convert a list of normalized keywords into HMAC search tokens.

    Args:
        keywords:   normalized keyword strings (from extract_keywords).
        search_key: 32-byte HMAC key.

    Returns:
        A list of hex token strings (one per keyword, de-duplicated).
    """
    tokens: List[str] = []
    seen = set()
    for kw in keywords:
        token = crypto.search_token(kw, search_key)
        if token not in seen:
            seen.add(token)
            tokens.append(token)
    return tokens


def index_document(
    db: Database,
    document_id: int,
    text: str,
    search_key: bytes,
) -> int:
    """
    Extract keywords from a document's text and store their HMAC tokens.

    Args:
        db:          the Database instance.
        document_id: id of the already-inserted document row.
        text:        plaintext extracted from the document.
        search_key:  32-byte HMAC key.

    Returns:
        The number of unique search tokens stored for this document.
    """
    keywords = document_processor.extract_keywords(text)
    tokens = build_tokens(keywords, search_key)
    db.add_search_tokens(document_id, tokens)
    return len(tokens)


def parse_query(raw_query: str) -> tuple[list[str], str]:
    """
    Parse a raw search box string into (terms, mode).

    Supported forms:
        "encryption"              -> (["encryption"], "AND")
        "cryptography AES"        -> (["cryptography", "aes"], "AND")
        "cryptography AND aes"    -> (["cryptography", "aes"], "AND")
        "cloud OR network"        -> (["cloud", "network"], "OR")

    The explicit AND/OR keywords (case-insensitive) set the combine mode;
    multiple bare terms default to AND. Terms are normalized the same way
    keywords were at index time.
    """
    tokens = raw_query.split()
    mode = "AND"
    terms: list[str] = []
    for tok in tokens:
        upper = tok.upper()
        if upper == "AND":
            mode = "AND"
            continue
        if upper == "OR":
            mode = "OR"
            continue
        normalized = document_processor.normalize_query_term(tok)
        if normalized:
            terms.append(normalized)
    # De-duplicate while preserving order.
    seen = set()
    unique_terms = [t for t in terms if not (t in seen or seen.add(t))]
    return unique_terms, mode


def search(
    db: Database,
    raw_query: str,
    search_key: bytes,
) -> List[int]:
    """
    Execute a search and return matching document ids.

    Each normalized term is converted to its HMAC token, looked up in the
    index, and the per-term id sets are combined with AND or OR semantics.

    Args:
        db:         the Database instance.
        raw_query:  the user's raw search string.
        search_key: 32-byte HMAC key.

    Returns:
        A list of matching document ids (ascending). Empty if no match or the
        query contained no usable terms.
    """
    terms, mode = parse_query(raw_query)
    if not terms:
        return []

    result_sets: List[set[int]] = []
    for term in terms:
        token = crypto.search_token(term, search_key)
        ids = set(db.find_documents_by_token(token))
        result_sets.append(ids)

    if mode == "OR":
        combined: set[int] = set().union(*result_sets)
    else:  # AND
        combined = result_sets[0]
        for s in result_sets[1:]:
            combined &= s

    return sorted(combined)
