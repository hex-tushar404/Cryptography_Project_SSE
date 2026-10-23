"""Tests for src/document_processor.py and src/index.py."""

import pytest

from src import crypto, document_processor, index
from src.database import Database


# --- document_processor -----------------------------------------------------

def test_extract_keywords_normalizes_and_filters():
    text = "Cryptography protects information using AES encryption."
    kws = document_processor.extract_keywords(text)
    assert "cryptography" in kws
    assert "aes" in kws
    assert "encryption" in kws
    # Lowercased.
    assert all(k == k.lower() for k in kws)
    # Stop word 'using' removed.
    assert "using" not in kws
    # Unique.
    assert len(kws) == len(set(kws))


def test_extract_keywords_drops_short_and_stopwords():
    text = "a an the I of to AES"
    kws = document_processor.extract_keywords(text)
    # Only 'aes' survives length + stop-word filtering.
    assert kws == ["aes"]


def test_extract_text_rejects_unsupported():
    with pytest.raises(document_processor.UnsupportedFileError):
        document_processor.extract_text(b"data", "image.png")


def test_validate_upload_size_limit():
    big = document_processor.MAX_FILE_SIZE_BYTES + 1
    with pytest.raises(document_processor.FileTooLargeError):
        document_processor.validate_upload("notes.txt", big)


def test_normalize_query_term():
    assert document_processor.normalize_query_term("  Encryption! ") == "encryption"
    assert document_processor.normalize_query_term("!!!") == ""


# --- index (with a temp DB) -------------------------------------------------

@pytest.fixture()
def db(tmp_path):
    return Database(tmp_path / "test.db")


@pytest.fixture()
def search_key():
    return crypto.derive_keys(crypto.generate_master_key()).search_key


def test_parse_query_modes():
    assert index.parse_query("encryption") == (["encryption"], "AND")
    assert index.parse_query("cryptography AES") == (["cryptography", "aes"], "AND")
    assert index.parse_query("cryptography AND aes") == (["cryptography", "aes"], "AND")
    assert index.parse_query("cloud OR network") == (["cloud", "network"], "OR")


def test_index_and_single_term_search(db, search_key):
    # Two documents with overlapping keyword "encryption".
    db.add_document("doc1.txt", "a.enc", 10, "t", "text/plain")
    db.add_document("doc2.txt", "b.enc", 10, "t", "text/plain")
    index.index_document(db, 1, "cryptography and encryption", search_key)
    index.index_document(db, 2, "cloud encryption basics", search_key)

    assert index.search(db, "encryption", search_key) == [1, 2]
    assert index.search(db, "cryptography", search_key) == [1]
    assert index.search(db, "cloud", search_key) == [2]
    assert index.search(db, "nonexistent", search_key) == []


def test_and_or_multi_term_search(db, search_key):
    db.add_document("doc1.txt", "a.enc", 10, "t", "text/plain")
    db.add_document("doc2.txt", "b.enc", 10, "t", "text/plain")
    index.index_document(db, 1, "cryptography aes symmetric", search_key)
    index.index_document(db, 2, "cryptography cloud storage", search_key)

    # AND: only doc1 has both cryptography and aes.
    assert index.search(db, "cryptography aes", search_key) == [1]
    # OR: both documents have cryptography.
    assert index.search(db, "aes OR cloud", search_key) == [1, 2]


def test_empty_query_returns_nothing(db, search_key):
    assert index.search(db, "   ", search_key) == []
    assert index.search(db, "!!!", search_key) == []


def test_index_does_not_store_plaintext_keyword(db, search_key):
    db.add_document("doc1.txt", "a.enc", 10, "t", "text/plain")
    index.index_document(db, 1, "cryptography encryption", search_key)
    tokens = db.sample_tokens(100)
    # Stored tokens are 64-char hex, never the raw words.
    assert "cryptography" not in tokens
    assert "encryption" not in tokens
    assert all(len(t) == 64 for t in tokens)
