"""
End-to-end tests for src/repository.py.

Each test uses an isolated temp directory (its own db, encrypted dir and key
file) so the real data/ repository is never touched.
"""

import pytest

from src.document_processor import FileTooLargeError, UnsupportedFileError
from src.repository import (
    DuplicateDocumentError,
    Repository,
    RepositoryError,
)


@pytest.fixture()
def repo(tmp_path):
    return Repository(
        db_path=tmp_path / "repo.db",
        encrypted_dir=tmp_path / "enc",
        key_file=tmp_path / "master.key",
    )


def test_full_upload_search_decrypt_flow(repo):
    text = b"Cryptography protects data. AES is a symmetric encryption algorithm."
    result = repo.upload_document("cryptography.txt", text)
    assert result.token_count > 0

    hits = repo.search("encryption")
    assert len(hits) == 1
    assert hits[0].original_filename == "cryptography.txt"

    recovered = repo.decrypt_document(hits[0].document_id)
    assert recovered == text.decode("utf-8")


def test_search_across_multiple_documents(repo):
    repo.upload_document("cryptography.txt", b"cryptography uses encryption and aes")
    repo.upload_document("cloud.txt", b"cloud security uses encryption too")
    repo.upload_document("network.txt", b"network firewalls and monitoring")

    hits = repo.search("encryption")
    names = sorted(h.original_filename for h in hits)
    assert names == ["cloud.txt", "cryptography.txt"]

    # AND semantics.
    hits_and = repo.search("cryptography aes")
    assert [h.original_filename for h in hits_and] == ["cryptography.txt"]


def test_encrypted_file_has_no_plaintext(repo, tmp_path):
    secret_line = b"TOPSECRETphrase supersecretmarker"
    result = repo.upload_document("secret.txt", secret_line)
    enc_path = (tmp_path / "enc") / result.encrypted_filename
    blob = enc_path.read_bytes()
    assert b"supersecretmarker" not in blob
    assert b"TOPSECRETphrase" not in blob


def test_duplicate_upload_rejected(repo):
    repo.upload_document("a.txt", b"hello world encryption")
    with pytest.raises(DuplicateDocumentError):
        repo.upload_document("a.txt", b"hello world encryption")


def test_unsupported_file_rejected(repo):
    with pytest.raises(UnsupportedFileError):
        repo.upload_document("image.png", b"not text")


def test_too_large_file_rejected(repo):
    from src.document_processor import MAX_FILE_SIZE_BYTES

    big = b"x" * (MAX_FILE_SIZE_BYTES + 1)
    with pytest.raises(FileTooLargeError):
        repo.upload_document("big.txt", big)


def test_decrypt_tampered_file_fails_gracefully(repo, tmp_path):
    result = repo.upload_document("doc.txt", b"important encryption content")
    enc_path = (tmp_path / "enc") / result.encrypted_filename
    data = bytearray(enc_path.read_bytes())
    data[-1] ^= 0x01  # tamper with the authentication tag
    enc_path.write_bytes(bytes(data))

    with pytest.raises(RepositoryError):
        repo.decrypt_document(result.document_id)


def test_wrong_key_cannot_decrypt(tmp_path):
    # Repo A encrypts with its own generated key.
    repo_a = Repository(
        db_path=tmp_path / "a.db",
        encrypted_dir=tmp_path / "enc_a",
        key_file=tmp_path / "a.key",
    )
    result = repo_a.upload_document("doc.txt", b"confidential encryption data")

    # Repo B has a DIFFERENT key but we point it at A's encrypted file + metadata
    # by copying the blob into B's dir under a record B knows about.
    repo_b = Repository(
        db_path=tmp_path / "b.db",
        encrypted_dir=tmp_path / "enc_b",
        key_file=tmp_path / "b.key",
    )
    # Recreate a metadata row in B pointing at a copied blob.
    blob = ((tmp_path / "enc_a") / result.encrypted_filename).read_bytes()
    enc_name = result.encrypted_filename
    (tmp_path / "enc_b" / enc_name).write_bytes(blob)
    doc_id = repo_b.db.add_document("doc.txt", enc_name, len(blob), "t", "text/plain")

    with pytest.raises(RepositoryError):
        repo_b.decrypt_document(doc_id)


def test_stats_and_token_privacy(repo):
    repo.upload_document("doc.txt", b"cryptography encryption secure")
    stats = repo.stats()
    assert stats["document_count"] == 1
    assert stats["keyword_count"] >= 1
    assert stats["encryption"] == "AES-256-GCM"
    assert stats["search_index"] == "HMAC-SHA256"
    # Sample tokens are hex, not raw keywords.
    for token in repo.sample_tokens(10):
        assert len(token) == 64
        assert token not in {"cryptography", "encryption", "secure"}


def test_empty_search_returns_no_hits(repo):
    repo.upload_document("doc.txt", b"cryptography encryption")
    assert repo.search("   ") == []
