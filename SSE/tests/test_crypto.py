"""Tests for src/crypto.py: key derivation, AES-GCM round trip, tamper, tokens."""

import os

import pytest

from src import crypto
from src.crypto import CryptoError


def _keys() -> crypto.KeySet:
    return crypto.derive_keys(crypto.generate_master_key())


def test_master_key_is_32_bytes():
    key = crypto.generate_master_key()
    assert isinstance(key, bytes)
    assert len(key) == crypto.MASTER_KEY_BYTES == 32


def test_derive_keys_are_distinct_and_deterministic():
    master = crypto.generate_master_key()
    ks1 = crypto.derive_keys(master)
    ks2 = crypto.derive_keys(master)
    # Deterministic: same master -> same derived keys.
    assert ks1.encryption_key == ks2.encryption_key
    assert ks1.search_key == ks2.search_key
    # The AES key and HMAC key must NOT be identical.
    assert ks1.encryption_key != ks1.search_key
    assert len(ks1.encryption_key) == 32
    assert len(ks1.search_key) == 32


def test_derive_keys_rejects_bad_master():
    with pytest.raises(CryptoError):
        crypto.derive_keys(b"too-short")


def test_encrypt_decrypt_round_trip():
    ks = _keys()
    plaintext = b"Cryptography is the practice of secure communication."
    blob = crypto.encrypt_document(plaintext, ks.encryption_key)
    # Encrypted blob should not contain the plaintext.
    assert plaintext not in blob
    recovered = crypto.decrypt_document(blob, ks.encryption_key)
    assert recovered == plaintext


def test_nonce_is_random_per_encryption():
    ks = _keys()
    data = b"same input"
    blob1 = crypto.encrypt_document(data, ks.encryption_key)
    blob2 = crypto.encrypt_document(data, ks.encryption_key)
    # Different nonce => different ciphertext for identical plaintext.
    assert blob1 != blob2
    assert blob1[: crypto.NONCE_BYTES] != blob2[: crypto.NONCE_BYTES]


def test_tampered_ciphertext_fails_authentication():
    ks = _keys()
    blob = bytearray(crypto.encrypt_document(b"important data", ks.encryption_key))
    # Flip a bit somewhere in the ciphertext/tag region.
    blob[-1] ^= 0x01
    with pytest.raises(CryptoError):
        crypto.decrypt_document(bytes(blob), ks.encryption_key)


def test_wrong_key_fails_decryption():
    ks = _keys()
    other = _keys()
    blob = crypto.encrypt_document(b"secret", ks.encryption_key)
    with pytest.raises(CryptoError):
        crypto.decrypt_document(blob, other.encryption_key)


def test_malformed_blob_raises():
    ks = _keys()
    with pytest.raises(CryptoError):
        crypto.decrypt_document(b"short", ks.encryption_key)


def test_same_keyword_same_token():
    ks = _keys()
    t1 = crypto.search_token("cryptography", ks.search_key)
    t2 = crypto.search_token("cryptography", ks.search_key)
    assert t1 == t2
    assert len(t1) == 64  # SHA-256 hex


def test_different_keyword_different_token():
    ks = _keys()
    t1 = crypto.search_token("cryptography", ks.search_key)
    t2 = crypto.search_token("encryption", ks.search_key)
    assert t1 != t2


def test_token_depends_on_key():
    master_a = os.urandom(32)
    master_b = os.urandom(32)
    ka = crypto.derive_keys(master_a)
    kb = crypto.derive_keys(master_b)
    assert crypto.search_token("aes", ka.search_key) != crypto.search_token("aes", kb.search_key)
