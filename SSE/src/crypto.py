"""
crypto.py
=========

All cryptographic operations for the SSE prototype live here and ONLY here.

Design (kept deliberately small and auditable):

    Master Secret (32 random bytes)
         |
         +-- HKDF(info="document-encryption") --> encryption_key (32 bytes, AES-256)
         |
         +-- HKDF(info="search-index")        --> search_key     (32 bytes, HMAC)

Document encryption:  AES-256-GCM (authenticated encryption)
    encrypted blob layout =  nonce(12 bytes) || ciphertext || tag(16 bytes)
    (the `cryptography` AESGCM API appends the 16-byte tag to the ciphertext)

Search tokens:        HMAC-SHA256(search_key, normalized_keyword)
    deterministic, so the same keyword + same key always yields the same token.

We never implement AES or HMAC by hand -- we use the `cryptography` library.
We never hard-code keys in source. Keys come from a master secret supplied by
the caller (loaded from an env var / local key file by the repository layer).
"""

from __future__ import annotations

import hmac
import os
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# --- Constants --------------------------------------------------------------

MASTER_KEY_BYTES = 32          # 256-bit master secret
DERIVED_KEY_BYTES = 32         # 256-bit derived keys (AES-256 / HMAC)
NONCE_BYTES = 12               # 96-bit nonce recommended for AES-GCM
GCM_TAG_BYTES = 16             # 128-bit authentication tag

# HKDF "info" labels keep the two derived keys cryptographically separated.
_INFO_ENCRYPTION = b"document-encryption"
_INFO_SEARCH = b"search-index"


class CryptoError(Exception):
    """Raised for any recoverable cryptographic failure (e.g. bad ciphertext)."""


@dataclass(frozen=True)
class KeySet:
    """
    Holds the two derived keys for a session.

    Attributes:
        encryption_key: 32-byte key used for AES-256-GCM document encryption.
        search_key:     32-byte key used for HMAC-SHA256 search tokens.
    """

    encryption_key: bytes
    search_key: bytes


# --- Master key handling ----------------------------------------------------

def generate_master_key() -> bytes:
    """Return a fresh cryptographically-secure 32-byte master secret."""
    return os.urandom(MASTER_KEY_BYTES)


def _hkdf(master_key: bytes, info: bytes) -> bytes:
    """Derive a 32-byte key from the master secret using HKDF-SHA256."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=DERIVED_KEY_BYTES,
        salt=None,        # salt omitted for determinism in this single-user prototype
        info=info,
    )
    return hkdf.derive(master_key)


def derive_keys(master_key: bytes) -> KeySet:
    """
    Derive the encryption key and search key from a master secret.

    Using distinct HKDF ``info`` labels guarantees the AES key and the HMAC key
    are independent -- we never reuse the same bytes for both purposes.

    Args:
        master_key: 32-byte master secret.

    Returns:
        A KeySet containing the derived encryption and search keys.

    Raises:
        CryptoError: if the master key is not exactly 32 bytes.
    """
    if not isinstance(master_key, (bytes, bytearray)) or len(master_key) != MASTER_KEY_BYTES:
        raise CryptoError(
            f"Master key must be {MASTER_KEY_BYTES} bytes, got "
            f"{len(master_key) if isinstance(master_key, (bytes, bytearray)) else 'non-bytes'}."
        )
    return KeySet(
        encryption_key=_hkdf(bytes(master_key), _INFO_ENCRYPTION),
        search_key=_hkdf(bytes(master_key), _INFO_SEARCH),
    )


# --- Document encryption (AES-256-GCM) --------------------------------------

def encrypt_document(plaintext: bytes, encryption_key: bytes) -> bytes:
    """
    Encrypt a document with AES-256-GCM.

    A fresh random 12-byte nonce is generated for every call (never reused).
    The returned blob is  nonce || ciphertext || tag  and is self-contained:
    decryption needs only this blob plus the key.

    Args:
        plaintext:      raw document bytes to protect.
        encryption_key: 32-byte AES-256 key (from derive_keys).

    Returns:
        Encrypted blob: nonce(12) + ciphertext + tag(16).

    Raises:
        CryptoError: if the key length is wrong.
    """
    if len(encryption_key) != DERIVED_KEY_BYTES:
        raise CryptoError("Encryption key must be 32 bytes (AES-256).")

    nonce = os.urandom(NONCE_BYTES)
    aesgcm = AESGCM(encryption_key)
    # AESGCM.encrypt appends the 16-byte tag to the ciphertext automatically.
    ciphertext_and_tag = aesgcm.encrypt(nonce, plaintext, associated_data=None)
    return nonce + ciphertext_and_tag


def decrypt_document(encrypted_blob: bytes, encryption_key: bytes) -> bytes:
    """
    Decrypt and authenticate an AES-256-GCM blob produced by encrypt_document.

    The GCM authentication tag is verified automatically. If the ciphertext was
    tampered with, or the wrong key is used, a CryptoError is raised instead of
    returning corrupt data.

    Args:
        encrypted_blob: nonce(12) + ciphertext + tag(16).
        encryption_key: 32-byte AES-256 key.

    Returns:
        The original plaintext bytes.

    Raises:
        CryptoError: if the key is wrong size, the blob is malformed, or
                     authentication fails (tampering / wrong key).
    """
    if len(encryption_key) != DERIVED_KEY_BYTES:
        raise CryptoError("Encryption key must be 32 bytes (AES-256).")
    if len(encrypted_blob) < NONCE_BYTES + GCM_TAG_BYTES:
        raise CryptoError("Encrypted data is too short or malformed.")

    nonce = encrypted_blob[:NONCE_BYTES]
    ciphertext_and_tag = encrypted_blob[NONCE_BYTES:]
    aesgcm = AESGCM(encryption_key)
    try:
        return aesgcm.decrypt(nonce, ciphertext_and_tag, associated_data=None)
    except InvalidTag as exc:
        # Raised when the tag does not match: tampering or wrong key.
        raise CryptoError(
            "Authentication failed: the encrypted file may have been modified "
            "or the key is invalid."
        ) from exc


# --- Search tokens (HMAC-SHA256) --------------------------------------------

def search_token(keyword: str, search_key: bytes) -> str:
    """
    Compute a deterministic search token for a normalized keyword.

    token = HMAC-SHA256(search_key, keyword) rendered as lowercase hex.

    Determinism is the whole point: the same keyword under the same key always
    produces the same token, which is what lets us look it up in the index
    without ever storing the plaintext keyword.

    Args:
        keyword:    a normalized (lowercased, trimmed) keyword string.
        search_key: 32-byte HMAC key (from derive_keys).

    Returns:
        64-character hex string.

    Raises:
        CryptoError: if the search key length is wrong.
    """
    if len(search_key) != DERIVED_KEY_BYTES:
        raise CryptoError("Search key must be 32 bytes.")
    mac = hmac.new(search_key, keyword.encode("utf-8"), digestmod="sha256")
    return mac.hexdigest()
