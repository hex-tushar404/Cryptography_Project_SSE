# 🔐 Secure Searchable Document Repository

**Searchable Symmetric Encryption (SSE) for Encrypted Document Repositories**

Search encrypted documents without decrypting the entire repository.

> ⚠️ **Disclaimer:** This is an educational SSE prototype, not a production-grade
> searchable encryption system. Advanced SSE constructions provide stronger
> leakage protection and access-control mechanisms.

---

## 1. Project Objective

Demonstrate how documents can be:

1. Encrypted before storage (so plaintext is never written to disk),
2. Searched by keyword using secure tokens (without decrypting everything),
3. Decrypted and viewed only when an authorized user requests it.

## 2. Problem Statement

Normal encryption protects confidentiality but destroys searchability. If a
repository only stores ciphertext, how do you find the document that mentions
*"encryption"* without downloading and decrypting every file? Searchable
Symmetric Encryption (SSE) solves exactly this.

## 3. Proposed Solution

- Encrypt each document with **AES-256-GCM** (authenticated encryption).
- For each keyword, compute a deterministic **HMAC-SHA256 token** and store only
  the token in a SQLite search index.
- At search time, convert the query term to the same token and look it up. The
  repository matches documents **without ever seeing the plaintext keyword**.

## 4. Features

- Upload `.txt` / `.md` documents (5 MB max).
- Real AES-256-GCM encryption with a fresh random nonce per document.
- HMAC-SHA256 search tokens; the index never stores plaintext keywords.
- Single-term exact search plus optional multi-keyword `AND` / `OR`.
- Decrypt & view with authentication-tag verification (tamper detection).
- Dashboard, Repository browser, and an educational **About SSE** page.
- Friendly error handling (no raw tracebacks shown to users).

## 5. Architecture

```text
                    USER (Streamlit UI — app.py)
                             |
             +---------------+----------------+
             |               |                |
         Upload           Search           Decrypt
             |               |                |
             v               v                v
   document_processor      index.py        crypto.py
   (extract + keywords)  (tokens+query)  (AES-GCM dec)
             |               |                |
             v               v                v
          crypto.py       database.py     repository.py
        (AES-GCM enc)   (SQLite tokens)   (orchestration)
             |               |
             v               v
   data/encrypted_documents/   data/repository.db
        (*.enc blobs)          (metadata + HMAC tokens)
```

Module responsibilities:

| Module | Responsibility |
|--------|----------------|
| `src/crypto.py` | Key derivation (HKDF), AES-256-GCM, HMAC-SHA256 tokens |
| `src/document_processor.py` | Validation, text extraction, keyword normalization |
| `src/index.py` | Build search tokens, parse queries, AND/OR search |
| `src/database.py` | SQLite schema + parameterized queries |
| `src/repository.py` | Key management + end-to-end orchestration |
| `app.py` | Streamlit UI (presentation + error handling only) |

## 6. Technology Stack

- Python 3.11+
- Streamlit (web UI)
- SQLite (metadata + search index, via the standard library `sqlite3`)
- `cryptography` (AES-256-GCM, HKDF)
- `hmac` / `hashlib` from the standard library (HMAC-SHA256)
- `python-dotenv` (optional `.env` key loading)

## 7. Cryptographic Design

```text
Master Secret (32 random bytes)
     |
     +-- HKDF(info="document-encryption") --> encryption_key (AES-256)
     |
     +-- HKDF(info="search-index")        --> search_key     (HMAC-SHA256)
```

- **Document encryption:** `AES-256-GCM`. Each encrypted file is laid out as
  `nonce(12 bytes) || ciphertext || auth tag(16 bytes)`. A new random nonce is
  generated for every encryption, and the GCM tag detects any tampering.
- **Search tokens:** `token = HMAC-SHA256(search_key, normalized_keyword)`,
  stored as 64-char hex. Deterministic, so the same keyword always maps to the
  same token — which is what makes lookup possible.
- **Key separation:** the AES key and HMAC key are derived with different HKDF
  `info` labels, so the same bytes are never reused for two purposes.

Keys are **never** hard-coded. A master secret is read from the `SSE_MASTER_KEY`
environment variable (optionally via `.env`), or generated on first run and
stored in the git-ignored `data/master.key` (classroom simplification).

## 8. Database Schema

```sql
documents
---------
id                 INTEGER PRIMARY KEY
original_filename  TEXT
encrypted_filename TEXT UNIQUE
file_size          INTEGER
uploaded_at        TEXT
mime_type          TEXT

search_index
------------
search_token TEXT        -- HMAC-SHA256 hex, NOT the plaintext keyword
document_id  INTEGER     -- FK -> documents(id)
PRIMARY KEY (search_token, document_id)
```

An index on `search_token` keeps lookups fast. The database stores **no
plaintext document content** and **no plaintext keywords**.

## 9. Installation

```bash
# 1. Create and activate a virtual environment
python -m venv .venv

# macOS / Linux:
source .venv/bin/activate
# Windows (PowerShell):
# .venv\Scripts\Activate.ps1
# Windows (cmd):
# .venv\Scripts\activate.bat

# 2. Install dependencies
pip install -r requirements.txt
```

(Optional) set your own master key instead of auto-generating one:

```bash
cp .env.example .env
python -c "import os; print('SSE_MASTER_KEY=' + os.urandom(32).hex())" >> .env
# then remove the placeholder line in .env
```

## 10. How to Run

```bash
# (optional) pre-load the bundled sample documents
python seed_samples.py

# start the app
streamlit run app.py
```

Then open the URL Streamlit prints (usually http://localhost:8501).

## 11. How to Demonstrate (10-minute flow)

1. `streamlit run app.py` and open the **Dashboard**.
2. Go to **📤 Upload Document**, upload `sample_documents/cryptography.txt`,
   click **🔐 Encrypt & Store** → see the success summary.
3. Open **📁 Repository**, expand **Show raw encrypted bytes** → the stored file
   is random-looking binary, not readable text.
4. Upload `network_security.txt` and `cloud_security.txt` too.
5. Go to **🔎 Search Documents**, search `encryption` → multiple encrypted
   documents match.
6. Click **🔓 Decrypt & View** on a result → the original plaintext appears.
   This is the "wow" moment: searchable, yet encrypted at rest.

You can also inspect the database directly to prove the index holds only tokens:

```bash
sqlite3 data/repository.db "SELECT search_token, document_id FROM search_index LIMIT 5;"
```

## 12. Running the Tests

```bash
pip install pytest
pytest -q
```

Tests cover: AES-GCM round-trip, tamper detection, wrong-key failure, HMAC token
determinism, keyword extraction, AND/OR search, the full upload→search→decrypt
flow, and the "no plaintext on disk / no plaintext in index" guarantees.

## 13. Security Considerations

Implemented: AES-256-GCM, random per-document nonce, HMAC-SHA256 tokens,
separate encryption/search keys via HKDF, parameterized SQL, file-type and
file-size validation, authentication-tag verification, and safe error handling.
No plaintext documents or plaintext keywords are stored.

## 14. Limitations (leakage — be honest about these)

This simplified prototype does **not** eliminate all leakage:

- **Search-pattern leakage:** identical queries produce identical tokens, so
  repeated searches are linkable.
- **Access-pattern leakage:** which documents are returned/opened is observable.
- **Frequency / metadata leakage:** token counts, file sizes and timestamps are
  visible.
- **Local key management:** a single master key stored locally.
- **Single-user authorization:** whoever runs the app is assumed authorized.

## 15. Future Enhancements

- PDF / DOCX text extraction (extend `document_processor.extract_text`).
- Phrase search, stemming, and result ranking.
- Padding / result-count hiding to reduce leakage.
- Per-user keys and real key management (KMS / HSM).
- Forward-private SSE constructions.

---

## How to Explain This Project in a 10-Minute Viva

**Problem.** Encryption protects documents but normally makes search impossible —
you would have to decrypt everything to find one keyword.

**Existing limitation.** Either you store plaintext (insecure) or you lose the
ability to search (unusable). We want both security *and* search.

**Proposed solution.** Searchable Symmetric Encryption: encrypt the documents,
and build a search index out of cryptographic *tokens* instead of plaintext
keywords.

**Architecture.** A Streamlit UI calls a `Repository` facade. `crypto.py` does
all cryptography, `document_processor.py` extracts keywords, `index.py` builds
and queries tokens, `database.py` stores metadata + tokens in SQLite, and
encrypted blobs live in `data/encrypted_documents/`.

**Role of AES-256-GCM.** Confidentiality + integrity for document contents. Each
file uses a fresh random nonce, and the authentication tag means any tampering
is detected at decryption time.

**Role of HMAC-SHA256.** Turns each keyword into a deterministic, opaque token
(`HMAC(search_key, keyword)`). The index stores tokens, never words, so the
repository can match a search without learning the keyword.

**Search workflow.** Query term → normalize → HMAC token → look up token in the
SQLite index → get matching document ids → show those encrypted documents.

**Demo workflow.** Upload a file → it is encrypted and indexed → show the random
`.enc` bytes → search a keyword → decrypt & view a result to reveal the original
text.

**Security limitations.** It still leaks search patterns, access patterns, and
metadata, and uses a single local key for one user. Honest framing matters.

**Future scope.** PDF support, ranking, leakage reduction (padding), per-user
keys, and forward-private SSE.
