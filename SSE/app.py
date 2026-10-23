"""
app.py
======

Streamlit UI for the Searchable Symmetric Encryption (SSE) document repository.

Pages (sidebar navigation):
    Dashboard        high-level stats + how-it-works summary
    Upload Document  encrypt + index a .txt / .md file
    Search Documents HMAC-token search over the encrypted index
    Repository       table of stored (encrypted) documents + details
    About SSE        educational explanation + limitations

Run with:
    streamlit run app.py

All real work is delegated to src/repository.Repository -- this file is only
presentation and error handling, so no plaintext or secret key is ever shown.
"""

from __future__ import annotations

import streamlit as st

from src import repository as repo_module
from src.document_processor import (
    SUPPORTED_EXTENSIONS,
    FileTooLargeError,
    UnsupportedFileError,
)
from src.repository import (
    DuplicateDocumentError,
    Repository,
    RepositoryError,
    format_size,
)

PAGE_TITLE = "🔐 Secure Searchable Document Repository"
SUBTITLE = "Search encrypted documents without decrypting the entire repository"


# --- Resource wiring --------------------------------------------------------

@st.cache_resource(show_spinner=False)
def get_repository() -> Repository:
    """Create (once) and cache the Repository for the whole Streamlit session."""
    return Repository()


def init_state() -> None:
    """Initialize session-state keys used across reruns."""
    st.session_state.setdefault("decrypted", {})      # doc_id -> plaintext
    st.session_state.setdefault("last_search", "")
    st.session_state.setdefault("search_hits", None)   # None = no search yet


# --- Pages ------------------------------------------------------------------

def page_dashboard(repo: Repository) -> None:
    st.header("📊 Dashboard")

    try:
        stats = repo.stats()
    except RepositoryError as exc:
        st.error(f"Could not load repository stats: {exc}")
        return

    col1, col2, col3 = st.columns(3)
    col1.metric("Encrypted Documents", stats["document_count"])
    col2.metric("Indexed Keywords", stats["keyword_count"])
    col3.metric("Repository Size", format_size(stats["repository_size_bytes"]))

    col4, col5 = st.columns(2)
    col4.metric("Encryption", stats["encryption"])
    col5.metric("Search Index", stats["search_index"])

    st.divider()
    st.info(
        "Documents are encrypted before storage. Search queries are converted "
        "into HMAC-based tokens and matched against the secure search index, so "
        "the repository never needs the plaintext to answer a search."
    )

    if stats["document_count"] == 0:
        st.warning(
            "The repository is empty. Go to **📤 Upload Document** to add a file, "
            "or load the bundled sample documents from **sample_documents/** "
            "(see the README)."
        )


def page_upload(repo: Repository) -> None:
    st.header("📤 Upload Document")
    st.caption("Supported formats: TXT and Markdown · Max size 5 MB")

    uploaded = st.file_uploader(
        "Choose a TXT or Markdown file",
        type=[ext.lstrip(".") for ext in sorted(SUPPORTED_EXTENSIONS)],
        accept_multiple_files=False,
    )

    if uploaded is None:
        st.stop()

    st.write(f"**Selected:** {uploaded.name}")

    if st.button("🔐 Encrypt & Store", type="primary"):
        raw_bytes = uploaded.getvalue()
        try:
            result = repo.upload_document(uploaded.name, raw_bytes)
        except UnsupportedFileError:
            st.error("Currently supported formats: TXT and Markdown.")
            return
        except FileTooLargeError as exc:
            st.error(f"❌ {exc}")
            return
        except DuplicateDocumentError as exc:
            st.warning(f"⚠️ {exc}")
            return
        except RepositoryError as exc:
            st.error(f"❌ Upload failed: {exc}")
            return

        # Invalidate cached search results since the index changed.
        st.session_state["search_hits"] = None

        st.success("✅ Document encrypted successfully.")
        st.markdown(
            f"""
| Field | Value |
|-------|-------|
| Filename | `{result.original_filename}` |
| Encryption | AES-256-GCM |
| Search tokens generated | {result.token_count} |
| Encrypted file | `{result.encrypted_filename}` |
| Storage | Encrypted Repository |
"""
        )
        st.caption("The secret key is never displayed and never leaves the app.")


def page_search(repo: Repository) -> None:
    st.header("🔎 Search Encrypted Documents")

    with st.form("search_form"):
        query = st.text_input(
            "Enter keyword",
            value=st.session_state.get("last_search", ""),
            placeholder="cryptography",
        )
        st.caption("Tip: multiple words use AND by default. Try `cloud OR network`.")
        submitted = st.form_submit_button("SEARCH", type="primary")

    if submitted:
        if not query.strip():
            st.warning("⚠️ Please enter a keyword to search.")
            st.session_state["search_hits"] = None
            return
        st.session_state["last_search"] = query
        try:
            st.session_state["search_hits"] = repo.search(query)
        except RepositoryError as exc:
            st.error(f"❌ Search failed: {exc}")
            st.session_state["search_hits"] = None
            return

    hits = st.session_state.get("search_hits")
    if hits is None:
        _render_search_explainer(st.session_state.get("last_search", "cryptography"))
        return

    st.subheader("Search Results")
    if not hits:
        st.info("No documents matched your search.")
    else:
        for hit in hits:
            _render_search_hit(repo, hit)
        st.success(f"{len(hits)} document(s) found.")

    st.divider()
    _render_search_explainer(st.session_state.get("last_search", "cryptography"))


def _render_search_hit(repo: Repository, hit: repo_module.SearchHit) -> None:
    """Render a single search result with a working Decrypt & View action."""
    with st.container(border=True):
        st.markdown(f"🔒 **{hit.original_filename}**  ·  {format_size(hit.file_size)}")
        decrypt_key = f"decrypt_{hit.document_id}"
        if st.button("🔓 Decrypt & View", key=decrypt_key):
            try:
                text = repo.decrypt_document(hit.document_id)
                st.session_state["decrypted"][hit.document_id] = text
            except RepositoryError as exc:
                st.error(f"❌ {exc}")

        if hit.document_id in st.session_state["decrypted"]:
            st.success("Decryption successful.")
            st.caption("Original document:")
            st.code(st.session_state["decrypted"][hit.document_id], language="text")
            st.warning("⚠️ The document was decrypted only for authorized viewing.")


def _render_search_explainer(sample_term: str) -> None:
    term = (sample_term or "cryptography").split()[0] if sample_term else "cryptography"
    st.caption("How a search works:")
    st.code(
        f'"{term}"\n'
        "      ↓  normalize keyword\n"
        f"{term.lower()}\n"
        "      ↓  HMAC-SHA256(search_key, keyword)\n"
        "search token (e.g. 9a7d1f...)\n"
        "      ↓  look up in encrypted index\n"
        "matching document ids\n"
        "      ↓\n"
        "matching documents",
        language="text",
    )
    st.caption("The secret HMAC key is never shown.")


def page_repository(repo: Repository) -> None:
    st.header("📁 Repository")

    try:
        docs = repo.list_documents()
    except RepositoryError as exc:
        st.error(f"Could not load repository: {exc}")
        return

    if not docs:
        st.info("No documents stored yet. Upload one from **📤 Upload Document**.")
        return

    # Summary table (no plaintext content shown here).
    rows = [
        {
            "Filename": d.original_filename,
            "Size": format_size(d.file_size),
            "Uploaded (UTC)": d.uploaded_at,
            "Status": "🔒 Encrypted",
        }
        for d in docs
    ]
    st.dataframe(rows, use_container_width=True, hide_index=True)

    st.divider()
    st.subheader("View Details")
    labels = {f"{d.original_filename} (id {d.id})": d.id for d in docs}
    choice = st.selectbox("Select a document", list(labels.keys()))
    doc_id = labels[choice]
    record = repo.get_document(doc_id)
    if record is None:
        st.error("Document not found.")
        return

    st.markdown(
        f"""
| Metadata | Value |
|----------|-------|
| Original filename | `{record.original_filename}` |
| Encrypted filename | `{record.encrypted_filename}` |
| Size | {format_size(record.file_size)} |
| MIME type | `{record.mime_type}` |
| Uploaded (UTC) | {record.uploaded_at} |
| Status | 🔒 Encrypted (AES-256-GCM) |
"""
    )

    with st.expander("🔬 Show raw encrypted bytes (proof it is not plaintext)"):
        try:
            preview = repo.read_encrypted_preview(doc_id, 48)
            st.code(preview.hex(" "), language="text")
            st.caption(
                "This is the start of the stored .enc file: random-looking bytes "
                "(nonce + ciphertext + authentication tag), not readable text."
            )
        except RepositoryError as exc:
            st.error(str(exc))


def page_about() -> None:
    st.header("ℹ️ About Searchable Symmetric Encryption")

    st.subheader("What problem does SSE solve?")
    st.write(
        "Encryption protects documents, but normally makes searching impossible: "
        "if everything is scrambled, how do you find the file that mentions "
        "\"encryption\"? Searchable Symmetric Encryption lets you search encrypted "
        "data using special search tokens, without first decrypting everything."
    )

    st.subheader("How does this prototype work?")
    st.code(
        "Document                 Keyword\n"
        "   ↓                        ↓\n"
        "AES-256-GCM              HMAC-SHA256\n"
        "   ↓                        ↓\n"
        "Encrypted Document       Search Token\n"
        "                            ↓\n"
        "                         Search Index (SQLite)",
        language="text",
    )

    st.subheader("What does the repository actually store?")
    st.write(
        "- Encrypted document data (AES-256-GCM blobs on disk)\n"
        "- Document metadata (filename, size, timestamp)\n"
        "- HMAC-based search tokens\n\n"
        "It does **not** store the document plaintext or the raw searchable "
        "keywords."
    )

    st.info(
        "This is an educational SSE prototype, not a production-grade searchable "
        "encryption system. Advanced SSE constructions provide stronger leakage "
        "protection and access-control mechanisms."
    )


# --- Main -------------------------------------------------------------------

def main() -> None:
    st.set_page_config(page_title="SSE Document Repository", page_icon="🔐", layout="wide")
    init_state()

    st.title(PAGE_TITLE)
    st.caption(SUBTITLE)

    try:
        repo = get_repository()
    except RepositoryError as exc:
        st.error(f"Could not start the repository: {exc}")
        st.stop()

    st.sidebar.title("Navigation")
    page = st.sidebar.radio(
        "Go to",
        (
            "📊 Dashboard",
            "📤 Upload Document",
            "🔎 Search Documents",
            "📁 Repository",
            "ℹ️ About",
        ),
        label_visibility="collapsed",
    )
    st.sidebar.divider()
    st.sidebar.caption(
        "Educational prototype · AES-256-GCM + HMAC-SHA256 · single local user"
    )

    if page == "📊 Dashboard":
        page_dashboard(repo)
    elif page == "📤 Upload Document":
        page_upload(repo)
    elif page == "🔎 Search Documents":
        page_search(repo)
    elif page == "📁 Repository":
        page_repository(repo)
    else:
        page_about()


if __name__ == "__main__":
    main()
