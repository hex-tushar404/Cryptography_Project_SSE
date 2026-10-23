"""
seed_samples.py
===============

Convenience script to load the bundled sample documents into the encrypted
repository so a demo is ready immediately. Safe to run multiple times:
documents that already exist are skipped.

Usage:
    python seed_samples.py
"""

from __future__ import annotations

from pathlib import Path

from src.repository import DuplicateDocumentError, Repository, RepositoryError

SAMPLE_DIR = Path(__file__).resolve().parent / "sample_documents"


def main() -> None:
    repo = Repository()
    sample_files = sorted(
        p for p in SAMPLE_DIR.iterdir()
        if p.suffix.lower() in {".txt", ".md"}
    )
    if not sample_files:
        print(f"No sample documents found in {SAMPLE_DIR}")
        return

    for path in sample_files:
        raw = path.read_bytes()
        try:
            result = repo.upload_document(path.name, raw)
        except DuplicateDocumentError:
            print(f"- skipped (already present): {path.name}")
            continue
        except RepositoryError as exc:
            print(f"! failed: {path.name} -> {exc}")
            continue
        print(
            f"+ encrypted & indexed: {path.name} "
            f"({result.token_count} search tokens)"
        )

    stats = repo.stats()
    print(
        f"\nRepository now holds {stats['document_count']} documents and "
        f"{stats['keyword_count']} unique search tokens."
    )


if __name__ == "__main__":
    main()
