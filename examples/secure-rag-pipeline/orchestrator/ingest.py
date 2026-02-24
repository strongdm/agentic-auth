#!/usr/bin/env python3
"""Ingest documents into the RAG pipeline.

Usage:
    python -m orchestrator.ingest --source ./sample-docs/
"""

import argparse
import sys

from orchestrator.graph import run_ingest


def main():
    parser = argparse.ArgumentParser(description="Ingest documents into the RAG pipeline")
    parser.add_argument(
        "--source",
        default="./sample-docs",
        help="Path to documents directory (default: ./sample-docs)",
    )
    args = parser.parse_args()

    print(f"Ingesting documents from: {args.source}\n")

    stats = run_ingest(args.source)

    print(f"\n{'='*60}")
    print(f"Ingestion complete:")
    print(f"  Documents processed: {stats['documents_processed']}")
    print(f"  Chunks created:      {stats['chunks_created']}")
    print(f"  Embeddings written:  {stats['embeddings_written']}")

    if stats.get("errors"):
        print(f"\nErrors ({len(stats['errors'])}):")
        for err in stats["errors"]:
            print(f"  - {err}")
        sys.exit(1)


if __name__ == "__main__":
    main()
