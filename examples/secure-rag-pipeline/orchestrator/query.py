#!/usr/bin/env python3
"""Query the RAG pipeline.

Usage:
    python -m orchestrator.query "What are the key findings from the Q4 report?"
"""

import sys

from orchestrator.graph import run_query


def main():
    if len(sys.argv) < 2:
        print("Usage: python -m orchestrator.query 'your question here'")
        sys.exit(1)

    query = " ".join(sys.argv[1:])
    print(f"Query: {query}\n")

    answer = run_query(query)

    print(f"\n{'='*60}")
    print(f"Answer:\n{answer}")


if __name__ == "__main__":
    main()
