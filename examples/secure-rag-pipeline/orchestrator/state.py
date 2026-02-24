"""Shared state schema for the RAG pipeline orchestrator."""

from typing import Optional, TypedDict


class RAGState(TypedDict):
    """State passed between nodes in the LangGraph pipeline."""

    # Input
    query: str
    mode: str  # "query" or "ingest"
    source_path: Optional[str]  # For ingest mode: path to documents

    # Token management
    orchestrator_token: str
    active_child_token: Optional[str]

    # Pipeline state (query path)
    retrieved_chunks: list[dict]
    ranked_chunks: list[dict]
    generated_answer: Optional[str]
    citations: list[dict]

    # Pipeline state (ingest path)
    documents_processed: int
    chunks_created: int
    embeddings_written: int

    # Observability
    errors: list[str]
    audit_events: list[dict]
