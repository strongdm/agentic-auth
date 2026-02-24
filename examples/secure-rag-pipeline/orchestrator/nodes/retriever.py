"""Retriever node: searches the vector store for relevant chunks.

Scope required: vdb:read, audit:write
"""

import os

from orchestrator.auth import TokenManager
from orchestrator.state import RAGState

VECTORDB_MCP_URL = os.environ.get("VECTORDB_MCP_URL", "http://localhost:8002")


def retrieve(state: RAGState, token_mgr: TokenManager) -> dict:
    """Search the vector store for chunks relevant to the query.

    1. Exchange orchestrator token for retriever-scoped token (vdb:read)
    2. Call vectordb-mcp /tools/search
    3. Return candidate chunks
    """
    try:
        # Scope narrowing: only vector DB read access
        child_token = token_mgr.exchange_token(
            state["orchestrator_token"],
            target_scopes=["vdb:read", "audit:write"],
        )

        result = token_mgr.make_authenticated_request(
            method="POST",
            url=f"{VECTORDB_MCP_URL}/tools/search",
            token=child_token,
            body={
                "query": state["query"],
                "top_k": 20,
                "include_metadata": True,
            },
        )

        chunks = result.get("results", [])
        return {
            "retrieved_chunks": chunks,
            "audit_events": state["audit_events"]
            + [
                {
                    "node": "retriever",
                    "action": "vector_search",
                    "results_count": len(chunks),
                }
            ],
        }

    except Exception as e:
        return {
            "retrieved_chunks": [],
            "errors": state["errors"] + [f"retriever: {e}"],
        }
