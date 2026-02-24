"""Ranker node: re-ranks retrieved chunks using a cross-encoder.

Scope required: rank:call, audit:write
"""

import os

from orchestrator.auth import TokenManager
from orchestrator.state import RAGState

RANKER_MCP_URL = os.environ.get("RANKER_MCP_URL", "http://localhost:8003")


def rank(state: RAGState, token_mgr: TokenManager) -> dict:
    """Re-rank retrieved chunks to select the most relevant.

    1. Exchange orchestrator token for ranker-scoped token (rank:call)
    2. Call ranker-mcp /tools/rerank with query + candidate chunks
    3. Return top-k highest-relevance chunks
    """
    if not state["retrieved_chunks"]:
        return {
            "ranked_chunks": [],
            "errors": state["errors"] + ["ranker: no chunks to rank"],
        }

    try:
        child_token = token_mgr.exchange_token(
            state["orchestrator_token"],
            target_scopes=["rank:call", "audit:write"],
        )

        result = token_mgr.make_authenticated_request(
            method="POST",
            url=f"{RANKER_MCP_URL}/tools/rerank",
            token=child_token,
            body={
                "query": state["query"],
                "chunks": state["retrieved_chunks"],
                "top_k": 5,
            },
        )

        ranked = result.get("ranked", [])
        return {
            "ranked_chunks": ranked,
            "audit_events": state["audit_events"]
            + [
                {
                    "node": "ranker",
                    "action": "rerank",
                    "input_count": len(state["retrieved_chunks"]),
                    "output_count": len(ranked),
                }
            ],
        }

    except Exception as e:
        # Fallback: use retrieved chunks unranked (take first 5)
        return {
            "ranked_chunks": state["retrieved_chunks"][:5],
            "errors": state["errors"] + [f"ranker: {e} (using unranked fallback)"],
        }
