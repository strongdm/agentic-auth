"""Generator node: produces the final answer using an LLM.

Scope required: llm:call, audit:write
"""

import os

from orchestrator.auth import TokenManager
from orchestrator.state import RAGState

LLM_MCP_URL = os.environ.get("LLM_MCP_URL", "http://localhost:8004")


def generate(state: RAGState, token_mgr: TokenManager) -> dict:
    """Generate an answer from ranked context chunks.

    1. Exchange orchestrator token for generator-scoped token (llm:call)
    2. Call llm-mcp /tools/generate with query + context
    3. Return generated answer with citations
    """
    if not state["ranked_chunks"]:
        return {
            "generated_answer": "I couldn't find relevant information to answer your question.",
            "citations": [],
            "errors": state["errors"] + ["generator: no context chunks available"],
        }

    try:
        child_token = token_mgr.exchange_token(
            state["orchestrator_token"],
            target_scopes=["llm:call", "audit:write"],
        )

        # Build context from ranked chunks
        context_parts = []
        for i, chunk in enumerate(state["ranked_chunks"]):
            source = chunk.get("metadata", {}).get("source", "unknown")
            text = chunk.get("text", chunk.get("content", ""))
            context_parts.append(f"[{i + 1}] (Source: {source})\n{text}")

        result = token_mgr.make_authenticated_request(
            method="POST",
            url=f"{LLM_MCP_URL}/tools/generate",
            token=child_token,
            body={
                "query": state["query"],
                "context": "\n\n".join(context_parts),
                "system_prompt": (
                    "You are a helpful assistant. Answer the user's question based "
                    "on the provided context. Cite sources using [N] notation. "
                    "If the context doesn't contain enough information, say so."
                ),
                "max_tokens": 2048,
            },
        )

        answer = result.get("text", "")
        citations = result.get("citations", [])

        return {
            "generated_answer": answer,
            "citations": citations,
            "audit_events": state["audit_events"]
            + [
                {
                    "node": "generator",
                    "action": "generate",
                    "context_chunks": len(state["ranked_chunks"]),
                    "answer_length": len(answer),
                }
            ],
        }

    except Exception as e:
        return {
            "generated_answer": None,
            "citations": [],
            "errors": state["errors"] + [f"generator: {e}"],
        }
