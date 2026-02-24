"""Re-ranking MCP server.

Provides JWT-authenticated access to a cross-encoder re-ranking model.
Scope: rank:call

Re-ranking improves RAG quality by scoring query-document pairs with
a cross-encoder, which is more accurate than vector similarity alone.
"""

import os

from fastapi import Depends, FastAPI
from pydantic import BaseModel

import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from shared.auth import audit_log, require_scope

app = FastAPI(title="ranker-mcp", description="Cross-encoder re-ranking for RAG pipeline")

RANKER_MODEL = os.environ.get("RANKER_MODEL", "cross-encoder/ms-marco-MiniLM-L-12-v2")

# Lazy-load model to avoid slow startup
_model = None


def _get_model():
    global _model
    if _model is None:
        from sentence_transformers import CrossEncoder
        _model = CrossEncoder(RANKER_MODEL)
    return _model


@app.get("/health")
async def health():
    """Readiness probe."""
    return {"status": "ok", "model": RANKER_MODEL}


class RerankRequest(BaseModel):
    query: str
    chunks: list[dict]  # Each chunk: {text, id, score?, metadata?}
    top_k: int = 5


@app.post("/tools/rerank")
async def rerank(
    req: RerankRequest, claims: dict = Depends(require_scope("rank:call"))
):
    """Re-rank chunks using a cross-encoder model.

    Takes the query and candidate chunks from the retriever,
    scores each (query, chunk) pair, and returns the top-k
    highest-scoring chunks.
    """
    if not req.chunks:
        return {"ranked": [], "caller": claims["sub"]}

    model = _get_model()

    # Build (query, document) pairs for the cross-encoder
    pairs = []
    for chunk in req.chunks:
        text = chunk.get("text", chunk.get("content", ""))
        pairs.append((req.query, text))

    # Score all pairs
    scores = model.predict(pairs)

    # Attach scores and sort
    scored_chunks = []
    for chunk, score in zip(req.chunks, scores):
        scored_chunks.append(
            {
                **chunk,
                "rerank_score": float(score),
            }
        )

    scored_chunks.sort(key=lambda c: c["rerank_score"], reverse=True)
    top_chunks = scored_chunks[: req.top_k]

    audit_log(
        "ranker-mcp",
        "/tools/rerank",
        claims,
        input_count=len(req.chunks),
        output_count=len(top_chunks),
        top_score=top_chunks[0]["rerank_score"] if top_chunks else None,
    )

    return {"ranked": top_chunks, "caller": claims["sub"]}
