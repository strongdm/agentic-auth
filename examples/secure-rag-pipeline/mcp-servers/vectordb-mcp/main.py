"""Vector database MCP server.

Provides JWT-authenticated access to a Qdrant vector store.
Scopes:
  - vdb:read  → search
  - vdb:write → upsert, delete
"""

import hashlib
import os
import uuid

from fastapi import Depends, FastAPI
from pydantic import BaseModel
from qdrant_client import QdrantClient
from qdrant_client.models import Distance, PointStruct, VectorParams

# Import path assumes running from project root
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from shared.auth import audit_log, require_scope

app = FastAPI(title="vectordb-mcp", description="Vector store operations for RAG pipeline")

QDRANT_URL = os.environ.get("QDRANT_URL", "http://localhost:6333")
COLLECTION_NAME = os.environ.get("COLLECTION_NAME", "rag-documents")
VECTOR_DIM = int(os.environ.get("VECTOR_DIM", "3072"))  # text-embedding-3-large

client = QdrantClient(url=QDRANT_URL)


@app.on_event("startup")
async def ensure_collection():
    """Create the vector collection if it doesn't exist."""
    collections = client.get_collections().collections
    names = [c.name for c in collections]
    if COLLECTION_NAME not in names:
        client.create_collection(
            collection_name=COLLECTION_NAME,
            vectors_config=VectorParams(size=VECTOR_DIM, distance=Distance.COSINE),
        )


@app.get("/health")
async def health():
    """Readiness probe (no auth required)."""
    try:
        client.get_collections()
        return {"status": "ok", "backend": "qdrant"}
    except Exception as e:
        return {"status": "error", "detail": str(e)}


class SearchRequest(BaseModel):
    query: list[float] | None = None  # Pre-computed query vector
    query_text: str | None = None  # Or raw text (requires external embedding)
    top_k: int = 20
    include_metadata: bool = True
    filters: dict | None = None


@app.post("/tools/search")
async def search(req: SearchRequest, claims: dict = Depends(require_scope("vdb:read"))):
    """Search the vector store for similar documents.

    Accepts either a pre-computed query vector or delegates to the caller
    to provide one. In practice, the retriever node pre-computes the
    embedding before calling this endpoint.
    """
    if req.query is None:
        return {"error": "query vector required (pre-compute via llm-mcp /tools/embed)"}

    results = client.search(
        collection_name=COLLECTION_NAME,
        query_vector=req.query,
        limit=req.top_k,
        with_payload=req.include_metadata,
    )

    formatted = []
    for hit in results:
        entry = {
            "id": str(hit.id),
            "score": hit.score,
        }
        if req.include_metadata and hit.payload:
            entry["text"] = hit.payload.get("text", "")
            entry["metadata"] = {
                k: v for k, v in hit.payload.items() if k != "text"
            }
        formatted.append(entry)

    audit_log("vectordb-mcp", "/tools/search", claims, results_count=len(formatted))
    return {"results": formatted, "caller": claims["sub"]}


class UpsertRequest(BaseModel):
    points: list[dict]  # Each: {id, vector, metadata}


@app.post("/tools/upsert")
async def upsert(req: UpsertRequest, claims: dict = Depends(require_scope("vdb:write"))):
    """Write embedding vectors to the store."""
    qdrant_points = []
    for p in req.points:
        point_id = p.get("id", str(uuid.uuid4()))
        qdrant_points.append(
            PointStruct(
                id=point_id if isinstance(point_id, int) else hashlib.md5(point_id.encode()).hexdigest()[:16],
                vector=p["vector"],
                payload=p.get("metadata", {}),
            )
        )

    client.upsert(collection_name=COLLECTION_NAME, points=qdrant_points)

    audit_log("vectordb-mcp", "/tools/upsert", claims, points_count=len(qdrant_points))
    return {"upserted": len(qdrant_points), "caller": claims["sub"]}


class DeleteRequest(BaseModel):
    ids: list[str]


@app.post("/tools/delete")
async def delete(req: DeleteRequest, claims: dict = Depends(require_scope("vdb:write"))):
    """Delete vectors by ID."""
    client.delete(collection_name=COLLECTION_NAME, points_selector=req.ids)

    audit_log("vectordb-mcp", "/tools/delete", claims, deleted_count=len(req.ids))
    return {"deleted": len(req.ids), "caller": claims["sub"]}
