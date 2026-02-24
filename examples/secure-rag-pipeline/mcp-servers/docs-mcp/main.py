"""Document source MCP server.

Provides JWT-authenticated access to source documents (local filesystem or S3).
Scope: docs:read
"""

import hashlib
import os
import uuid

from fastapi import Depends, FastAPI
from pydantic import BaseModel

import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from shared.auth import audit_log, require_scope

app = FastAPI(title="docs-mcp", description="Document source access for RAG pipeline")

DOCS_ROOT = os.environ.get("DOCS_ROOT", "./sample-docs")
# Supported file extensions
SUPPORTED_EXTENSIONS = {".txt", ".md", ".pdf", ".json", ".csv", ".html"}


@app.get("/health")
async def health():
    """Readiness probe."""
    exists = os.path.isdir(DOCS_ROOT)
    return {"status": "ok" if exists else "error", "docs_root": DOCS_ROOT}


class ListRequest(BaseModel):
    path: str = "/"
    extensions: list[str] | None = None


@app.post("/tools/list_documents")
async def list_documents(
    req: ListRequest, claims: dict = Depends(require_scope("docs:read"))
):
    """List available documents in the source directory."""
    search_path = os.path.join(DOCS_ROOT, req.path.lstrip("/"))
    if not os.path.isdir(search_path):
        return {"documents": [], "error": f"Path not found: {req.path}"}

    allowed_ext = set(req.extensions) if req.extensions else SUPPORTED_EXTENSIONS
    documents = []

    for root, _dirs, files in os.walk(search_path):
        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext not in allowed_ext:
                continue
            full_path = os.path.join(root, fname)
            rel_path = os.path.relpath(full_path, DOCS_ROOT)
            doc_id = hashlib.sha256(rel_path.encode()).hexdigest()[:16]
            stat = os.stat(full_path)
            documents.append(
                {
                    "id": doc_id,
                    "name": fname,
                    "path": rel_path,
                    "size_bytes": stat.st_size,
                    "extension": ext,
                }
            )

    audit_log(
        "docs-mcp", "/tools/list_documents", claims, documents_found=len(documents)
    )
    return {"documents": documents, "caller": claims["sub"]}


class GetDocumentRequest(BaseModel):
    document_id: str


@app.post("/tools/get_document")
async def get_document(
    req: GetDocumentRequest, claims: dict = Depends(require_scope("docs:read"))
):
    """Read the full content of a document by ID."""
    # Find document by ID (hash of relative path)
    for root, _dirs, files in os.walk(DOCS_ROOT):
        for fname in files:
            full_path = os.path.join(root, fname)
            rel_path = os.path.relpath(full_path, DOCS_ROOT)
            doc_id = hashlib.sha256(rel_path.encode()).hexdigest()[:16]
            if doc_id == req.document_id:
                with open(full_path, "r", errors="replace") as f:
                    content = f.read()
                audit_log(
                    "docs-mcp",
                    "/tools/get_document",
                    claims,
                    document=rel_path,
                    size=len(content),
                )
                return {
                    "id": doc_id,
                    "name": fname,
                    "content": content,
                    "caller": claims["sub"],
                }

    return {"error": f"Document not found: {req.document_id}"}


class GetChunksRequest(BaseModel):
    document_id: str
    chunk_size: int = 512  # Approximate tokens
    chunk_overlap: int = 64


@app.post("/tools/get_chunks")
async def get_chunks(
    req: GetChunksRequest, claims: dict = Depends(require_scope("docs:read"))
):
    """Read a document and return it pre-chunked.

    Uses a simple character-based chunking strategy. In production,
    you'd use a proper tokenizer-aware chunker.
    """
    # Find and read document
    for root, _dirs, files in os.walk(DOCS_ROOT):
        for fname in files:
            full_path = os.path.join(root, fname)
            rel_path = os.path.relpath(full_path, DOCS_ROOT)
            doc_id = hashlib.sha256(rel_path.encode()).hexdigest()[:16]
            if doc_id != req.document_id:
                continue

            with open(full_path, "r", errors="replace") as f:
                content = f.read()

            # Simple chunking: ~4 chars per token
            char_size = req.chunk_size * 4
            char_overlap = req.chunk_overlap * 4
            chunks = []
            start = 0
            idx = 0

            while start < len(content):
                end = min(start + char_size, len(content))
                chunk_text = content[start:end]
                chunk_id = f"{doc_id}_{idx}"
                chunks.append(
                    {
                        "id": chunk_id,
                        "index": idx,
                        "text": chunk_text,
                        "char_start": start,
                        "char_end": end,
                    }
                )
                idx += 1
                start = end - char_overlap
                if start >= len(content):
                    break

            audit_log(
                "docs-mcp",
                "/tools/get_chunks",
                claims,
                document=rel_path,
                chunks=len(chunks),
            )
            return {"chunks": chunks, "caller": claims["sub"]}

    return {"error": f"Document not found: {req.document_id}"}
