"""Indexer node: ingests documents, chunks them, and writes embeddings.

Scopes required: docs:read, vdb:write, llm:call (embed only), audit:write
"""

import os

from orchestrator.auth import TokenManager
from orchestrator.state import RAGState

DOCS_MCP_URL = os.environ.get("DOCS_MCP_URL", "http://localhost:8001")
LLM_MCP_URL = os.environ.get("LLM_MCP_URL", "http://localhost:8004")
VECTORDB_MCP_URL = os.environ.get("VECTORDB_MCP_URL", "http://localhost:8002")

CHUNK_SIZE = 512  # tokens per chunk
CHUNK_OVERLAP = 64  # overlap between chunks
BATCH_SIZE = 50  # embeddings per batch


def ingest(state: RAGState, token_mgr: TokenManager) -> dict:
    """Ingest documents into the vector store.

    Pipeline:
    1. Exchange token for indexer scopes
    2. List and read documents from docs-mcp
    3. Chunk documents
    4. Generate embeddings via llm-mcp /tools/embed
    5. Write embeddings to vectordb-mcp /tools/upsert
    """
    try:
        # Scope narrowing for indexer: docs + vectordb write + embedding
        child_token = token_mgr.exchange_token(
            state["orchestrator_token"],
            target_scopes=["docs:read", "vdb:write", "llm:call", "audit:write"],
        )

        # Step 1: List available documents
        docs_list = token_mgr.make_authenticated_request(
            method="POST",
            url=f"{DOCS_MCP_URL}/tools/list_documents",
            token=child_token,
            body={"path": state.get("source_path", "/")},
        )

        documents = docs_list.get("documents", [])
        total_chunks = 0
        total_embeddings = 0

        for doc_meta in documents:
            # Step 2: Read document content
            doc = token_mgr.make_authenticated_request(
                method="POST",
                url=f"{DOCS_MCP_URL}/tools/get_chunks",
                token=child_token,
                body={
                    "document_id": doc_meta["id"],
                    "chunk_size": CHUNK_SIZE,
                    "chunk_overlap": CHUNK_OVERLAP,
                },
            )

            chunks = doc.get("chunks", [])
            total_chunks += len(chunks)

            # Step 3: Generate embeddings in batches
            for i in range(0, len(chunks), BATCH_SIZE):
                batch = chunks[i : i + BATCH_SIZE]
                texts = [c["text"] for c in batch]

                embeddings_result = token_mgr.make_authenticated_request(
                    method="POST",
                    url=f"{LLM_MCP_URL}/tools/embed",
                    token=child_token,
                    body={"texts": texts, "model": "text-embedding-3-large"},
                )

                embeddings = embeddings_result.get("embeddings", [])

                # Step 4: Write to vector store
                points = []
                for chunk, embedding in zip(batch, embeddings):
                    points.append(
                        {
                            "id": chunk["id"],
                            "vector": embedding,
                            "metadata": {
                                "source": doc_meta.get("name", "unknown"),
                                "document_id": doc_meta["id"],
                                "chunk_index": chunk.get("index", 0),
                                "text": chunk["text"],
                            },
                        }
                    )

                token_mgr.make_authenticated_request(
                    method="POST",
                    url=f"{VECTORDB_MCP_URL}/tools/upsert",
                    token=child_token,
                    body={"points": points},
                )
                total_embeddings += len(points)

        return {
            "documents_processed": len(documents),
            "chunks_created": total_chunks,
            "embeddings_written": total_embeddings,
            "audit_events": state["audit_events"]
            + [
                {
                    "node": "indexer",
                    "action": "ingest",
                    "documents": len(documents),
                    "chunks": total_chunks,
                    "embeddings": total_embeddings,
                }
            ],
        }

    except Exception as e:
        return {
            "documents_processed": 0,
            "chunks_created": 0,
            "embeddings_written": 0,
            "errors": state["errors"] + [f"indexer: {e}"],
        }
