"""LangGraph state graph for the secure multi-agent RAG pipeline.

Two execution modes:
- "query": retriever → ranker → generator
- "ingest": indexer (document ingestion)

Each node exchanges the orchestrator's broad token for a scope-narrowed
child token before making MCP calls.
"""

import os
import sys

from langgraph.graph import END, StateGraph

from orchestrator.auth import TokenManager
from orchestrator.nodes.generator import generate
from orchestrator.nodes.indexer import ingest
from orchestrator.nodes.ranker import rank
from orchestrator.nodes.retriever import retrieve
from orchestrator.state import RAGState

CLIENT_ID = os.environ.get("SDM_CLIENT_ID", "")

# All scopes the orchestrator can request
ALL_SCOPES = [
    "rag:orchestrate",
    "docs:read",
    "vdb:read",
    "vdb:write",
    "rank:call",
    "llm:call",
    "audit:write",
]


def _acquire_token(state: RAGState) -> dict:
    """Acquire the orchestrator's broad token."""
    token_mgr = TokenManager(CLIENT_ID)
    token = token_mgr.acquire_token(ALL_SCOPES)
    return {"orchestrator_token": token}


def _route_mode(state: RAGState) -> str:
    """Route to query or ingest pipeline based on mode."""
    return state.get("mode", "query")


def _retrieve_node(state: RAGState) -> dict:
    token_mgr = TokenManager(CLIENT_ID)
    return retrieve(state, token_mgr)


def _rank_node(state: RAGState) -> dict:
    token_mgr = TokenManager(CLIENT_ID)
    return rank(state, token_mgr)


def _generate_node(state: RAGState) -> dict:
    token_mgr = TokenManager(CLIENT_ID)
    return generate(state, token_mgr)


def _ingest_node(state: RAGState) -> dict:
    token_mgr = TokenManager(CLIENT_ID)
    return ingest(state, token_mgr)


def _summary_node(state: RAGState) -> dict:
    """Log final pipeline state."""
    mode = state.get("mode", "query")
    errors = state.get("errors", [])

    if mode == "query":
        print(f"Query: {state.get('query', '')}")
        print(f"Retrieved: {len(state.get('retrieved_chunks', []))} chunks")
        print(f"Ranked: {len(state.get('ranked_chunks', []))} chunks")
        answer = state.get("generated_answer", "")
        print(f"Answer length: {len(answer) if answer else 0} chars")
    else:
        print(f"Documents processed: {state.get('documents_processed', 0)}")
        print(f"Chunks created: {state.get('chunks_created', 0)}")
        print(f"Embeddings written: {state.get('embeddings_written', 0)}")

    if errors:
        print(f"Errors ({len(errors)}):")
        for err in errors:
            print(f"  - {err}")

    return {}


def build_graph() -> StateGraph:
    """Build the RAG pipeline graph.

    Graph structure:
        acquire_token → route_mode
            ├─ "query"  → retrieve → rank → generate → summary
            └─ "ingest" → ingest → summary
    """
    graph = StateGraph(RAGState)

    # Add nodes
    graph.add_node("acquire_token", _acquire_token)
    graph.add_node("retrieve", _retrieve_node)
    graph.add_node("rank", _rank_node)
    graph.add_node("generate", _generate_node)
    graph.add_node("ingest", _ingest_node)
    graph.add_node("summary", _summary_node)

    # Entry point
    graph.set_entry_point("acquire_token")

    # Routing based on mode
    graph.add_conditional_edges(
        "acquire_token",
        _route_mode,
        {
            "query": "retrieve",
            "ingest": "ingest",
        },
    )

    # Query path: retrieve → rank → generate → summary
    graph.add_edge("retrieve", "rank")
    graph.add_edge("rank", "generate")
    graph.add_edge("generate", "summary")

    # Ingest path: ingest → summary
    graph.add_edge("ingest", "summary")

    # Summary → end
    graph.add_edge("summary", END)

    return graph


def run_query(query: str) -> str:
    """Run a query through the RAG pipeline. Returns the generated answer."""
    app = build_graph().compile()
    initial_state: RAGState = {
        "query": query,
        "mode": "query",
        "source_path": None,
        "orchestrator_token": "",
        "active_child_token": None,
        "retrieved_chunks": [],
        "ranked_chunks": [],
        "generated_answer": None,
        "citations": [],
        "documents_processed": 0,
        "chunks_created": 0,
        "embeddings_written": 0,
        "errors": [],
        "audit_events": [],
    }

    final_state = app.invoke(initial_state)
    return final_state.get("generated_answer", "No answer generated.")


def run_ingest(source_path: str) -> dict:
    """Run document ingestion. Returns stats."""
    app = build_graph().compile()
    initial_state: RAGState = {
        "query": "",
        "mode": "ingest",
        "source_path": source_path,
        "orchestrator_token": "",
        "active_child_token": None,
        "retrieved_chunks": [],
        "ranked_chunks": [],
        "generated_answer": None,
        "citations": [],
        "documents_processed": 0,
        "chunks_created": 0,
        "embeddings_written": 0,
        "errors": [],
        "audit_events": [],
    }

    final_state = app.invoke(initial_state)
    return {
        "documents_processed": final_state.get("documents_processed", 0),
        "chunks_created": final_state.get("chunks_created", 0),
        "embeddings_written": final_state.get("embeddings_written", 0),
        "errors": final_state.get("errors", []),
    }


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python -m orchestrator.graph query 'your question here'")
        print("  python -m orchestrator.graph ingest /path/to/documents")
        sys.exit(1)

    mode = sys.argv[1]
    if mode == "query":
        question = sys.argv[2] if len(sys.argv) > 2 else "What is this about?"
        answer = run_query(question)
        print(f"\n{'='*60}")
        print(f"Answer: {answer}")
    elif mode == "ingest":
        path = sys.argv[2] if len(sys.argv) > 2 else "./sample-docs"
        stats = run_ingest(path)
        print(f"\nIngestion complete: {stats}")
    else:
        print(f"Unknown mode: {mode}")
        sys.exit(1)
