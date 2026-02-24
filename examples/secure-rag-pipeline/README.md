# Secure Multi-Agent RAG Pipeline

A complete, deployable example of a Retrieval-Augmented Generation (RAG) pipeline where every agent holds its own cryptographic identity and operates under strict least-privilege scope enforcement via [StrongDM ID](https://id.strongdm.ai).

This example shows the "why" of agentic identity, not just the mechanics. A traditional RAG pipeline runs as a single process with a single service account. If a malicious document triggers prompt injection, the attacker inherits full access to the vector store, the LLM, and every document. Here, each agent can only do what its token explicitly permits — enforced by the authorization server, not by the agent's own behavior.

## What This Example Demonstrates

- **Per-agent least-privilege** — Indexer can write to the vector store but cannot call the LLM; Generator can call the LLM but cannot write to the vector store
- **RFC 8693 token exchange** — The orchestrator exchanges its broad token for scope-narrowed child tokens before dispatching each agent
- **RFC 9449 DPoP** — All tokens are sender-constrained to an ephemeral EC keypair; a stolen token cannot be replayed from another process
- **Replay detection** — DPoP proof `jti` nonces are tracked and rejected on reuse
- **Structured audit trail** — Every MCP server logs caller identity, scope used, and operation details

## Architecture

```
             ┌────────────────────────────────────────────┐
             │            Orchestrator (LangGraph)         │
             │  token: rag:orchestrate + all child scopes  │
             └──────┬──────┬───────────┬──────────────────┘
    RFC 8693        │      │           │              │
    exchange down   ▼      ▼           ▼              ▼
    ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────┐
    │  Indexer │ │Retriever │ │  Ranker  │ │  Generator   │
    │docs:read │ │ vdb:read │ │rank:call │ │  llm:call    │
    │vdb:write │ │          │ │          │ │              │
    │llm:call  │ │          │ │          │ │              │
    └────┬─────┘ └────┬─────┘ └────┬─────┘ └──────┬───────┘
         │            │            │               │
         ▼            ▼            ▼               ▼
    ┌─────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────┐
    │docs-mcp │ │vectordb- │ │ranker-   │ │   llm-mcp    │
    │         │ │   mcp    │ │  mcp     │ │              │
    └─────────┘ └────┬─────┘ └──────────┘ └──────────────┘
                     │
                     ▼
                ┌─────────┐
                │ Qdrant  │
                └─────────┘
```

See [architecture.md](architecture.md) for a full breakdown of the threat model, token flows, and attack mitigations.

## Agent Scopes

| Agent | Scopes | Can do | Cannot do |
|-------|--------|--------|-----------|
| Orchestrator | `rag:orchestrate docs:read vdb:read vdb:write llm:call rank:call` | Everything (exchange only) | Acts only by delegating |
| Indexer | `docs:read vdb:write llm:call` | Read docs, embed, write vectors | Generate answers, read vectors |
| Retriever | `vdb:read` | Similarity search | Write, generate, rank |
| Ranker | `rank:call` | Re-rank results | Any data access |
| Generator | `llm:call` | Generate answers | Read/write any data store |

## Quick Start

### 1. Register the orchestrator agent

```bash
curl -s -X POST https://id.strongdm.ai/realms/default/register/request \
  -H 'Content-Type: application/json' \
  -d '{
    "email": "you@example.com",
    "client_name": "rag-orchestrator",
    "requested_scopes": [
      "rag:orchestrate", "docs:read",
      "vdb:read", "vdb:write", "llm:call", "rank:call"
    ]
  }'
```

Check your email and confirm enrollment:

```bash
curl -s -X POST https://id.strongdm.ai/realms/default/register/confirm \
  -H 'Content-Type: application/json' \
  -d '{"client_id": "cli_rag_orchestrator_XXXXXXXX", "code": "123456"}'
```

### 2. Configure environment

```bash
cp .env.example .env
# Fill in SDM_CLIENT_ID, SDM_CLIENT_SECRET, ANTHROPIC_API_KEY, OPENAI_API_KEY
```

### 3. Start all services

```bash
docker compose up --build
```

This starts Qdrant, all four MCP servers, and the orchestrator container.

### 4. Ingest documents

```bash
docker compose run orchestrator python -m orchestrator.ingest --source /docs
```

### 5. Query

```bash
docker compose run orchestrator python -m orchestrator.query "What were the key findings?"
```

## Configuration

### Root `.env`

| Variable | Description | Default |
|----------|-------------|---------|
| `SDM_CLIENT_ID` | Orchestrator client ID from StrongDM ID | Required |
| `SDM_CLIENT_SECRET` | Orchestrator client secret | Required |
| `SDM_ISSUER` | StrongDM ID realm URL | `https://id.strongdm.ai/realms/default` |
| `ANTHROPIC_API_KEY` | API key for Claude (LLM generation) | Required |
| `OPENAI_API_KEY` | API key for text-embedding-3-large | Required |

### MCP Server Environment

Each MCP server accepts:

| Variable | Description | Default |
|----------|-------------|---------|
| `SDM_ISSUER` | Token issuer for JWT verification | `https://id.strongdm.ai/realms/default` |
| `SDM_JWKS_URL` | JWKS endpoint (derived from issuer if not set) | `{SDM_ISSUER}/jwks` |

Additional variables per server:

| Server | Variable | Description |
|--------|----------|-------------|
| `vectordb-mcp` | `QDRANT_URL` | Qdrant HTTP endpoint |
| `vectordb-mcp` | `COLLECTION_NAME` | Vector collection name |
| `vectordb-mcp` | `VECTOR_DIM` | Embedding dimensions (3072 for text-embedding-3-large) |
| `docs-mcp` | `DOCS_ROOT` | Root directory for source documents |
| `ranker-mcp` | `RANKER_MODEL` | HuggingFace cross-encoder model |
| `llm-mcp` | `DEFAULT_MODEL` | Claude model ID |

## Error Responses

All MCP servers return consistent JSON error bodies:

| HTTP Status | Meaning |
|-------------|---------|
| `401 Unauthorized` | Missing, expired, or invalid token; DPoP proof verification failed |
| `403 Forbidden` | Valid token but insufficient scope |
| `422 Unprocessable Entity` | Invalid request body |

Example 401 (scope mismatch):
```json
{
  "detail": "Insufficient scope: requires 'vdb:write', token has 'vdb:read'"
}
```

Example 401 (DPoP replay):
```json
{
  "detail": "DPoP proof jti replay detected"
}
```

## DPoP Support

All tokens are DPoP-bound by default. The orchestrator generates an ephemeral EC P-256 keypair at startup and includes a DPoP proof header with every request to MCP servers.

Each MCP server validates the full RFC 9449 proof chain:

1. Proof is signed by the key embedded in the `jwk` header
2. `typ` is `dpop+jwt`, `alg` is `ES256`
3. `htm` matches the HTTP method of the request
4. `htu` matches the request URL (scheme + authority + path)
5. `iat` is within the last 5 minutes (±30s clock skew allowed)
6. `jti` has not been seen before (bounded nonce cache, 10,000 entries)
7. `ath` matches SHA-256 of the access token (when present)
8. `cnf.jkt` in the access token matches the proof's JWK thumbprint (RFC 7638)

## Running Without Docker

For local development, each component can be started independently:

```bash
# Start Qdrant
docker run -p 6333:6333 qdrant/qdrant

# Install and start each MCP server
cd mcp-servers/docs-mcp && pip install -r requirements.txt
DOCS_ROOT=../../sample-docs uvicorn main:app --port 8001

cd mcp-servers/vectordb-mcp && pip install -r requirements.txt
QDRANT_URL=http://localhost:6333 uvicorn main:app --port 8002

cd mcp-servers/ranker-mcp && pip install -r requirements.txt
uvicorn main:app --port 8003

cd mcp-servers/llm-mcp && pip install -r requirements.txt
uvicorn main:app --port 8004

# Run the orchestrator
cd orchestrator && pip install -r requirements.txt
python -m orchestrator.ingest --source ../sample-docs
python -m orchestrator.query "What were the key findings?"
```

## Security Notes

- **Use HTTPS in production.** The MCP servers listen on HTTP by default; place a TLS-terminating reverse proxy in front of them.
- **DPoP is required for sensitive operations.** Tokens are ephemeral (1-hour lifetime) and bound to the orchestrator's keypair. A stolen token cannot be used from another process.
- **LLM and embedding API keys never leave the `llm-mcp` container.** Agents authenticate via JWT; only the MCP server sees raw API credentials.
- **Set a specific audience** (`SDM_AUDIENCE`) in production to prevent token reuse across services.
- **The scope hierarchy is enforced at the authorization server**, not by agent behavior. Even a compromised generator agent cannot acquire `vdb:write` — its token simply lacks the scope.
