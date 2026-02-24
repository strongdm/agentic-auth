"""LLM gateway MCP server.

Provides JWT-authenticated access to LLM APIs (Claude, OpenAI).
Scope: llm:call

This server acts as a controlled gateway — agents never hold raw API keys.
The LLM credentials live only in this server's environment.
"""

import os

import anthropic
from fastapi import Depends, FastAPI
from pydantic import BaseModel

import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from shared.auth import audit_log, require_scope

app = FastAPI(title="llm-mcp", description="LLM gateway for RAG pipeline")

# LLM configuration — credentials stay in this server only
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
DEFAULT_MODEL = os.environ.get("DEFAULT_MODEL", "claude-sonnet-4-6-20250514")


@app.get("/health")
async def health():
    """Readiness probe."""
    has_anthropic = bool(ANTHROPIC_API_KEY)
    has_openai = bool(OPENAI_API_KEY)
    return {
        "status": "ok" if (has_anthropic or has_openai) else "no_credentials",
        "anthropic": has_anthropic,
        "openai": has_openai,
    }


class GenerateRequest(BaseModel):
    query: str
    context: str
    system_prompt: str = "You are a helpful assistant."
    max_tokens: int = 2048
    model: str | None = None


@app.post("/tools/generate")
async def generate(
    req: GenerateRequest, claims: dict = Depends(require_scope("llm:call"))
):
    """Generate a response using an LLM.

    The agent's JWT proves its identity, but it never sees the LLM API key.
    Rate limiting and cost tracking can be applied per-agent using the
    JWT 'sub' claim.
    """
    model = req.model or DEFAULT_MODEL
    caller = claims["sub"]

    try:
        client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
        message = client.messages.create(
            model=model,
            max_tokens=req.max_tokens,
            system=req.system_prompt,
            messages=[
                {
                    "role": "user",
                    "content": f"Context:\n{req.context}\n\nQuestion: {req.query}",
                }
            ],
        )

        text = message.content[0].text if message.content else ""

        audit_log(
            "llm-mcp",
            "/tools/generate",
            claims,
            model=model,
            input_tokens=message.usage.input_tokens,
            output_tokens=message.usage.output_tokens,
        )

        return {
            "text": text,
            "model": model,
            "usage": {
                "input_tokens": message.usage.input_tokens,
                "output_tokens": message.usage.output_tokens,
            },
            "caller": caller,
        }

    except Exception as e:
        audit_log("llm-mcp", "/tools/generate", claims, error=str(e))
        return {"error": str(e), "caller": caller}


class EmbedRequest(BaseModel):
    texts: list[str]
    model: str = "text-embedding-3-large"


@app.post("/tools/embed")
async def embed(req: EmbedRequest, claims: dict = Depends(require_scope("llm:call"))):
    """Generate embeddings for a list of texts.

    Uses OpenAI's embedding API (Anthropic doesn't offer embeddings yet).
    The OpenAI API key is held only by this server.
    """
    try:
        import openai

        client = openai.OpenAI(api_key=OPENAI_API_KEY)
        response = client.embeddings.create(input=req.texts, model=req.model)

        embeddings = [item.embedding for item in response.data]

        audit_log(
            "llm-mcp",
            "/tools/embed",
            claims,
            model=req.model,
            texts_count=len(req.texts),
        )

        return {
            "embeddings": embeddings,
            "model": req.model,
            "count": len(embeddings),
            "caller": claims["sub"],
        }

    except Exception as e:
        audit_log("llm-mcp", "/tools/embed", claims, error=str(e))
        return {"error": str(e), "caller": claims["sub"]}
