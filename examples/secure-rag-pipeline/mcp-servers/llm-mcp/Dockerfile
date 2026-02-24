FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN pip install --no-cache-dir \
    fastapi>=0.110.0 \
    uvicorn>=0.29.0 \
    PyJWT>=2.8.0 \
    cryptography>=42.0.0 \
    anthropic>=0.40.0 \
    openai>=1.30.0

COPY mcp-servers/shared/ ./shared/
COPY mcp-servers/llm-mcp/ ./llm-mcp/

CMD ["uvicorn", "llm-mcp.main:app", "--host", "0.0.0.0", "--port", "8000"]
