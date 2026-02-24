FROM python:3.12-slim

WORKDIR /app

COPY orchestrator/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY orchestrator/ ./orchestrator/

# Default: show usage. Override via docker compose run:
#   docker compose run orchestrator python -m orchestrator.ingest --source /docs
#   docker compose run orchestrator python -m orchestrator.query "your question"
CMD ["python", "-m", "orchestrator.graph"]
