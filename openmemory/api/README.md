# OpenMemory API

This directory contains the backend API for OpenMemory, built with FastAPI and SQLAlchemy. This also runs the Mem0 MCP Server that you can use with MCP clients to remember things.

## Quick Start with Docker (Recommended)

The easiest way to get started is using Docker. Make sure you have Docker and Docker Compose installed.

1. Build the containers:
```bash
make build
```

2. Create `.env` file:
```bash
make env
```

Once you run this command, edit the file `api/.env` and enter the `OPENAI_API_KEY`.

3. Start the services:
```bash
make up
```

The API will be available at `http://localhost:8765`

The Compose deployment stores SQLite in the Docker-managed `openmemory_db`
volume rather than the host bind mount. This keeps SQLite's WAL files inside
the VM filesystem and avoids host-side read-only tooling sharing its locks.

### Common Docker Commands

- View logs: `make logs`
- Open shell in container: `make shell`
- Run database migrations: `make migrate`
- Run tests: `make test`
- Run tests and clean up: `make test-clean`
- Stop containers: `make down`

## API Documentation

Once the server is running, you can access the API documentation at:
- Swagger UI: `http://localhost:8765/docs`
- ReDoc: `http://localhost:8765/redoc`

## Memory Behavior

The MCP `search_memory` tool accepts `query`, `top_k`, and optional `mark_used` arguments:

- `top_k` requests between 1 and 50 results; values outside that range are clamped.
- `mark_used` accepts memory IDs from the immediately preceding search for the same user and client. Accepted IDs are recorded as usage feedback; invalid or unrelated IDs are ignored.
- Search results contain `id`, `memory`, `hash`, `created_at`, `updated_at`, and `score`.

REST writes return a stable rejection body when no memory is accepted:

```json
{"accepted": 0, "reason": "no_facts_extracted"}
```

Possible rejection reasons are `client_unavailable`, `malformed_sdk_response`,
`no_facts_extracted`, `non_add_events`, and `extraction_error`.

Each MCP search also appends one owner-only JSONL record. Set
`OPENMEMORY_SEARCH_LOG` to change the path; the default is
`/usr/src/openmemory/data/search-log.jsonl`. Records include the query, result
count, latency, top score, and count of dropped usage IDs. Search logging is
best-effort and does not fail a search.

Relative score cutoffs are opt-in with `OPENMEMORY_CUTOFF=on`. When enabled,
`OPENMEMORY_SELF_LEARNING=off` disables file-based overrides and restores the
defaults (`k=1.0`, `delta=0.02`). Overrides loaded from
`OPENMEMORY_PARAMS_FILE` are clamped to `k=0.5..3.0` and `delta=0.02..0.20`;
the default path is `/usr/src/openmemory/data/retrieval-params.json`.

## Project Structure

- `app/`: Main application code
  - `models.py`: Database models
  - `database.py`: Database configuration
  - `routers/`: API route handlers
- `migrations/`: Database migration files
- `tests/`: Test files
- `alembic/`: Alembic migration configuration
- `main.py`: Application entry point

## Development Guidelines

- Follow PEP 8 style guide
- Use type hints
- Write tests for new features
- Update documentation when making changes
- Run migrations for database changes
