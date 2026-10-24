# Observable Incident Triage Agent (GA5 v2)

This is a FastAPI starter for the provided `ga5-incident-agent/v2` contract. It includes the three required endpoints, SQLite-backed idempotency and state, a single OpenAI-compatible planning call for a first-seen run, receipt-driven retries/approval/effect dispatch, and an OTLP JSON trace that avoids exporting transcript text, sensitive fields, tool arguments, and tool results.

**Important:** the screenshots describe a strict, grader-specific contract. Treat this as a working starting point, not a claim that it has already earned 4/4. Use the grader's first feedback to adjust any tool-specific `resultClass` assumptions or exact response fields before using the final Save.

## Run locally

```bash
python -m venv .venv
# Windows PowerShell:
.\.venv\Scripts\Activate.ps1
# macOS/Linux:
# source .venv/bin/activate
pip install -r requirements.txt
copy .env.example .env   # Windows; edit the values and export them to the process
uvicorn main:app --host 0.0.0.0 --port 8000
```

Set these environment variables in your terminal or hosting provider:

- `MODEL_BASE_URL`: OpenAI-compatible endpoint root (the app adds `/chat/completions`).
- `MODEL_API_KEY`: provider key, stored only in environment variables, never in source control.
- `MODEL_NAME`: a low-latency model that can return JSON reliably.
- `MODEL_TIMEOUT_SECONDS`: keep at or below the grader's per-request timeout (default 12.5).
- `DATABASE_PATH`: writable SQLite path. For hosted deployment, use the provider's persistent volume if available.

Check `/healthz` without consuming a grader check. The required routes are exactly:

- `POST /v2/incidents`
- `POST /v2/incidents/{runId}/receipts`
- `GET /v2/incidents/{runId}`

Do not add trailing slash redirects to these routes. Do not set credentials in the public base URL. Do not commit `.env` or provider keys.

## Before using a grader Check

1. Deploy and ensure the base URL uses HTTPS and routes do not redirect.
2. Confirm `POST /v2/incidents` returns JSON within 18 seconds and the service remains warm.
3. Confirm SQLite writes persist between requests and deploys, if your hosting provider supports a volume.
4. Test that re-posting the identical incident returns the original JSON; changing content for an existing `runId` returns 409.
5. Test identical receipt replay and changed-content conflict for a `receiptId`.
6. Inspect the final `GET` state and OTLP trace for matching dispatches/receipts and no sensitive or transcript content.

The grader's `Check` calls may each test multiple personalized incidents. Keep one of the ten operations for the final **Save**; only the latest Save counts.
