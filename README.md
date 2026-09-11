# Guardian

Guardian is a provider-agnostic AI security analyst agent for SIEM/EDR alerts and logs.

It ingests security alerts, enriches them with context, and returns a structured
verdict — disposition, confidence, reasoning, and recommended actions — so
analysts spend their time on the alerts that matter instead of on triage queues.

Guardian is decision support. It investigates and recommends; it does not take
containment actions.

## Status

Early scaffold. The service runs, supports OpenAI-compatible and native Anthropic
model endpoints, and includes a SentinelOne connector and triage pipeline. The
enrichment tools other than
`search_related_alerts` are stubs awaiting your threat-intel and asset sources.

## How it works

```
SentinelOne  ──poll──┐
                     ├──►  Alert (normalized)  ──►  Analyst agent  ──►  TriageResult
webhook POST  ───────┘                                   │                    │
                                                  enrichment tools        store + API
```

1. **Connectors** (`connectors/`) pull from a security product and normalize
   into `Alert`, Guardian's vendor-neutral schema. Adding a source means writing
   a mapper into that schema and nothing else.
2. **The analyst agent** (`agent/`) investigates in two phases: an agentic tool
   loop that gathers context, then a structured-output call that produces a
   schema-valid `Verdict`. Splitting them keeps every stored disposition
   directly comparable rather than parsed out of prose.
3. **The API** (`api/`) accepts pushed alerts, serves results, and hosts the
   background poller.

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

cp .env.example .env      # set a provider, endpoint, model, model key, and webhook token
guardian                  # or: uvicorn --factory guardian.api.app:create_app --reload
```

Guardian runs without SentinelOne credentials — it just won't poll. Once a model
provider and `GUARDIAN_WEBHOOK_TOKEN` are configured, push an
alert in directly:

```bash
curl -X POST localhost:8000/v1/alerts \
  -H 'Content-Type: application/json' \
  -H "X-Guardian-Token: $GUARDIAN_WEBHOOK_TOKEN" \
  -d '{
    "source": "manual",
    "title": "Suspicious PowerShell execution",
    "severity": "high",
    "host": {"hostname": "WIN-FIN-0427"},
    "process": {
      "name": "powershell.exe",
      "command_line": "powershell -enc SQBFAFgA..."
    }
  }'
```

Or post a raw SentinelOne threat object and let Guardian normalize it:

```bash
curl -X POST localhost:8000/v1/alerts/sentinelone \
  -H 'Content-Type: application/json' \
  -H "X-Guardian-Token: $GUARDIAN_WEBHOOK_TOKEN" \
  -d @samples/sentinelone_threat.json
```

## API

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/healthz` | Liveness and configuration check |
| `POST` | `/v1/alerts` | Triage an alert in Guardian's schema |
| `POST` | `/v1/alerts/sentinelone` | Triage a raw SentinelOne threat object |
| `GET` | `/v1/triage` | Recent triage results (newest first) |
| `GET` | `/v1/triage/{alert_id}` | One triage result |
| `POST` | `/v1/poll` | Run a SentinelOne poll cycle now |

Every endpoint except `/healthz` requires the `X-Guardian-Token` header. Reads
are authenticated too: a `TriageResult` embeds the original vendor payload,
including host, user, process, and indicator data.

Interactive docs at `/docs` while the service is running.

Guardian **refuses to start** without `GUARDIAN_WEBHOOK_TOKEN` set, so an unconfigured deployment
fails closed rather than accepting anonymous alerts. For local development,
`GUARDIAN_ALLOW_UNAUTHENTICATED=true` opts out explicitly.

## Configuration

The model provider is deliberately not defaulted. Set all of `GUARDIAN_PROVIDER`,
`GUARDIAN_BASE_URL`, and `GUARDIAN_MODEL` for a deployment. The example file uses
Neuralwatt and GLM 5.3 Flash as one possible OpenAI-compatible configuration.

All settings are environment variables prefixed `GUARDIAN_`, or a `.env` file.
See `.env.example`. Set `GUARDIAN_API_KEY` for OpenAI-compatible providers. Native Anthropic also accepts
`ANTHROPIC_API_KEY` (or an `ant auth login` profile) directly.

| Variable | Default | Purpose |
| --- | --- | --- |
| `GUARDIAN_PROVIDER` | — | `openai` for OpenAI-compatible APIs or `anthropic` for native Messages APIs (required) |
| `GUARDIAN_BASE_URL` | — | Provider base URL (required; e.g. `https://api.neuralwatt.com/v1`) |
| `GUARDIAN_API_KEY` | — | Generic provider API key; use `ANTHROPIC_API_KEY` for native Anthropic |
| `GUARDIAN_MODEL` | — | Provider model ID (required; e.g. `glm-5.3-flash`) |
| `GUARDIAN_EFFORT` | `high` | Thinking effort where supported: `low`–`max` |
| `GUARDIAN_S1_BASE_URL` | — | SentinelOne console URL |
| `GUARDIAN_S1_API_TOKEN` | — | SentinelOne API token |
| `GUARDIAN_S1_POLL_INTERVAL` | `60` | Seconds between polls |
| `GUARDIAN_S1_POLL_ENABLED` | `true` | Disable to run webhook-only |
| `GUARDIAN_WEBHOOK_TOKEN` | — | Shared secret for write endpoints (required) |
| `GUARDIAN_ALLOW_UNAUTHENTICATED` | `false` | Dev-only opt-out of the above |

## Development

```bash
pytest              # 83 tests, no API calls — the analyst is stubbed
ruff check src tests
ruff format src tests
```

## Extending Guardian

**Add a connector.** Implement the `Connector` protocol in
`connectors/base.py` — `fetch_since`, `normalize`, `aclose` — and map the
vendor's payload into `Alert`. `connectors/sentinelone.py` is the worked
example; keep the mapper defensive, since vendor payloads vary by agent version.

**Connect enrichment.** `agent/tools.py` has four tools. `search_related_alerts`
is live against Guardian's own store; the other three return an explicit
`NOT_CONFIGURED` marker that tells the model to treat the indicator as unknown
rather than benign. Replace each `TODO` body with a real call and the agent's
confidence improves without any prompt changes.

**Persist results.** `store.py` is in-memory and bounded, so results are lost on
restart. Implement the same four methods against a real database and swap it in
`api/app.py`.

## Design notes

- **Refusals are surfaced, never silently swallowed.** Alert content — malware
  names, attacker command lines — is exactly what the configured model's safety classifiers
  may decline. Both triage phases check for `stop_reason == "refusal"` and mark
  the result `refused` for human review. The investigation phase also enables
  server-side fallbacks, which re-runs a declined request on a fallback model
  within the same call.
- **The system prompt is a frozen constant** so it forms a stable, cacheable
  prefix across every alert. Per-alert data goes in `messages`, never
  interpolated into the prompt.
- **The agent is told to prefer `needs_human_review` over a confident guess.**
  A hedged accurate verdict is worth more to a SOC than a confident wrong one.
