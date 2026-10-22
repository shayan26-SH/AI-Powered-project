# SOC Alert Triage MVP

A local, defensive SOC workflow prototype for reviewing synthetic security events. It groups related events, calculates an explainable heuristic risk score, retrieves relevant references from a small local MITRE ATT&CK knowledge file, and allows analysts to approve **simulated-only** response actions.

This is an educational MVP, not a production SIEM or an autonomous response system. It has no LLM, external service, firewall integration, process control, or real-host isolation. Its “AI triage” foundation is deliberately transparent and deterministic; an LLM can be added later behind the same evidence-first boundary and separately evaluated.

## Requirements

- Python 3.10 or newer
- No third-party packages

## Run locally

From the repository root:

```powershell
python -m soc_triage
```

Open <http://127.0.0.1:8000>. The first run creates `data/soc_triage.db` and seeds clearly labeled synthetic demo events. Stop the server with Ctrl+C.

By default, the server binds only to `127.0.0.1`. To use another local port:

```powershell
$env:SOC_TRIAGE_PORT = "8080"
python -m soc_triage
```

The SQLite database is local application state and can be removed manually when you want to reset the demo. Do not place sensitive or production telemetry in this prototype.

## What works

- Dashboard with incident list, risk score, heuristic classification, ATT&CK context, and source-event evidence.
- Local JSON API for incident retrieval and event ingestion.
- Correlation by source address and rule category within a 15-minute window.
- Input validation, event provenance, duplicate detection, and persisted audit history.
- Two-step response workflow: request an action, then explicitly approve it.
- Simulation-only `isolate_host` and `block_source` actions. Isolation applies only to the preconfigured mock lab assets; source blocking accepts only RFC 5737 documentation-range IPv4 addresses. No operating-system or network changes are made.

## API

- `GET /api/health` — process health.
- `GET /api/incidents` — incident summaries.
- `GET /api/incidents/{incident_id}` — incident, supporting events, and related knowledge.
- `GET /api/assets` — mock asset state.
- `GET /api/audit` — recent response audit entries.
- `POST /api/events` — ingest `{"events":[...]}` (up to 500 events per request).
- `POST /api/incidents/{incident_id}/response-requests` — request a simulation with `{"action":"isolate_host"}` or `{"action":"block_source"}`.
- `POST /api/response-requests/{request_id}/approve` — approve and apply a pending simulation.

Example event:

```json
{
  "event_id": "demo-auth-004",
  "timestamp": "2026-10-21T12:00:00Z",
  "source_ip": "198.51.100.42",
  "asset_id": "lab-workstation-01",
  "event_type": "authentication_failure",
  "severity": 7,
  "description": "Repeated failed sign-in attempts for a synthetic account"
}
```

Input `source_ip` values must be in the documentation-only ranges `192.0.2.0/24`, `198.51.100.0/24`, or `203.0.113.0/24`. `asset_id` must name one of the configured `lab-*` mock assets. These restrictions are intentional.

## Testing

```powershell
python -m unittest discover -s tests -v
```

## Triage logic and limitations

Classification uses explicit event-type rules; risk is a heuristic score based on maximum input severity and event count. Neither risk nor the displayed rule-match confidence is a calibrated probability. Retrieval is a small category-based lookup over bundled, source-attributed MITRE ATT&CK references, not a general vector database or live threat-intelligence feed. The entries are brief pointers, not a complete or continuously updated knowledge base.

For a course extension, consider importing a licensed dataset with a documented field mapping, adding time-window and retrieval evaluations, and comparing a locally hosted language model against this deterministic baseline. Preserve event IDs and citations in generated claims, test for unsupported output, and keep response execution simulated unless a separately reviewed, isolated lab is explicitly designed.
