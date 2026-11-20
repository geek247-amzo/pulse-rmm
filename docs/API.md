> Legacy compatibility API. Use docs/MANAGEMENT-API.md and /openapi-v1.json for scoped per-agent integrations and customer-aware management.

# PulseRMM API

The deployed API is described by [OpenAPI 3.1](../server/static/openapi.yaml) and indexed at `GET /api`. Current paths use the `/api` prefix; no breaking `/api/v1` namespace has been introduced yet.

## Authentication

Dashboard login at `POST /api/login` returns a short-lived JWT and an HttpOnly, SameSite=Strict cookie. Dashboard API requests use the bearer JWT. Service clients send `Authorization: Bearer $HERMES_API_TOKEN`. The service token is exchanged internally for a short-lived JWT and currently has administrator-equivalent privileges. There are no per-route scopes today.

All API endpoints except `/api`, `/api/info`, login/logout, and the enrollment-configured binary download require authentication as documented. Use HTTPS; bearer tokens and the session cookie are credentials.

## Example

```sh
export PULSERMM_URL='https://rmm.example.internal'
curl --fail --silent --show-error \
  -H "Authorization: Bearer $HERMES_API_TOKEN" \
  "$PULSERMM_URL/api/devices"
```

## Endpoints

- `GET /api/devices` — current fleet and latest telemetry.
- `GET /api/devices/{device_id}?range=1h|3h|24h|1w|1m` — device details, resource history, jobs, maintenance.
- `GET /api/devices/{device_id}/logs?hours=24&limit=100` — recent endpoint logs.
- `POST /api/devices/{device_id}/analyze` — explicit AI triage request; selected logs/telemetry leave the server for the configured provider.
- `POST /api/enrollment-token` — authenticated one-time token minting for supported OS/architecture. `DELETE /api/enrollment-token` revokes an unused token. Required by `GET /downloads/get` to retrieve an agent binary.
- `GET /api/jobs?device_id=...`, `GET /api/audit` — job and audit inspection.
- `POST /api/command` — queue an OS command for an online agent. Commands are audit logged and run with the agent process's OS permissions.
- `GET|POST /api/alerts`, `GET|POST /api/maintenance` — fleet policies and coordination windows.
- `POST /api/support-session` — audited RustDesk handoff record; it does not itself create a desktop session.
- `GET|PUT /api/settings`, `GET /api/settings/openai/models` — integration settings and model discovery. OpenAI secrets are write-only and settings are administrator-only.

Use endpoint status codes and response bodies as described by OpenAPI. IDs in path segments must be URL encoded by clients.


## Administrator-managed API keys

In Settings → API keys, an administrator can create a named key with a 7, 30, 90, 180, or 365 day expiry (90 days is the default). The plaintext secret is returned once and cannot be retrieved later. Only its SHA-256 hash and a short display prefix are persisted. Keys can be revoked immediately from Settings or via `DELETE /api/admin/api-keys/{id}`.

These keys authenticate to the operational API with administrator-equivalent device access, including command dispatch. They cannot create or revoke other API keys or change platform settings; those management endpoints require the administrator's browser session. The existing `HERMES_API_TOKEN` remains supported for compatibility and keeps its current broad privileges. Store issued keys in a secret manager and transmit them only over HTTPS.
