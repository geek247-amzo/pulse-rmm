# Management API v1

Base URL: `https://YOUR_DOMAIN/api/v1`. Use normal hostname/certificate validation. No redirect or insecure TLS workaround is part of onboarding. The public hosted instance uses `https://pulse.seunarain.co.za/api/v1`.

## Authentication

Create one named key per external agent/profile at `/manage.html` -> Agent API keys. Send `Authorization: Bearer $PULSERMM_API_KEY`. Keys are shown once, hash-stored, expire in 1–365 days and revoke immediately. Explicit scopes are required; optional customer IDs restrict object access. An empty customer restriction deliberately grants the selected scopes across all customers. Service keys cannot manage human accounts or issue/revoke keys.

First verify `GET /status` and compare the returned identity/scopes with the intended profile. Presence of an environment variable is not proof of identity. Never fall back to a different profile's or a shared token. Keys issued through the old `/api/admin/api-keys` UI remain legacy broad credentials; new issuance there is disabled. They do not gain access to this expanded API.

```sh
curl --fail --silent --show-error \
  -H "Authorization: Bearer $PULSERMM_API_KEY" \
  https://YOUR_DOMAIN/api/v1/status
```

Human sessions use `/api/login` with JSON `username`, `password`, and `otp` when enrolled. Responses include a session cookie and bearer token for the legacy console. Cookie-based mutations require `X-Pulse-CSRF: 1`. Session/credential secrets never appear in resource views. `/api/logout` revokes the current session. Login attempts are throttled.

## Resource routes

| Route | Methods | Purpose |
|---|---|---|
| `/status` | GET | Identity, role and configured scope names |
| `/users` | GET, POST | Human administrator account list/create |
| `/users/{id}` | PUT | Human administrator account edit/disable/password reset; owner protections apply |
| `/keys` | GET, POST | Human administrator scoped key list/create |
| `/keys/{id}` | DELETE | Human administrator key revocation |
| `/customers` | GET, POST | Customer list/create |
| `/customers/{id}` | GET, PUT | Customer view/edit/archive |
| `/locations` | GET, POST | Customer-linked locations |
| `/locations/{id}` | GET, PUT | Location view/edit/archive |
| `/contacts` | GET, POST | Customer-linked people and communication preferences |
| `/contacts/{id}` | GET, PUT | Contact view/edit/archive |
| `/devices` or `/devices/{id}` | GET | Visible device telemetry plus assignment; collection-shaped JSON |
| `/assignments` | GET | Visible assignments |
| `/assignments/{device_id}` | PUT | Customer/location/contact/portal-user assignment |
| `/tickets` | GET, POST | Visible requests/list/create |
| `/tickets/{id}` | GET, PUT | Read/update request status/assignee |
| `/tickets/{id}/messages` | POST | Visible reply or authorized technician internal note |
| `/tickets/{id}/files` | GET, POST | Private attachment list/upload |
| `/tickets/{id}/files/{file_id}` | GET | Authorized attachment download |
| `/tickets/{id}/assist` | POST | Explicit consent-based AI advice; no command execution |
| `/actions` | GET, POST | Consent-based allowlisted diagnostic requests |
| `/actions/{id}/approve` | POST | Different authorized operator approves and dispatches once |
| `/jobs` | GET | Visible job results; end users see only diagnostics requested by them |
| `/notifications` | GET | Current user's in-app support updates |

Collections are JSON arrays. GET-with-id directory/ticket/device views retain array shape; an inaccessible directory/ticket has no visible entries, while a device returns 404. Do not infer an inaccessible object's existence from an empty result. Collection pagination, signed outbound webhooks and external email/SMS providers are future work; use bounded deployment/fleet sizes meanwhile.

## Payloads

Customer/location/contact records accept: `name`, `customer_id`, `location_id`, `email`, `phone`, `address`, `timezone`, `preferred_channel`, `communication_methods`, `notification_consent`, `active`. Locations require an active customer; contact locations must be in the same customer. Contact methods: `in_app`, `email`, `phone`, `sms`, `whatsapp`. Actual external sending adapters are not enabled. Referenced device assignments must be changed before a related record can be archived.

Users: `username`, `email`, `role`, `customer_id`, `active`, `password`. Roles: `owner`, `admin`, `technician` (global); `customer_admin`, `viewer`, `end_user` (require a customer). Create passwords are required, 14–72 characters; edit can leave password blank to retain it. Account edits revoke that user's sessions. Owners cannot disable/demote/rename themselves through the management endpoint. Administrators cannot change owner accounts. Password reset does not reset an enrolled second factor.

Scoped keys: `name`, `scopes` (nonempty array), `customers` (array, empty = all), `days` (1–365). The plaintext `key` appears only in the successful create response; subsequent views contain a short prefix and metadata. Do not automatically repeat an uncertain key-creation POST; inspect the key list and revoke/reissue if needed.

Assignments: `customer_id`, `location_id`, `contact_id`, `user_id`; the path identifies the enrolled device. Account/contact/location must match the assigned customer. Only global operators can initially claim unassigned devices.

Tickets: `subject`, `body`, `device_id`, `customer_id`, `priority` (`low|normal|high|urgent`). Device assignment determines customer where present. Updates: `status` (`open|in_progress|waiting_on_user|resolved|closed`), `assignee` (active global operator account ID). Messages: `body`, `internal` (boolean). Internal notes are not returned to customer users.

Files: multipart fields `file` and `consent=true`; max 2 MiB, five files per request. Accepted types: PNG, JPEG, WebP, PDF, plain UTF-8 text. Downloads use attachment disposition and are not executed/previewed. There is no antivirus scanning service; never open untrusted attachments casually. Attachments are never automatically sent to AI.

AI assistance: `{ "consent": true }`. Sends only the last bounded visible conversation text to the configured OpenAI provider. Without a configured provider it returns 503 and leaves the human ticket intact. No diagnostic logs, attachments or secret values are attached automatically.

Diagnostic request: `device_id`, `kind` (`system-info|storage-check|network-check`), `consent=true`. A different authorized operator needs `jobs.approve`, `jobs.execute` and `diagnostics.run` to dispatch. Requests expire after 24 hours; a processed request cannot be replayed. Commands are fixed server-side and never accept arbitrary shell input. New agents impose a 60-second timeout and bounded output. A delivery-uncertain request is not automatically retried: reconcile the associated job first.

## Account self-service routes (outside v1)

- `GET /api/account/me`, `GET /api/account/sessions`.
- `POST /api/account/mfa/setup`: current `password`; returns enrollment secret/URI only to that authenticated account.
- `POST /api/account/mfa/confirm`: current `password`, current `otp`; returns recovery codes once.
- `POST /api/account/mfa/disable`: current `password` plus authenticator/recovery `otp`.
- `POST /api/account/password`: current `password`, `new_password`, and `otp` when MFA is enabled; invalidates all sessions.
- `POST /api/account/logout-all`: current `password` and `otp` when enabled.

Codes are time-based six-digit TOTP with 30-second intervals. A successfully used time step cannot be replayed; wait for a new code before another protected action. Recovery codes are one-use and must be stored privately. No API key can enroll/reset a human factor.

## Authority and retries

A valid key is not owner authority to perform an action. Read current target state and live grants first. GET is read-only; do not blindly retry uncertain mutations, sends or dispatches. Every changed device/request/user is checked against the caller's role and customer/device restrictions. New unknown scopes are rejected. Existing legacy fleet commands remain powerful and are for separately authorized global operators only.

See `/openapi-v1.json` for the machine-readable route contract. OpenAPI specifies the route/method/security surface; the payload fields and rollout limits above remain part of the contract.
