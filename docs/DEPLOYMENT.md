# Deploy, upgrade and recover

## Initial install

Run scripts/configure.py with a public HTTPS origin, then docker compose up -d --build. Proxy HTTPS to the loopback HTTP listener. PUBLIC_URL controls new enrollment WebSocket URLs; it is an administrator setting, not a trusted client header. COOKIE_SECURE=true is required in production. Configure a separate private RustDesk server only if remote desktop is wanted.

## Accounts

The first start creates one durable owner account from ADMIN_USER and the configured password/hash. Later starts do not reset that account from environment variables. Existing administrator credentials migrate on first start of the accounts release; previously signed sessions become invalid and users must sign in again. No factor is mandatory until the account confirms its authenticator enrollment. Save recovery codes before ending enrollment.

Create customers and locations, then contacts and customer-bound portal accounts. Assign enrolled devices before end users can see them. Customers cannot claim unassigned devices. Global owners/administrators maintain the fleet. Technicians are global operators; customer administrators/viewers/end users are customer-bound. Do not use a global technician role where customer isolation is required.

## Upgrade

1. Read release notes and stop operator writes during the cutover.
2. Take a consistent SQLite backup, plus the complete data directory including account-encryption.key, settings, attachments and any configured persistent secrets. Retain the previous image and environment privately.
3. Test a restored copy with the candidate image, representative seeded accounts and permission tests. Never test privileged actions against production devices.
4. Recreate only the RMM app. RustDesk services and agents are separate and must not be recreated as collateral changes.
5. Verify HTTPS, administrator sign-in, MFA/recovery on a disposable account, customer isolation, scoped-key reads/revocation and continued device check-ins.

The expansion adds a platform_state table alongside the existing kv/telemetry tables. It preserves enrollment data and RustDesk identity. New MFA/account data is not understood by older releases: simply reverting the image could bypass the new access model. Keep the site in maintenance and restore the matching complete backup for a coordinated rollback; reconcile any new tickets/messages before discarding state.

## External clients

Create one key per agent/profile under Workspace -> Agent API keys. Choose explicit scopes and optional customer IDs. Store the one-time secret directly in the intended agent's secure configuration. Never paste it into a chat. Prefer /api/v1/status as an initial harmless read. Read the live role/scopes and verify expected identity before attempting changes. Revoke old shared keys after migrating integrations.

## Known rollout limits

The support app is an installable browser portal and desktop shortcut, not a native privileged tray service. Existing agents need deliberate updates to receive shortcuts and the new header-only connection behavior. Email/SMS/WhatsApp preferences are recorded but sending adapters are not enabled. AI needs a configured provider key and user consent; no provider test is implied by successful server tests. The hosted CloudMonkey provisioning/billing storefront is a separate integration.

For multiple manually hosted instances, use separate checkout/data directories, Compose project names, generated secrets and distinct loopback RMM_PORT values. Route each HTTPS hostname to its own port. Do not share signing/enrollment/encryption keys or data volumes between instances. Automated CloudMonkey provisioning remains a separate integration.
