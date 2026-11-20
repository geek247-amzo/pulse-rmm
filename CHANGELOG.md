# Release notes

## 0.2.0 — accounts and support workspace

- Durable account management with global operator and customer-bound roles.
- Authenticator-app MFA, encrypted seeds, one-use recovery codes and persisted/revocable idle-expiring sessions.
- Customer/location/contact directory and explicit device/end-user assignment.
- Support tickets, messages/internal notes, bounded private attachments and in-app notification timeline.
- Consent-based AI advice using the configured OpenAI provider, with a usable human-support fallback.
- Named basic diagnostics with separate operator approval; no shell input in the end-user flow.
- Separate scoped/expiring API credentials with optional customer restrictions; legacy broad keys do not gain access to the new API.
- Support PWA/desktop links and header-only agent credentials in updated binaries; legacy enrolled devices preserved.
- Public source/deployment examples, upgrade/security documentation and CI.

Upgrade requires a complete protected backup and fresh browser login. The initial owner is migrated from existing admin configuration. MFA enrollment/recovery is a local owner action, not automatically completed by deployment. Native tray software, external notification providers and hosted-instance provisioning are not included in this release.
