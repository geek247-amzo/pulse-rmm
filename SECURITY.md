# Security policy

Report security issues privately through GitHub private vulnerability reporting when enabled; otherwise contact the repository owner privately. Do not post tokens, enrolled device identities, session cookies, user records or device logs in public issues.

## Authentication and authorization

Human accounts use password hashes and persisted, revocable opaque sessions. Sessions expire after 24 hours or two hours of inactivity. Authenticator setup must be confirmed before MFA becomes active. TOTP seeds use AES-GCM with a separate persisted key; recovery codes are hashed, single use and displayed once. Authentication is throttled. Keep offline account recovery material private.

New service keys are hash-only, individually scoped, optionally customer-restricted and expiring. Empty customer restrictions mean explicitly global access; an empty scope list cannot be issued. Customer accounts and scoped keys cannot enter the unrestricted legacy operational API. Legacy service credentials remain broad for compatibility and cannot access new customer/support APIs. Migrate and revoke them deliberately. Never give an end-user app an operator key.

Cookie mutations require a custom CSRF header; sessions are HttpOnly and SameSite=Strict. Set COOKIE_SECURE=true behind HTTPS. The legacy fleet console still keeps its bearer session in browser local storage; avoid untrusted extensions/shared browser profiles. The new management/support portal uses the secure session cookie.

## Device control

Existing global operators and legacy credentials can dispatch OS commands with the enrolled agent's OS rights. This is powerful administrative access. The end-user portal offers only named diagnostic requests, requires consent, and needs a different authorized operator to approve execution. AI advice cannot dispatch commands. Treat logs, messages and screenshots as untrusted.

New agents use encrypted WebSockets when PUBLIC_URL is HTTPS and put credentials in headers, not URL query strings. Existing enrolled agents may still use old transport until explicitly updated. No forced agent update or command is dispatched by a server upgrade.

Attachments are private, bounded and served only as authenticated downloads. They are not antivirus-scanned: use caution with downloaded PDFs/files. AI support sends visible ticket text only after explicit consent and never sends attachments automatically. In-app notifications work without external messaging providers.

## Deployment

Expose HTTPS via a trusted reverse proxy; keep the HTTP listener on loopback/private networks. Use TLS or a protected tunnel for an upstream hop crossing an untrusted network. Back up the entire private data directory and encryption key under restricted access. Runtime state, generated configuration, customer data and private keys must never enter Git or public releases. Run tests and verify migrations on a copy before upgrading. Cross-compilation is not a real Windows/macOS/Linux end-user test.

Release verification with govulncheck on Go 1.27.4 found no vulnerabilities affecting reachable code or imported packages. It reported 23 advisories in required modules outside the used call paths; this is not a claim that all dependency versions have no advisories. Dependency modernization remains scheduled work.
