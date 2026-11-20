# Architecture

One Go HTTP service serves the operator console, scoped management API and support portal. SQLite WAL holds the original device/telemetry state and a separate versioned expansion state record containing accounts, sessions, directory records, assignments, support tickets, scoped keys and consented diagnostic requests. Private attachment files live under the same protected data directory. A separate AES-GCM key protects authenticator seeds.

Human authentication -> live session/account validation -> per-route role/scope checks -> customer/device ownership checks -> operation -> durable state and audit. Global operators use the existing fleet console; scoped keys and customer users cannot fall back to the unrestricted legacy API. The new portal uses the same authorization functions as external clients.

End-user request -> consent -> typed diagnostic queue -> different authorized operator approval -> fixed OS-specific command -> existing authenticated agent connection -> normal job results. No user-controlled shell string appears in this path. AI support can append advisory messages only, never approve or execute jobs.

The user-facing portal has no device master secret or local privileged listener. Desktop links contain only the HTTPS portal address. User login and server-side device assignment control what each person can see. Headless monitoring continues independently.

Self-hosted: domain -> HTTPS proxy -> PulseRMM -> persistent state. Managed CloudMonkey instances should use isolated data volumes, signing/enrollment/encryption secrets and customer boundaries per instance; provisioning and billing are outside the RMM itself.
