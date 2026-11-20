# 0.2.0 verification

Verified 2026-11-20 with Go 1.27.4.

- 26 server test cases, agent package compilation and go vet passed.
- Two setup-script tests passed: private unique configuration, no overwrite and insecure-origin rejection.
- govulncheck found no affected reachable code or imported packages. It reported 23 advisories in required modules outside the used code paths; this is not a claim of advisory-free dependencies.
- Linux amd64/arm64, Windows amd64 and macOS amd64/arm64 agent binaries cross-compiled. Real Windows/macOS endpoint installation, OS signing and native tray behavior were not verified.
- Chrome synthetic workflow passed: customer/location/contact/account creation, device assignment, request/reply UI, private attachment, separate diagnostic approval and simulated job completion.
- Chrome MFA enrollment, required second-factor login, one-use recovery login, scoped key issuance/legacy-route denial/revocation and second-customer isolation passed.
- The release image passed a network-isolated migration check against a protected database copy, preserving the existing owner and enrollment/key records.
- Live HTTPS discovery/pages/API contract return 200; unauthenticated management returns 401. Production integration tests did not send device commands or customer content to AI.

Synthetic screenshots and browser scripts are included. Fixture credentials exist only in test scripts and must never be used in a real deployment. The browser workflow runs against a disposable instance with no mounted production data.

A normal HTTPS model-discovery request and an actual AI support request using only synthetic text returned HTTP 200. The AI test ran in a disposable instance without customer/device data; temporary state and verification sessions were removed. No production support conversation was sent.
