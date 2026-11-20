# Third-party notices

PulseRMM source is licensed under Apache-2.0. Dependencies retain their own licenses; Apache-2.0 does not relicense third-party works. Go module versions and checksums are recorded in server/go.mod and server/go.sum. Review module license files when redistributing dependency source or binaries.

Direct dependencies include Gorilla WebSocket (BSD-2-Clause), golang.org/x/crypto and golang.org/x/sys (BSD-3-Clause), gopsutil (BSD-3-Clause), and modernc SQLite (see the individual module and its transitive dependency license files). The UI's legacy icon font is loaded from cdnjs; Font Awesome Free has separate font/icon/code licenses. See https://fontawesome.com/license/free.

RustDesk is a separate project licensed under AGPL-3.0; see https://github.com/rustdesk/rustdesk and its license. No RustDesk installer, service private key or RustDesk database is included in this public source/release. Optional setup obtains pinned official upstream artifacts at runtime. Distribution or modification of RustDesk carries its own obligations; users should obtain corresponding source from the upstream release.

Docker build images and operating-system packages retain their upstream licenses. The release does not convey trademarks or imply upstream endorsement.
