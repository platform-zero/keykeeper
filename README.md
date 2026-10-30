# Keykeeper v3

Fresh, **not yet usable** OpenBao-backed credential manager. Current source is only a tested authorization domain; there is no login, HTTP server, CLI, UI, OpenBao adapter or real secret release. Do not install or use with real credentials yet.

The first release needs a simple web vault plus CLI. Keycloak provides distinct human and agent identities; both have **the same rights and features** under a common grant policy. A user can explicitly share a credential with another human or agent; a granted agent can read the value via the API/CLI. OpenBao holds values; the Keykeeper service owns authorization and audit. Do not copy the old P0 Keykeeper code or its unfinished approval system. Browser extension, Android app and TOTP are out of scope.

Run unit tests with Java 21: `./gradlew test`. The independent `../acceptance` repo must prove actual web, CLI, SSO, and restored-credential workflows before any release claim.
