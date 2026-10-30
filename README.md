# Keykeeper v3 — LOCAL/TEST-ONLY vertical slice

A Kotlin/JDK 21 loopback web vault and CLI with an OpenBao KV-v2 adapter and an injectable, production-oriented OIDC/JWT verifier. **Not a production vault or verified SSO integration. Do not use real credentials.** No old P0 code, deployment or external service changes are included.

## What works

- `Vault` checks a *verified* `(issuer, subject, kind)` for every list/read/create/edit/share/revoke. Humans and agents have exactly the same authorization and operations. READ controls discovery and release; EDIT replaces values; SHARE delegates only rights held by the actor, and can revoke a grant. Revocation is checked on every request (not against a cached session).
- `IdentityVerifier` is the SSO injection boundary. `OidcIdentityVerifier` verifies **RS256 access JWTs** against an operator-pinned JWKS source: exact HTTPS issuer, audience (string or array), signature and unique RSA `kid` (2048–4096 bits), `exp`, `nbf`, `iat`, maximum one-hour token lifetime and a nonempty `jti`. It requires both an `azp` in a pinned client-to-kind map **and** a matching signed `keykeeper_principal_type` (HUMAN/AGENT). Configure the latter as an **admin-only IdP protocol mapper**, never a user-editable attribute or caller-supplied header. A required `RevocationChecker` receives the signed `jti`, token and subject on every request; an exception denies authentication. The OIDC server uses `PinnedKeycloakIntrospection` (confidential client, HTTPS, pinned same-realm URL, no redirects/cache) to demand `active=true` and matching `sub`/optional `jti`; failures deny access. The optional `PinnedHttpsJwksSource` accepts only an explicitly pinned same-origin Keycloak realm certs URL with HTTPS, normal JVM trust, no redirects, no token-derived URLs and no stale-key fallback. Configure/test trust roots and rotation before real use. There is no automatic discovery or caching; real Keycloak integration has not been verified. `LocalTestVerifier` still maps operator-provided opaque tokens to fixed principals **only in the explicit `serve --local-test` mode**. `serve --oidc` uses only signed JWT verification plus online Keycloak introspection, never fake tokens. Neither mode changes the loopback bind.
- `OpenBaoStore` uses KV-v2 `LIST /v1/<mount>/metadata/`, `GET /v1/<mount>/data/<uuid>` and `POST /v1/<mount>/data/<uuid>` with `options.cas` (zero on create, version on edit/share/revoke). Each record is one KV document containing owner, grants and value. There is no separate metadata database; CAS prevents lost grant updates. Configure the KV-v2 mount and service token separately in a disposable local OpenBao; the service token must permit list metadata and read/write data on that mount. **The service token has broad power; only Keykeeper may access it.** Bao URLs are restricted to loopback.
- Web `http://127.0.0.1:<port>/` and `/api/items` use bearer auth for CLI and an **optional OIDC browser session** in `serve --oidc`. Browser sign-in uses authorization code + S256 PKCE, random one-time state bound to an HttpOnly SameSite=Lax callback cookie, server-side token storage, a 15-minute HttpOnly SameSite=Strict session cookie, origin + CSRF-header checks on all session mutations/logout, and re-verification on each API request. Tokens are never in browser JS or session cookies; authorization callbacks never echo codes. The local-test password field still keeps its test token in page memory only. Secrets render as DOM text nodes (not HTML). Responses use no-store and restrictive CSP. No CORS or public bind. CLI `--device` requests an OAuth device code interactively via an HTTPS realm; it shows only verification URL/user code, keeps the token in process memory, and uses the same HTTP API without token args/env. Legacy `--oidc` env-token CLI remains available for controlled testing. `create` and `edit` accept a value via stdin, never arguments. Audit entries record action, SHA-256 principal identity, UUID or `-`, and result, **not tokens or values**. Malformed input and upstream failures have generic responses.

## Build and offline tests

```sh
export JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
export GRADLE_USER_HOME=/mnt/media/p0-v3/cache/gradle-user
./gradlew --offline clean check
```

JaCoCo 0.8.13 enforces **at least 90% LINE coverage of the entire production bundle** on both `test` and `check`; no production classes are excluded. Report: `build/reports/jacoco/test/html/index.html` and `build/reports/jacoco/test/jacocoTestReport.xml`. As measured by `./gradlew --offline clean check`: **506 covered / 547 total production lines = 92.50457038391225% (92.50%)**. The separate opt-in actual Bao and Raft restore tests do not contribute to this offline test figure.

Offline tests exercise locally generated RSA-signed OIDC tokens, a disposable fake IdP token endpoint exchanging S256 PKCE codes for signed JWTs, state/cookie/CSRF/logout/session expiry, a fake device authorization endpoint and CLI token-in-memory path, authorization/revocation, HTTP bearer failures, local server configuration, KV-v2 wire requests/CAS/conflicts using an in-process fake Bao server, and audit redaction. They do **not** prove integration with a real OpenBao/SSO installation.

## Optional real OpenBao integration test (never automatic)

The unit tests use an **in-process fake Bao HTTP server** to check KV-v2 wire shape; they do not contact OpenBao. `realBaoTest` is a *separate source set/task*, not part of `test`, `check`, or the offline JaCoCo numerator. It requires an operator-provisioned, disposable, loopback-only **real OpenBao** with its own empty KV-v2 mount named `keykeeper-test-*`, a test-only token permitted to list metadata, read/write data and delete metadata on that mount, and explicit opt-in. Never point it at a shared/active service or use real credential values. The test generates a random UUID and fake secret; in `finally` it deletes **only its own UUID** via KV-v2 metadata delete (all versions) and checks absence. If the process is killed, that fake record may need manual cleanup. No OpenBao instance or credentials are included in this repository.

```sh
export KEYKEEPER_REAL_BAO_DISPOSABLE=YES
export KEYKEEPER_REAL_BAO_URL=http://127.0.0.1:8200
export KEYKEEPER_REAL_BAO_MOUNT=keykeeper-test-disposable
export KEYKEEPER_REAL_BAO_TOKEN='<operator-provided-local-disposable-token>'
./gradlew --offline realBaoTest -PlocalBaoTest=true
```

Without the Gradle flag this task is skipped, even if invoked explicitly. Missing environment variables/confirmation or a non-loopback URL fail closed. **Not run here: no disposable real Bao or test token was available.**

## Optional disposable Raft snapshot/restore test (never automatic)

`raftRestoreTest` starts **two independently initialized** disposable OpenBao processes with separate Raft directories, config, identities, root/unseal keys and `127.0.0.1` ports in `build/raft-scratch/`. The source mounts KV-v2, stores a fake value and agent grant, snapshots Raft, then edits and revokes on the still-running source. The separately initialized fresh target is first checked for absence of the source record; it receives the source snapshot, restarts **only the target process** on its own restored directory and unseals. A new `OpenBaoStore`/`Vault` pointed at that target must read the restored fake value as owner and agent, then revoke the agent and confirm denial. The source must independently retain its post-snapshot edit and revoke. Both processes are destroyed and both directories deleted in `finally`. It **never targets an existing cluster or accepts a Bao URL/token**. An operator must provide a trusted local executable; without the flag the task is skipped. Do not run with an active process's binary flags/wrappers or use real data.

```sh
export KEYKEEPER_DISPOSABLE_RAFT_CONFIRM=YES-NEW-INSTANCE-ONLY
export KEYKEEPER_TEST_BAO_BINARY=/path/to/trusted/local/openbao
./gradlew --offline raftRestoreTest -PdisposableRaftRestore=true
```

**Isolated test result:** using verified OpenBao **2.7.2** at `/mnt/media/p0-v3/cache/openbao/v2.7.2/bin/bao`, the independent-target restore passed once and then passed two forced reruns. An additional opt-in test in the same task uses a disposable fake IdP with locally signed tokens and a fresh real KV-v2 Bao to exercise browser PKCE/session/CSRF, verified human access, agent bearer grant/read/revoke, and logout; it passed with OpenBao 2.7.2. The earlier same-process snapshot test was **not** isolated and is superseded. This test checks the restored value and grant through the target adapter, target revocation, and source independence; it is still **not** full-stack restore or release proof. The separate operator-provided `realBaoTest` (against a pre-existing disposable mount) has not run here.

## OIDC wiring (configuration contract, not validated with Keycloak)

`serve --oidc` requires `KEYKEEPER_OIDC_ISSUER` (HTTPS realm URL), `KEYKEEPER_OIDC_AUDIENCE`, **distinct** `KEYKEEPER_OIDC_HUMAN_CLIENT` and `KEYKEEPER_OIDC_AGENT_CLIENT` (pinned `azp` values), `KEYKEEPER_OIDC_INTROSPECTION_CLIENT` and `KEYKEEPER_OIDC_INTROSPECTION_SECRET` for a confidential Keycloak client allowed to introspect access tokens, plus loopback `KEYKEEPER_BAO_URL`, `KEYKEEPER_BAO_MOUNT`, `KEYKEEPER_BAO_TOKEN` and optional `KEYKEEPER_PORT`. Do not put credentials in arguments, files, logs or this repository. The real IdP must issue signed admin-only `keykeeper_principal_type`, `jti`, `nbf`, `iat`, `exp`, `aud`, `azp`, `sub` and `iss` claims; an agent client's interactive human login must be disabled by policy. The browser automatically redirects to the pinned Keycloak authorization endpoint (`KEYKEEPER_OIDC_HUMAN_CLIENT` must allow the exact `http://127.0.0.1:<port>/auth/callback` redirect URI and PKCE S256); the server exchanges the code and verifies the resulting access token and introspection. CLI `cli --device list|read ...` uses `KEYKEEPER_OIDC_AGENT_CLIENT`, which must enable the device authorization grant; enter its user code only on the pinned realm. CLI `cli --oidc ...` still reads `KEYKEEPER_ACCESS_TOKEN` from the environment for controlled tests (local-test tokens never substitute). Both modes bind `127.0.0.1` only; never expose this HTTP listener or enter real secrets in it without further hardening.

## Optional disposable loopback sandbox (fake values only)

Only if a **separately provisioned LOCAL KV-v2 test mount** is available, supply your own test-only OpenBao token via the environment (never commit it). Example shell configuration; replace placeholders in your private shell, not this repository:

```sh
export KEYKEEPER_BAO_URL=http://127.0.0.1:8200
export KEYKEEPER_BAO_MOUNT=keykeeper-test
export KEYKEEPER_BAO_TOKEN='local-sandbox-token-from-your-own-test-bao'
export KEYKEEPER_TEST_ISSUER='local-test-issuer'
export KEYKEEPER_TEST_SUBJECT='alice'
export KEYKEEPER_TEST_KIND=HUMAN
export KEYKEEPER_TEST_TOKEN='alice-test-token-at-least-24-chars'
export KEYKEEPER_TEST_AGENT_SUBJECT='bot-1'
export KEYKEEPER_TEST_AGENT_TOKEN='bot-test-token-at-least-24-chars'
export KEYKEEPER_PORT=8765
./gradlew --offline run --args='serve --local-test'
```

In another shell set `KEYKEEPER_TEST_TOKEN` to the appropriate test person's/agent's token (the server environment stays unchanged) and optionally `KEYKEEPER_URL=http://127.0.0.1:8765`. Examples (shell history must not contain values):

```sh
./gradlew --offline run --args='cli --local-test list'
printf 'fake-value-only' | ./gradlew --offline run --args='cli --local-test create'
./gradlew --offline run --args='cli --local-test read UUID_FROM_CREATE'
printf 'new-fake-value' | ./gradlew --offline run --args='cli --local-test edit UUID_FROM_CREATE'
./gradlew --offline run --args='cli --local-test share UUID_FROM_CREATE local-test-issuer bot-1 AGENT READ,EDIT,SHARE'
./gradlew --offline run --args='cli --local-test revoke UUID_FROM_CREATE local-test-issuer bot-1 AGENT'
```

**Caution:** Gradle `run` may print task/build output to stdout alongside CLI output; for piping secrets use a packaged executable or invoke the main class directly in a controlled environment. The CLI prints the revealed value on read, so redirect it appropriately. Browsers, terminals, process environments, reverse proxies and OpenBao can leak sensitive material; this sandbox is explicitly not hardened for production.

## Blockers before real web/OpenBao use

Browser PKCE and `cli --device` are wired, but real Keycloak integration and validating its admin-only kind mapper/client policy, configured redirect/device grants, JWKS rotation, introspection privileges/revocation and logout behavior remain **unverified**. Sessions are in-process only (not HA/durable), and browser OAuth logout only invalidates the local session, not the upstream IdP session. OIDC mode still binds loopback and requires separately provisioned local Bao; it is not a public deployment. Session lifecycle, TLS and non-loopback deployment security, protected operator token distribution, a real Bao KV-v2 integration test including permissions/restore, HA audit sink with durable tamper-resistant delivery, UX/security review and backup/restore acceptance are outstanding. The local audit sink prints to stdout and can fail if the process dies; do not treat it as compliance logging. An independent entire-stack web/CLI/SSO and restore gate is required before any 2/2 reinstall claim. **2/2 reinstall remains 0/2 verified**. No reinstall claim is made here.
