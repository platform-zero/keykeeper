# Keykeeper v3 — LOCAL/TEST-ONLY vertical slice

A Kotlin/JDK 21 loopback web vault and CLI with an OpenBao KV-v2 adapter. **Not a production vault or SSO integration. Do not use real credentials.** No old P0 code, deployment or external service changes are included.

## What works

- `Vault` checks a *verified* `(issuer, subject, kind)` for every list/read/create/edit/share/revoke. Humans and agents have exactly the same authorization and operations. READ controls discovery and release; EDIT replaces values; SHARE delegates only rights held by the actor, and can revoke a grant. Revocation is checked on every request (not against a cached session).
- `IdentityVerifier` is the injection boundary for future SSO: an implementation must verify signature, issuer, audience, expiration, agent/human classification and revocation. The bundled `LocalTestVerifier` maps operator-provided opaque tokens to fixed principals **only in local test mode**; no arbitrary claim headers, password login, Keycloak/OIDC or production verifier exists.
- `OpenBaoStore` uses KV-v2 `LIST /v1/<mount>/metadata/`, `GET /v1/<mount>/data/<uuid>` and `POST /v1/<mount>/data/<uuid>` with `options.cas` (zero on create, version on edit/share/revoke). Each record is one KV document containing owner, grants and value. There is no separate metadata database; CAS prevents lost grant updates. Configure the KV-v2 mount and service token separately in a disposable local OpenBao; the service token must permit list metadata and read/write data on that mount. **The service token has broad power; only Keykeeper may access it.** Bao URLs are restricted to loopback.
- Web `http://127.0.0.1:<port>/` and `/api/items` use bearer auth; the page keeps its token in memory, clears its input, and uses DOM text nodes (not HTML) for secrets. Responses use no-store and restrictive CSP. No cookies/CORS or public bind. CLI uses the same HTTP API. `create` and `edit` accept a value via stdin, never arguments. Audit entries record action, SHA-256 principal identity, UUID or `-`, and result, **not tokens or values**. Malformed input and upstream failures have generic responses.

## Build and offline tests

```sh
export JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
export GRADLE_USER_HOME=/mnt/media/p0-v3/cache/gradle-user
./gradlew --offline clean check
```

JaCoCo 0.8.13 enforces **at least 90% LINE coverage of the entire production bundle** on both `test` and `check`; no production classes are excluded. Report: `build/reports/jacoco/test/html/index.html` and `build/reports/jacoco/test/jacocoTestReport.xml`. As measured by `./gradlew --offline clean check`: **261 covered / 286 total production lines = 91.25874125874125% (91.26%)**. The separate opt-in actual Bao test does not contribute to this offline test figure.

Offline tests exercise authorization/revocation, HTTP bearer failures, two identities using the same API/CLI, local server configuration, KV-v2 wire requests/CAS/conflicts using an in-process fake Bao server, and audit redaction. They do **not** prove integration with a real OpenBao/SSO installation.

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
./gradlew --offline run --args='cli list'
printf 'fake-value-only' | ./gradlew --offline run --args='cli create'
./gradlew --offline run --args='cli read UUID_FROM_CREATE'
printf 'new-fake-value' | ./gradlew --offline run --args='cli edit UUID_FROM_CREATE'
./gradlew --offline run --args='cli share UUID_FROM_CREATE local-test-issuer bot-1 AGENT READ,EDIT,SHARE'
./gradlew --offline run --args='cli revoke UUID_FROM_CREATE local-test-issuer bot-1 AGENT'
```

**Caution:** Gradle `run` may print task/build output to stdout alongside CLI output; for piping secrets use a packaged executable or invoke the main class directly in a controlled environment. The CLI prints the revealed value on read, so redirect it appropriately. Browsers, terminals, process environments, reverse proxies and OpenBao can leak sensitive material; this sandbox is explicitly not hardened for production.

## Blockers before real web/OpenBao use

Real OIDC/JWT verification (JWKS rotation, audience/issuer, expiration, agent identity and logout/revocation), session lifecycle, TLS and non-loopback deployment security, protected operator token distribution, a real Bao KV-v2 integration test including permissions/restore, HA audit sink with durable tamper-resistant delivery, UX/security review and backup/restore acceptance are outstanding. The local audit sink prints to stdout and can fail if the process dies; do not treat it as compliance logging. An independent entire-stack web/CLI/SSO and restore gate is required before any 2/2 reinstall claim. No such claim is made here.
