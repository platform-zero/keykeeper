# Build context: keykeeper/ after ./gradlew installDist.
# Runtime only; Gradle distribution and all dependencies are built/tested separately.
FROM docker.io/library/eclipse-temurin@sha256:03fedab2c0d7355868b5ba5330d64088b956a0bfac48f904e5c57207e261e2c9
COPY --chown=65532:65532 build/install/p0-v3-keykeeper/ /opt/keykeeper/
USER 65532:65532
WORKDIR /opt/keykeeper
ENTRYPOINT ["/opt/keykeeper/bin/p0-v3-keykeeper"]
