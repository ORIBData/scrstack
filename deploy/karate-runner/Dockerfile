# SCRS Karate runner: karate-cli with a pinned Karate jar, the karate-gatling
# load launcher, headless Chromium for UI tests, and the scrs-qa-runner REST
# service. Build from the repository root:
#   docker build -f deploy/karate-runner/Dockerfile -t scrs-qa-runner .
# Run it on a host you manage; see docs/QA_TESTING.md.

FROM golang:1.27.4 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
COPY api ./api
RUN CGO_ENABLED=0 go build -trimpath -o /out/scrs-qa-runner ./cmd/scrs-qa-runner

# karate-gatling and its dependencies, collected at build time so the
# runner needs no build tool or network to start a load test.
FROM maven:3.9.11-eclipse-temurin-21 AS perf
WORKDIR /perf
COPY deploy/karate-runner/perf/pom.xml ./
RUN mvn -q -B dependency:go-offline
COPY deploy/karate-runner/perf/src ./src
RUN mvn -q -B package -DskipTests

FROM debian:trixie-slim
ARG TARGETARCH
ARG KARATE_VERSION=2.1.4
ARG KARATE_SHA256=1f743f4acc56526b39bd88c84bfe4491c46d5e94f4ab5a38c437c9400dbc2488
ARG KARATE_CLI_VERSION=0.1.9
ARG KARATE_CLI_SHA256_AMD64=2e4a41cf7d902a1a3a37afa9b7fee942585362baefa54404dc396e66de84c8df
ARG KARATE_CLI_SHA256_ARM64=4eea65d8ec2e187df5fdc4ed1c3dfe53ff65d76336718297d57ea1a242551f90
RUN apt-get update \
 && apt-get install -y --no-install-recommends openjdk-21-jre-headless chromium fonts-liberation ca-certificates curl tini \
 && rm -rf /var/lib/apt/lists/* \
 && ln -s /usr/bin/chromium /usr/bin/google-chrome
# karate-cli (MIT) and the Karate jar (MIT), both checked against pinned
# SHA-256 digests. karate-cli finds the jar in KARATE_HOME/dist and is told
# not to look for updates.
RUN set -eu; \
    case "$TARGETARCH" in \
      amd64) cli=linux-x64; sum="$KARATE_CLI_SHA256_AMD64" ;; \
      arm64) cli=linux-arm64; sum="$KARATE_CLI_SHA256_ARM64" ;; \
      *) echo "unsupported architecture $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/karate-cli.tar.gz "https://github.com/karatelabs/karate-cli/releases/download/v${KARATE_CLI_VERSION}/karate-${cli}.tar.gz"; \
    echo "$sum  /tmp/karate-cli.tar.gz" | sha256sum -c -; \
    tar -xzf /tmp/karate-cli.tar.gz -C /usr/local/bin karate; \
    rm /tmp/karate-cli.tar.gz; \
    mkdir -p /opt/karate/dist; \
    curl -fsSL -o "/opt/karate/dist/karate-${KARATE_VERSION}.jar" "https://github.com/karatelabs/karate/releases/download/v${KARATE_VERSION}/karate-${KARATE_VERSION}.jar"; \
    echo "$KARATE_SHA256  /opt/karate/dist/karate-${KARATE_VERSION}.jar" | sha256sum -c -; \
    printf '{"channel":"stable","karate_version":"%s","check_updates":false}\n' "$KARATE_VERSION" > /opt/karate/karate-cli.json; \
    ln -s "/usr/lib/jvm/java-21-openjdk-${TARGETARCH}" /usr/lib/jvm/scrs-java; \
    groupadd --gid 10001 qajob && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin qajob
COPY --from=perf /perf/target/scrs-perf-1.jar /opt/scrs-perf/scrs-perf-1.jar
COPY --from=perf /perf/target/lib /opt/scrs-perf/lib
COPY --from=build /out/scrs-qa-runner /usr/local/bin/scrs-qa-runner
ENV KARATE_HOME=/opt/karate \
    JAVA_HOME=/usr/lib/jvm/scrs-java \
    SCRS_QA_RUNNER_KARATE=karate \
    SCRS_QA_RUNNER_KARATE_VERSION=${KARATE_VERSION} \
    SCRS_QA_RUNNER_PERF_CLASSPATH=/opt/scrs-perf/scrs-perf-1.jar:/opt/scrs-perf/lib/* \
    SCRS_QA_RUNNER_WORKDIR=/work \
    SCRS_QA_RUNNER_ADDR=:8090
WORKDIR /work
EXPOSE 8090
HEALTHCHECK --interval=30s --timeout=5s CMD curl -fsS http://127.0.0.1:8090/healthz || exit 1
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/scrs-qa-runner"]
