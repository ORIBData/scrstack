# SCRS Karate runner with every linter. Two images come from this file:
#   base  the runner with Karate, Gatling, Chromium and ruff (--target base)
#   lint  base plus mypy, bandit, pylint, PHPStan, phpcs, clang-tidy, the Go
#         toolchain with golangci-lint, ESLint with Node, ktlint, SwiftLint and
#         the Dart SDK. This is the last stage, so it is the default build and
#         what `make release-qa-runner` publishes for the Dokploy stack.
# Build from the repository root:
#   docker build -f deploy/karate-runner/Dockerfile -t scrs-qa-runner .
#   docker build -f deploy/karate-runner/Dockerfile --target base -t scrs-qa-runner-base .
# Every download is checked against a pinned SHA-256. See docs/QA_TESTING.md.

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

FROM debian:trixie-slim AS base
ARG TARGETARCH
ARG KARATE_VERSION=2.1.4
ARG KARATE_SHA256=1f743f4acc56526b39bd88c84bfe4491c46d5e94f4ab5a38c437c9400dbc2488
ARG KARATE_CLI_VERSION=0.1.9
ARG KARATE_CLI_SHA256_AMD64=2e4a41cf7d902a1a3a37afa9b7fee942585362baefa54404dc396e66de84c8df
ARG KARATE_CLI_SHA256_ARM64=4eea65d8ec2e187df5fdc4ed1c3dfe53ff65d76336718297d57ea1a242551f90
ARG RUFF_VERSION=0.17.5
ARG RUFF_SHA256_AMD64=7d261fc981a784668e19e9fa6ad437bfd95b67f2dc263fc1eab87d54d72fcc90
ARG RUFF_SHA256_ARM64=4d959d4322a8cd3effe11e9fc6743da1dbb41cd0b2476e433b6e6bfd9a69b626
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
# ruff (MIT, a single static binary) is the Python linter of lint jobs, checked
# against a pinned SHA-256. The linters for Go, TypeScript, Kotlin, Swift and
# Dart need toolchains, so they are in the lint stage below.
RUN set -eu; \
    case "$TARGETARCH" in \
      amd64) arch=x86_64; sum="$RUFF_SHA256_AMD64" ;; \
      arm64) arch=aarch64; sum="$RUFF_SHA256_ARM64" ;; \
      *) echo "unsupported architecture $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/ruff.tar.gz "https://github.com/astral-sh/ruff/releases/download/${RUFF_VERSION}/ruff-${arch}-unknown-linux-gnu.tar.gz"; \
    echo "$sum  /tmp/ruff.tar.gz" | sha256sum -c -; \
    tar -xzf /tmp/ruff.tar.gz -C /tmp; \
    install -m 0755 "/tmp/ruff-${arch}-unknown-linux-gnu/ruff" /usr/local/bin/ruff; \
    rm -rf /tmp/ruff.tar.gz "/tmp/ruff-${arch}-unknown-linux-gnu"; \
    ruff --version
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

# The lint stage: every other linter, on top of the runner.
FROM base AS lint
ARG TARGETARCH
ARG PHPSTAN_VERSION=2.3.6
ARG PHPSTAN_SHA256=bd5af896c8eb831e10873a4407c37ac33118dcd88de4ea77e13cd6e6702a41cc
ARG PHPCS_VERSION=4.0.4
ARG PHPCS_SHA256=4b010cd21d8bc8a17e2504792e3c77ef8259126f24caf7eafe7eddef1fa871e9
ARG COMPOSER_VERSION=2.11.2
ARG COMPOSER_SHA256=dd158c0afd41d15fac89e1b4e47b5d42911fe316c3687cd5edac98319b25d028
ARG GO_VERSION=1.27.4
ARG GO_SHA256_AMD64=7226736c2339719cda28fbf3a54d71aa63bcefe376e98cef00034268dab24840
ARG GO_SHA256_ARM64=3392582988a273a87ab5043ee1b2c9c17a2c3c00580bf9326c47a2e0aaaeac92
ARG GOLANGCI_VERSION=2.15.0
ARG GOLANGCI_SHA256_AMD64=9b7fe6a6bf6334b98decf8d86b11415ea7889afdabdd1959fdce23af2a9ebcea
ARG GOLANGCI_SHA256_ARM64=b4d8f17068b35ee6060cc2f69a16fb48740d706fbba81661c318649c114a6998
ARG NODE_VERSION=26.13.1
ARG NODE_SHA256_AMD64=5c063e46bab0fbc1c17cc445d7ff129cbdcd0471be6ed83b6ab864f8143bc864
ARG NODE_SHA256_ARM64=89e1853138db51e8b82d3e98ba9c0d3f2956a28e5e55ea1b7e12d25aae92d5dd
ARG KTLINT_VERSION=1.8.0
ARG KTLINT_SHA256=a3fd620207d5c40da6ca789b95e7f823c54e854b7fade7f613e91096a3706d75
ARG SWIFTLINT_VERSION=0.65.1
ARG SWIFTLINT_SHA256_AMD64=caeed6f4a679c35539ffaf124f6c4ab4a8416917f7d8796279dc52b74026059d
ARG SWIFTLINT_SHA256_ARM64=9ffa52f478e6d8eb485d37d14715ffac90abc81c58f3370d598bf75be05605f8
ARG DART_VERSION=3.14.1
ARG DART_SHA256_AMD64=759bed01e0aeb50e1a0b0a19474ba5c80c6087ce1d37b3214e475c81a44430e8
ARG DART_SHA256_ARM64=c6e5581d478ac43ecf7d7028798b1bd10aef509f5e351184c755ec7eeeb1bea9

RUN apt-get update \
 && apt-get install -y --no-install-recommends xz-utils unzip ca-certificates curl git libatomic1 python3 python3-venv php-cli php-mbstring php-xml clang-tidy libc6-dev libstdc++-14-dev \
 && rm -rf /var/lib/apt/lists/*

# mypy, bandit and pylint, installed from a lockfile whose every file is
# pinned by hash, into their own virtual environment (the repository's own
# dependencies are never installed for them).
COPY deploy/karate-runner/lint/requirements.txt /opt/pytools-requirements.txt
RUN set -eu; \
    python3 -m venv /opt/pytools; \
    /opt/pytools/bin/pip install --no-cache-dir --require-hashes --only-binary=:all: -r /opt/pytools-requirements.txt; \
    for t in mypy bandit pylint; do ln -s "/opt/pytools/bin/$t" "/usr/local/bin/$t"; done; \
    mypy --version; bandit --version | head -n1; pylint --version | head -n1

# PHPStan, PHP_CodeSniffer and Composer (for the opt-in dependency step), single-file phars checked against pinned
# SHA-256 digests, run by the distribution's php-cli. clang-tidy comes from
# the Debian package (signed by the distribution) with the C and C++ standard
# library headers it needs.
RUN set -eu; \
    curl -fsSL -o /usr/local/bin/phpstan "https://github.com/phpstan/phpstan/releases/download/${PHPSTAN_VERSION}/phpstan.phar"; \
    echo "$PHPSTAN_SHA256  /usr/local/bin/phpstan" | sha256sum -c -; \
    curl -fsSL -o /usr/local/bin/phpcs "https://github.com/PHPCSStandards/PHP_CodeSniffer/releases/download/${PHPCS_VERSION}/phpcs.phar"; \
    echo "$PHPCS_SHA256  /usr/local/bin/phpcs" | sha256sum -c -; \
    curl -fsSL -o /usr/local/bin/composer "https://getcomposer.org/download/${COMPOSER_VERSION}/composer.phar"; \
    echo "$COMPOSER_SHA256  /usr/local/bin/composer" | sha256sum -c -; \
    chmod 0755 /usr/local/bin/phpstan /usr/local/bin/phpcs /usr/local/bin/composer; \
    phpstan --version; phpcs --version; composer --version; clang-tidy --version | sed -n 2p

# Go toolchain and golangci-lint.
RUN set -eu; \
    case "$TARGETARCH" in \
      amd64) go_sum="$GO_SHA256_AMD64"; gl_sum="$GOLANGCI_SHA256_AMD64" ;; \
      arm64) go_sum="$GO_SHA256_ARM64"; gl_sum="$GOLANGCI_SHA256_ARM64" ;; \
      *) echo "unsupported architecture $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/go.tgz "https://go.dev/dl/go${GO_VERSION}.linux-${TARGETARCH}.tar.gz"; \
    echo "$go_sum  /tmp/go.tgz" | sha256sum -c -; \
    tar -xzf /tmp/go.tgz -C /usr/local; \
    curl -fsSL -o /tmp/gl.tgz "https://github.com/golangci/golangci-lint/releases/download/v${GOLANGCI_VERSION}/golangci-lint-${GOLANGCI_VERSION}-linux-${TARGETARCH}.tar.gz"; \
    echo "$gl_sum  /tmp/gl.tgz" | sha256sum -c -; \
    tar -xzf /tmp/gl.tgz -C /tmp; \
    install -m 0755 "/tmp/golangci-lint-${GOLANGCI_VERSION}-linux-${TARGETARCH}/golangci-lint" /usr/local/bin/golangci-lint; \
    rm -rf /tmp/go.tgz /tmp/gl.tgz "/tmp/golangci-lint-${GOLANGCI_VERSION}-linux-${TARGETARCH}"; \
    /usr/local/go/bin/go version; golangci-lint --version

# Node and ESLint. ESLint comes from a lockfile (integrity hashes), without
# install scripts.
COPY deploy/karate-runner/lint/package.json deploy/karate-runner/lint/package-lock.json deploy/karate-runner/lint/eslint.config.mjs /opt/eslint/
RUN set -eu; \
    case "$TARGETARCH" in \
      amd64) arch=x64; sum="$NODE_SHA256_AMD64" ;; \
      arm64) arch=arm64; sum="$NODE_SHA256_ARM64" ;; \
      *) echo "unsupported architecture $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/node.txz "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-${arch}.tar.xz"; \
    echo "$sum  /tmp/node.txz" | sha256sum -c -; \
    mkdir -p /usr/local/node; \
    tar -xJf /tmp/node.txz -C /usr/local/node --strip-components=1; \
    rm /tmp/node.txz; \
    cd /opt/eslint; \
    PATH="/usr/local/node/bin:$PATH" npm ci --ignore-scripts --no-audit --no-fund; \
    ln -s /opt/eslint/node_modules/.bin/eslint /usr/local/bin/eslint; \
    PATH="/usr/local/node/bin:$PATH" eslint --version

# ktlint (a self-contained executable that needs the base image's Java).
RUN set -eu; \
    curl -fsSL -o /usr/local/bin/ktlint "https://github.com/pinterest/ktlint/releases/download/${KTLINT_VERSION}/ktlint"; \
    echo "$KTLINT_SHA256  /usr/local/bin/ktlint" | sha256sum -c -; \
    chmod 0755 /usr/local/bin/ktlint

# SwiftLint and the Dart SDK for `dart analyze`. The SwiftLint release ships
# a fully static build (swiftlint-static) that needs no Swift toolchain. It
# skips the few rules that need SourceKit and says so on stderr.
RUN set -eu; \
    case "$TARGETARCH" in \
      amd64) sl_sum="$SWIFTLINT_SHA256_AMD64"; dart_sum="$DART_SHA256_AMD64"; dart_arch=x64 ;; \
      arm64) sl_sum="$SWIFTLINT_SHA256_ARM64"; dart_sum="$DART_SHA256_ARM64"; dart_arch=arm64 ;; \
      *) echo "unsupported architecture $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/sl.zip "https://github.com/realm/SwiftLint/releases/download/${SWIFTLINT_VERSION}/swiftlint_linux_${TARGETARCH}.zip"; \
    echo "$sl_sum  /tmp/sl.zip" | sha256sum -c -; \
    mkdir -p /tmp/sl && unzip -q /tmp/sl.zip -d /tmp/sl; \
    install -m 0755 "$(find /tmp/sl -type f -name swiftlint-static | head -n1)" /usr/local/bin/swiftlint; \
    rm -rf /tmp/sl /tmp/sl.zip; \
    curl -fsSL -o /tmp/dart.zip "https://storage.googleapis.com/dart-archive/channels/stable/release/${DART_VERSION}/sdk/dartsdk-linux-${dart_arch}-release.zip"; \
    echo "$dart_sum  /tmp/dart.zip" | sha256sum -c -; \
    unzip -q /tmp/dart.zip -d /opt; \
    rm /tmp/dart.zip; \
    ln -s /opt/dart-sdk/bin/dart /usr/local/bin/dart

ENV PATH=/usr/local/go/bin:/usr/local/node/bin:/opt/dart-sdk/bin:${PATH} \
    GOROOT=/usr/local/go
