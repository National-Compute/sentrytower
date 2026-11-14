# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
#
# The SentryTower container image: Python 3.12 and Node.js 24 on Debian 13
# (trixie), the pinned Pi coding agent 1.5.0, and ripgrep 15.2.0 and fd 10.5.0
# as in the measured runs.
# The release workflow publishes it for linux/amd64 and linux/arm64 as
# ghcr.io/national-compute/sentrytower:<version>.
#
#   docker build -f docker/Dockerfile -t sentrytower:0.1.1 .
#   mkdir -p ~/sentrytower-results     # outside the audited repository
#   docker run --rm -e SENTRYTOWER_API_KEY --user "$(id -u):$(id -g)" \
#     --read-only --tmpfs "/home/dev:uid=$(id -u),gid=$(id -g)" --tmpfs /tmp \
#     -v "$PWD:/workspace/repo:ro" -v ~/sentrytower-results:/workspace/out \
#     sentrytower:0.1.1 audit /workspace/repo --out /workspace/out
#
# The layout of the run is the layout of the measured runs: the
# repository at /workspace/repo and the agent state below /home/dev. The
# agent shows these paths to the model.
#
# The stages that only download or build files that do not depend on the
# architecture (ripgrep and fd, the pure-Python wheel) run on the platform
# of the build, so that a multi-platform build emulates less.

ARG PYTHON_IMAGE=python:3.12.16-slim-trixie@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b
ARG NODE_IMAGE=node:24.22.3-trixie-slim@sha256:af02d57b57719b9657a45199a79264a9437940cd55b3c7b3fc99615654f124a0

# ---------------------------------------------------------------------------
# The Pi coding agent from the lockfile (its integrity values are checked).
# This stage runs on the target platform: npm installs the packages of a
# native install, and the runtime takes its node binary.
# ---------------------------------------------------------------------------
FROM ${NODE_IMAGE} AS pi
WORKDIR /opt/pi-install
COPY docker/pi/package.json docker/pi/package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund \
 && test "$(node -p "require('./node_modules/@earendil-works/pi-coding-agent/package.json').version")" = "1.5.0" \
 && rm -rf /root/.npm

# ---------------------------------------------------------------------------
# ripgrep and fd: the pinned releases, with the SHA-256 of each archive and binary.
# ---------------------------------------------------------------------------
FROM --platform=$BUILDPLATFORM ${PYTHON_IMAGE} AS tools
ARG TARGETARCH
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
# The base image is pinned by digest; these packages take their security updates.
# hadolint ignore=DL3008
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*
RUN set -eu; \
    case "${TARGETARCH:-amd64}" in \
      amd64) \
        rg_file=ripgrep-15.2.0-x86_64-unknown-linux-musl; \
        rg_archive=33e15bcf1624b25cdd2a55813a47a2f95dbe126268203e76aa6a585d1e7b149c; \
        rg_binary=e62198eb19b136b88c330af83647b5a962cb99b6b1f066758568f12de1974849; \
        fd_file=fd-v10.5.0-x86_64-unknown-linux-gnu; \
        fd_archive=a1259cd129636efbc3fef123525c1b49e88fe5088c012630983c310e52fdfa95; \
        fd_binary=c776d4bcfac0e87c0741008d25dab50e3608c5293280208f504eafb0146f8711 ;; \
      arm64) \
        rg_file=ripgrep-15.2.0-aarch64-unknown-linux-gnu; \
        rg_archive=a740b91c82eaf9914cfedd353572f2791cbe0162c84101ee0951058f4dcbc90d; \
        rg_binary=e36d0eb52e70696bdf1781392722e05a21bb91d3b7b762ef5ec20e5df2ec687b; \
        fd_file=fd-v10.5.0-aarch64-unknown-linux-gnu; \
        fd_archive=c0ee43802e3313a317c5af2f4eabd6ba13eeedd595af9775f05e18a13ac4f52c; \
        fd_binary=84af02927affcc04af7e4180a23f5ec2525c4a7c6560f3413515c8f1493fa2f1 ;; \
      *) echo "unsupported architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    work=$(mktemp -d); \
    curl --proto '=https' --tlsv1.2 -fsSL --retry 5 -o "$work/rg.tgz" \
      "https://github.com/BurntSushi/ripgrep/releases/download/15.2.0/${rg_file}.tar.gz"; \
    echo "${rg_archive}  $work/rg.tgz" | sha256sum --check --strict -; \
    tar -xzf "$work/rg.tgz" -C "$work" --no-same-owner "${rg_file}/rg"; \
    echo "${rg_binary}  $work/${rg_file}/rg" | sha256sum --check --strict -; \
    curl --proto '=https' --tlsv1.2 -fsSL --retry 5 -o "$work/fd.tgz" \
      "https://github.com/sharkdp/fd/releases/download/v10.5.0/${fd_file}.tar.gz"; \
    echo "${fd_archive}  $work/fd.tgz" | sha256sum --check --strict -; \
    tar -xzf "$work/fd.tgz" -C "$work" --no-same-owner "${fd_file}/fd"; \
    echo "${fd_binary}  $work/${fd_file}/fd" | sha256sum --check --strict -; \
    install -D -m 0755 "$work/${rg_file}/rg" /out/usr/local/bin/rg; \
    install -D -m 0755 "$work/${fd_file}/fd" /out/usr/local/bin/fd; \
    rm -rf "$work"

# ---------------------------------------------------------------------------
# The SentryTower wheel (no runtime dependency: the standard library only).
# ---------------------------------------------------------------------------
FROM --platform=$BUILDPLATFORM ${PYTHON_IMAGE} AS wheel
WORKDIR /src
COPY pyproject.toml README.md LICENSE-APACHE LICENSE-MIT NOTICE ./
COPY src ./src
RUN PYTHONDONTWRITEBYTECODE=1 pip wheel --no-cache-dir --no-deps --disable-pip-version-check --wheel-dir /wheels .

# ---------------------------------------------------------------------------
# The runtime image.
# ---------------------------------------------------------------------------
FROM ${PYTHON_IMAGE} AS runtime
LABEL org.opencontainers.image.title="SentryTower" \
      org.opencontainers.image.description="LLM security audits of source repositories: a size-routed hybrid of a funnel engine and a single agent." \
      org.opencontainers.image.source="https://github.com/National-Compute/sentrytower" \
      org.opencontainers.image.url="https://github.com/National-Compute/sentrytower" \
      org.opencontainers.image.documentation="https://github.com/National-Compute/sentrytower/blob/main/docs/deployment.md" \
      org.opencontainers.image.licenses="Apache-2.0 OR MIT" \
      org.opencontainers.image.version="0.1.1"
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
# libstdc++ for Node.js; tini reaps the agent processes and forwards signals. The base image is
# pinned by digest; the upgrade installs the Debian security updates published since it was built,
# and the added packages take theirs.
# hadolint ignore=DL3008
RUN apt-get update \
 && apt-get upgrade -y --no-install-recommends \
 && apt-get install -y --no-install-recommends libstdc++6 tini ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --uid 1000 --user-group --create-home --home-dir /home/dev --shell /usr/sbin/nologin dev \
 && mkdir -p /workspace/repo /workspace/out \
 && chown dev:dev /workspace/out
COPY --from=pi /usr/local/bin/node /usr/local/bin/node
COPY --from=pi /opt/pi-install /opt/pi-install
COPY --from=tools /out/usr/local/bin/ /usr/local/bin/
# The wheel comes from a bind mount, so that no layer keeps it; pip writes the bytecode of SentryTower,
# not of itself. SentryTower has no runtime dependency and nothing runs pip at run time, so pip
# removes itself once the wheel is installed.
RUN --mount=type=bind,from=wheel,source=/wheels,target=/tmp/wheels \
    PYTHONDONTWRITEBYTECODE=1 pip install --no-cache-dir --no-deps --disable-pip-version-check --root-user-action=ignore /tmp/wheels/*.whl \
 && PYTHONDONTWRITEBYTECODE=1 pip uninstall --yes --disable-pip-version-check --root-user-action=ignore pip \
 && ! python3 -c 'import pip' 2>/dev/null \
 && ln -s /opt/pi-install/node_modules/@earendil-works/pi-coding-agent /opt/pi \
 && ln -s /opt/pi/dist/bundle/cli.js /usr/local/bin/pi \
 && test "$(rg --version | head -1 | cut -d' ' -f2)" = "15.2.0" \
 && test "$(fd --version | cut -d' ' -f2)" = "10.5.0" \
 && node --version && sentrytower version
ENV HOME=/home/dev \
    SENTRYTOWER_STATE_DIR=/home/dev \
    SENTRYTOWER_PI=/opt/pi/dist/bundle/cli.js \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
USER 1000:1000
WORKDIR /workspace
HEALTHCHECK --interval=5m --timeout=30s --start-period=5s --retries=1 \
  CMD ["sentrytower", "doctor", "--offline", "--quiet"]
ENTRYPOINT ["/usr/bin/tini", "--", "sentrytower"]
CMD ["doctor", "--offline"]
