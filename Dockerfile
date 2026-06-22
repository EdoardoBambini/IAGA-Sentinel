# Stage 1: Build
# IAGA Sentinel workspace build. The runtime binary is `iaga`
# (full name `iaga-sentinel`) from `crates/iaga-sentinel-core`.
FROM rust:1.94-slim-bookworm AS builder

RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the entire workspace and build in one shot. The dummy-stub
# dependency-cache trick that earlier versions of this Dockerfile used
# is fragile across multi-crate workspaces (the second build can fail
# to rebuild the binary). A single-shot build is slower but reliable.
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
# The Codex plug-in is a workspace member outside crates/ (plug-ins/codex-plugin).
# cargo must read every member manifest to resolve the workspace, even though the
# `iaga` binary does not depend on it.
COPY plug-ins/codex-plugin/ plug-ins/codex-plugin/

# Build only the production binary we ship. `--locked` enforces that
# Cargo.lock matches what was committed.
RUN cargo build --release --bin iaga --locked

# Stage 2: Runtime
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libsqlite3-0 \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN adduser --disabled-password --gecos '' iaga

WORKDIR /app

COPY --from=builder /app/target/release/iaga ./iaga
# BUSL-1.1 requires the license to travel with each copy of the work.
COPY LICENSE ./LICENSE
COPY crates/iaga-sentinel-core/iaga-sentinel.example.yaml ./iaga-sentinel.yaml
COPY crates/iaga-sentinel-dictum/examples /app/examples/dictum
COPY crates/iaga-sentinel-core/examples/policies /app/examples/policies

RUN mkdir -p /app/data /home/iaga/.iaga-sentinel/keys && \
    chown -R iaga:iaga /app/data /home/iaga/.iaga-sentinel

USER iaga

ENV PORT=4010
ENV DATABASE_URL=sqlite:///app/data/iaga_sentinel.db?mode=rwc

EXPOSE 4010

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:4010/health || exit 1

ENTRYPOINT ["./iaga"]
CMD ["serve"]
