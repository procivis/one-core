ARG BASE_IMAGE=registry.gitlab.procivis.ch/procivis/one/one-operations/core-base:1.90.0-0.1
ARG APP_VERSION

# ----------- Planner image -----------
# Creates dependencies tree file
FROM $BASE_IMAGE AS planner

WORKDIR /app

COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# ----------- Builder image -----------
# Builds dependencies (cached in a single layer) and then the final app binary
FROM $BASE_IMAGE AS builder

ARG APP_VERSION

ENV CARGO_UNSTABLE_GC="true"
ENV APP_VERSION=${APP_VERSION}

WORKDIR /app

COPY --from=planner /app/recipe.json recipe.json
# Build dependencies - this is the caching Docker layer
RUN cargo chef cook --release --recipe-path recipe.json

# Build the app binary
COPY . .
RUN cargo build --release -p core-server && \
    cargo sweep --time 7


# ----------- App Base image -----------
# Basic runtime setup
FROM debian:12-slim AS base

ARG GID=1000
ARG UID=1000
ARG USER=rust

RUN apt-get update && \
    apt-get install -y ca-certificates && \
    apt-get clean && \
    groupadd -g "$GID" "$USER" && \
    useradd -r -u "$UID" -g "$USER" "$USER"


# ----------- Production image -----------
# Copies the final app binary - created in builder stage - to the base image
FROM base

WORKDIR /app

COPY --from=builder --chmod=555 /app/target/release/core-server .
COPY config /app/config

EXPOSE 3000

USER $USER
ENTRYPOINT ["/app/core-server"]
