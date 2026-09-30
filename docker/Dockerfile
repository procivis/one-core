ARG BASE_IMAGE=registry.gitlab.procivis.ch/procivis/one/one-operations/core-base:1.92.0-0.1
ARG APP_VERSION

# ----------- Builder image -----------
FROM $BASE_IMAGE AS builder

ARG APP_VERSION

ENV CARGO_UNSTABLE_GC="true"
ENV APP_VERSION=${APP_VERSION}

WORKDIR /app

COPY . .
# /app/target is a cache directory on the build host. It is kept between builds and is not part of the image.
# sharing=locked: one build uses it at a time. A second build waits until this RUN ends.
RUN --mount=type=cache,target=/app/target,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    cargo build --release -p core-server && \
    cargo sweep --time 7 && \
    # Copy the binary from the cache into the image.
    cp target/release/core-server /core-server


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

COPY --from=builder --chmod=555 /core-server .
COPY config /app/config

EXPOSE 3000

USER $USER
ENTRYPOINT ["/app/core-server"]
