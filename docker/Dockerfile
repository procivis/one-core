# --- Build Stage ---
FROM rust:latest AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y pkg-config libssl-dev build-essential ca-certificates

# Set working directory
WORKDIR /app

# Copy source code
COPY . .

# Build the project in release mode
RUN cargo build --release

# --- Runtime Stage ---
FROM debian:12-slim

# Define build args
ARG GID=1000
ARG UID=1000
ARG USER=rust

# Create app directory and system user
WORKDIR /app

RUN apt-get update && \
    apt-get install -y ca-certificates && \
    apt-get clean && \
    groupadd -g "$GID" "$USER" && \
    useradd -r -u "$UID" -g "$USER" "$USER"

# Copy built binary and config files from builder
COPY --from=builder --chmod=555 /app/target/release/core-server /app/core-server
COPY --chmod=+x config /app/config

EXPOSE 3000

# Switch to non-root user
USER $USER

# Set entrypoint
ENTRYPOINT ["/app/core-server"]
