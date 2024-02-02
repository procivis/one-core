FROM debian:12-slim

ARG GID=1000
ARG UID=1000
ARG USER=rust

WORKDIR /app/

RUN apt-get update && \
    apt-get install -y ca-certificates && \
    apt-get clean && \
    groupadd -g "$GID" "$USER" && \
    useradd -r -u "$UID" -g "$USER" "$USER"

COPY --chmod=555 target/release/core-server /app/
COPY --chmod=444 config /app/config

EXPOSE 3000

USER $USER
ENTRYPOINT ["/app/core-server"]
