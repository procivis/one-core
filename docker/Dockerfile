FROM alpine:3.16.0

ARG GID=1000
ARG UID=1000
ARG USER=rust

RUN addgroup -g $GID -S $USER && \
    adduser -S $USER -G $USER --uid "$UID"

COPY --chown=$USER:$USER target/x86_64-unknown-linux-musl/release/mock-server /usr/local/bin

EXPOSE 3000

USER $USER
ENTRYPOINT ["/usr/local/bin/mock-server"]
