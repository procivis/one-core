FROM debian:11-slim

ARG GID=1000
ARG UID=1000
ARG USER=rust

WORKDIR /app/

RUN groupadd -g $GID $USER && \
    useradd -r -u $UID -g $USER $USER

COPY --chown=$USER:$USER target/release/core-server /app/
COPY --chown=$USER:$USER config /app/config

EXPOSE 3000

USER $USER
ENTRYPOINT ["/app/core-server"]
