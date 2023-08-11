FROM debian:11-slim

ARG GID=1000
ARG UID=1000
ARG USER=rust


RUN groupadd -g $GID $USER && \
    useradd -r -u $UID -g $USER $USER

COPY --chown=$USER:$USER target/release/core-server config.yml /app/

EXPOSE 3000

USER $USER
ENTRYPOINT ["/app/core-server"]
