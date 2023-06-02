# One Core


## Docker

For running docker container based on Dockerfile should be installed:

```shell
rustup target add x86_64-unknown-linux-musl
cargo build --target x86_64-unknown-linux-musl --release
```


* Build project
```shell
docker build -t one-core -f docker/Dockerfile .
```

* Run project
```shell
docker run --init  -p 3000:3000 -it --rm one-core
```

* Run shell in the container
```shell
docker run -it --rm --entrypoint="" one-core sh
```

