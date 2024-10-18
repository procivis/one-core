# Docker One Core documentation


* Generate docs site
```shell
cargo doc --no-deps --release
```

* Build image
```shell
docker build -t one-core-docs -f docs/docker/Dockerfile .
```

* Run image
```shell
docker run -p 8000:8000 -it --rm one-core-docs
```
