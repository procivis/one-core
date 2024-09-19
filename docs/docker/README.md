# Docker Rust documentation

* Build image
```shell
docker build -t open-core-docs -f docs/docker/Dockerfile .
```

* Run image
```shell
docker run -p 80:8000 -it --rm open-core-docs
```
