# One Core


## Docker

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

