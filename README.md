# One Core


## Docker

* Run MariaDB for local developing
```shell
docker-compose -f docker/db.yml up -d
```

* Run MariaDB logs
```shell
docker-compose -f docker/db.yml logs -f
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
