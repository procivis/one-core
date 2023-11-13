# One Core

## Build

You can build the project with cargo build as well as build certain target using cargo-make.
Cargo-make will include dev.env file in the runtime. This makes env config convenient
and create an opportunity to document used variables in one place.

Install cargo-make

```shell
cargo install cargo-make
```

Build REST server
```shell
makers build
```

Run REST server
```shell
makers run
```

We can use `Makefile.toml` to add and fine tune build/run targets later in the project.

## Tests

To run only the unit tests 

```shell
cargo test --lib
# or 
makers unit-tests
```

To run integration-tests 
```shell
cargo test --test integration_tests
# or 
makers integration-tests
```


## Run Wallet

You can start a separate instance of a service that will play wallet role. This instance is accessible on port 3001.

```shell
makers runwallet
```

### Live Reload

Using `cargo-watch`, the code can be automatically recompiled when changes are made.

Setup

```
cargo install cargo-watch
```

Run the REST server

```
makers runw
```


## Docker

* Run MariaDB for local developing
```shell
docker-compose -f docker/db.yml up -d
or
makers dbstart
```

* Stop MariaDB for local developing
```shell
docker-compose -f docker/db.yml down
or
makers dbstop
```

* Drop MariaDB for local developing - removes everything
```shell
makers dbdrop
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
