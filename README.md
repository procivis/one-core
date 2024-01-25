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

```shell
cargo install cargo-watch
```

Run the REST server

```shell
makers runw
```

Run compiled application (Local env)

```shell
./target/debug/core-server --config config/config-procivis-base.yml --config config/config-local.yml
```

## Docker

- Run MariaDB for local developing

```shell
docker-compose -f docker/db.yml up -d
or
makers dbstart
```

- Stop MariaDB for local developing

```shell
docker-compose -f docker/db.yml down
or
makers dbstop
```

- Drop MariaDB for local developing - removes everything

```shell
makers dbdrop
```

- Print MariaDB logs

```shell
docker-compose -f docker/db.yml logs -f
```

- Build project

```shell
docker build -t one-core -f docker/Dockerfile .
```

- Run project on Windows or Mac

```shell
docker run --init -p 3000:3000 -it --rm \
  -e ONE_app__databaseUrl=mysql://core:886eOqVMmlHsayu6Vyxw@host.docker.internal/core \
  one-core --config config/config-procivis-base.yml --config config/config-local.yml
```

- Run project on Linux

```shell
docker run --init -p 3000:3000 -it --rm \
  -e ONE_app__databaseUrl=mysql://core:886eOqVMmlHsayu6Vyxw@172.17.0.1/core \
  one-core --config config/config-procivis-base.yml --config config/config-local.yml
```

- Run shell in the container

```shell
docker run -it --rm --entrypoint="" one-core bash
```

# SBOM

Source:

- [https://github.com/CycloneDX/cyclonedx-rust-cargo](https://github.com/CycloneDX/cyclonedx-rust-cargo)
- [https://github.com/CycloneDX/cyclonedx-cli](https://github.com/CycloneDX/cyclonedx-cli)

- Install cyclonedx-cli

```shell
sudo curl -L https://github.com/CycloneDX/cyclonedx-cli/releases/download/v0.25.0/cyclonedx-linux-x64 -o /usr/local/bin/cyclonedx-cli
sudo chmod +x /usr/local/bin/cyclonedx-cli
```

- Install cyclonedx

```shell
cargo install cargo-cyclonedx
```

- Generate JSON format

```shell
cargo cyclonedx -f json
```

- Prepare env

```shell
export DEPENDENCY_TRACK_BASE_URL=https://dtrack.dev.one-trust-solution.com
export DEPENDENCY_TRACK_API_KEY="<api_key>"
export DEPENDENCY_TRACK_PROJECT_NAME="ONE-Core"

export D_TRACK_PATH=${DEPENDENCY_TRACK_BASE_URL}/api/v1/bom
export SBOM_FILE_PATH="apps/core-server/bom.json"
export APP_VERSION="local-test-1"
```

- Upload JSON BOM file

```shell
file_content=$(base64 -i merged_sbom.json)

curl -v -X PUT \
  -H "Content-Type: application/json" \
  -H "X-API-Key: ${DEPENDENCY_TRACK_API_KEY}" \
  --data @- ${D_TRACK_PATH} <<EOF
{
  "projectName": "${DEPENDENCY_TRACK_PROJECT_NAME}",
  "projectVersion": "${APP_VERSION}",
  "autoCreate": true,
  "bom": "${file_content}"
}
EOF
```

- Merge all SBOM files to one

```shell
FILES="apps/core-server/bom.json apps/migration/bom.json lib/one-core/bom.json lib/shared-types/bom.json lib/sql-data-provider/bom.json platforms/uniffi/bom.json platforms/uniffi-bindgen/bom.json"
cyclonedx-cli merge --input-files ${FILES} --input-format=json --output-format=json > merged_sbom.json
```

### Testing

##### Run tests

```shell
cargo llvm-cov --no-clean --workspace --release --ignore-filename-regex=".*test.*\.rs$|tests/.*\.rs$"
```

##### Generate report

- Cobertura

```shell
cargo llvm-cov report --release --cobertura --output-path cobertura.xml
```

- Lcov

```shell
cargo llvm-cov report --release --lcov --output-path lcov.info
```
