<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://assets.procivis-one.com/static/logo/logo_light_One_Core.png">
  <source media="(prefers-color-scheme: light)" srcset="https://assets.procivis-one.com/static/logo/logo_dark_One_Core.png">
  <img alt="Shows a Procivis One Core black logo in light color mode and a white one in dark color mode." src="https://assets.procivis-one.com/static/logo/logo_dark_One_Core.png">
</picture>

## Table of Contents

- [Getting started](#getting-started)
- [Background](#background)
- [EU Digital Identity Ecosystem](#eu-digital-identity-ecosystem)
- [Interoperability and conformance](#interoperability-and-conformance)
- [Standards and technologies](#standards-and-technologies)
- [Support](#support)
- [License](#license)

The *Procivis One Core* is a robust solution capable of powering every element of the
digital identity credential lifecycle, flexibly handling a broad array of different
protocols and trust models, ensuring compatibility with different digital identity
regulations, and can be installed and operated almost anywhere, ensuring seamless
integration through a powerful API.

*Procivis One* is built to connect your organization to the SSI ecosystem, become
compatible with regulations such as [**eIDAS 2.0**](#eidas-20), and be extensible as
new regulations and requirements emerge.

See the [key features][key] and complete solution [architecture][archi].

## Get started

### Prerequisites

- Rust - [Install via rustup.rs][rust]. See `rust-version` in `Cargo.toml`
  for the minimum required version. Any stable release at or above that
  works fine.
- Docker with Docker Compose - [Docker Desktop][dock] recommended for
  easiest setup.
- cargo-make: `cargo install cargo-make`

### Quick start

1. Verify Docker is running: `docker compose version`

2. Compile the project: `makers build`

3. Start the database: `makers dbstart`

4. Start the server: `makers run`

5. Open http://localhost:3000/swagger-ui/index.html
  *You should see the Swagger UI interface*

6. Click the green "Authorize" button and set the authorization bearer
  token: `test`

&rarr; *You can now make API calls directly to the server using
  the Swagger UI interface*

**What's running:**
- Database: running in Docker
- API server: http://localhost:3000
- Swagger UI: http://localhost:3000/swagger-ui/index.html

### Next steps

See [Getting Started with Credentials][get-started] on the docs.

### Troubleshooting

- Issues compiling - check `rustc --version` and run `rustup update`
  if your version is below the version specified in `Cargo.toml`.
- Issues starting the database - make sure Docker is running.
  - Mac: you should see the whale icon in your menu bar.
  - Windows: you should see the whale icon in your system tray.
- Issues making API calls - make sure you have added the authorization
  bearer token `test` to the swagger.
  - If you still have issues with calls, check the value of
  `app.authToken` in `config/config-local.yml` as this determines
  your authorization token.

### Advanced configurations

Values set in `dev.env` will override the configuration files found
in `/config`.

- Set a new server authorization token: `ONE_app__authToken=yourTokenHere`
- Provide new encryption tokens for OpenID4VCI and private keys (default
  configuration has placeholder values allowing the server to start):
  - `ONE_issuanceProtocol__OPENID4VCI_FINAL1__params__private__encryption=yourTokenHere`
  - `ONE_issuanceProtocol__OPENID4VCI_FINAL1_HAIP__params__private__encryption=yourTokenHere`
  - `ONE_issuanceProtocol__OPENID4VCI_FINAL1_SWIYU__params__private__encryption=yourTokenHere`
  - `ONE_keyStorage__INTERNAL__params__private__encryption=yourTokenHere`

Encryption keys must be a 32 byte hex-encoded value. Use
`openssl rand -hex 32` or another qualified tool to generate a
cryptographically-secure key.

For more, see [Operations][operations].

### Trial

You can use the full enterprise stack when you [join our Trial Environment][trial].
Here you are given control of an organization in the Procivis One Desk UI.

### Tests

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

To run integration-tests with MariaDB

```shell
makers dbstart
ONE_app__databaseUrl="mysql://root:Qpq5nDb5MKD6v9bt8dPD@localhost/core" makers integration-tests
```

To run integration-tests with Postgres

```shell
makers dbstart_postgres
ONE_app__databaseUrl="postgresql://core:886eOqVMmlHsayu6Vyxw@localhost/core" makers integration-tests
```

### Run Wallet

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

### Docker

- Run MariaDB for local developing

```shell
docker compose -f docker/db.yml up -d
or
makers dbstart
```

- Stop MariaDB for local developing

```shell
docker compose -f docker/db.yml down
or
makers dbstop
```

- Drop MariaDB for local developing - removes everything

```shell
makers dbdrop
```

- Print MariaDB logs

```shell
docker compose -f docker/db.yml logs -f
```

- Build project

```shell
docker build -t one-core -f docker/Dockerfile .
```

- Run project on Windows or Mac

```shell
docker run --init -p 3000:3000 -it --rm \
  -e RUST_BACKTRACE=full \
  -e ONE_app__databaseUrl=mysql://core:886eOqVMmlHsayu6Vyxw@host.docker.internal/core \
  one-core --config config/config-procivis-base.yml --config config/config-local.yml
```

- Run project on Linux

```shell
docker run --init -p 3000:3000 -it --rm \
  -e RUST_BACKTRACE=full \
  -e ONE_app__databaseUrl=mysql://core:886eOqVMmlHsayu6Vyxw@172.17.0.1/core \
  one-core --config config/config-procivis-base.yml --config config/config-local.yml
```

- Run shell in the container

```shell
docker run -it --rm --entrypoint="" one-core bash
```

### SBOM

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
FILES="apps/core-server/bom.json lib/migration/bom.json lib/one-core/bom.json lib/shared-types/bom.json lib/sql-data-provider/bom.json platforms/uniffi/bom.json platforms/uniffi-bindgen/bom.json"
cyclonedx-cli merge --input-files ${FILES} --input-format=json --output-format=json > merged_sbom.json
```

#### Testing

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

#### Migration

##### Generate new migration

- Using Sea-ORM CLI

```shell
makers generate_migration description_of_new_migration
```

## Background

Decentralized digital identities and credentials is an approach to identity that relocates
digital credentials from the possession and control of centralized authorities to the
digital wallet of the credentials holder. This architecture eliminates the need for the
user to "phone home" to use their credentials as well as the verifier to communicate to
the issuer via back-channels, keeping the wallet holder's interactions private between only
those parties directly involved in each interaction. This model of digital identity is
often referred to as Self-Sovereign Identity, or SSI.

## EU Digital Identity Ecosystem

*Procivis One* provides solutions for multiple roles within this ecosystem:

![Procivis One in the EU Digital Identity Ecosystem](https://onesdk.blob.core.windows.net/doc-assets/img/EUDI_Architecture.png)

Use the *Procivis One Core* for Issuer or Verifier solutions. For an EUDI Wallet, use the
[One Core React Native SDK][rncore] for embedding into an existing app, or use the
[Procivis One Wallet][pow] with adaptations to fit your needs.

## Interoperability and conformance

*Procivis One* is built using [open standards](#supported-standards) and tested to ensure
interoperability with different software vendors and across different international
regulatory ecosystems.

- W3C standards
  - The W3C offers several test suites for standards conformance. See
    the latest test results for Procivis One at [canivc.com][canivc].
- ISO/IEC 18013-5 mDL
  - *Procivis One*'s implementation of the ISO mDL standard is compatible with the
    OpenWallet Foundation's verifier: *Procivis One* can successfully issue mDL
    credentials to a *Procivis One Wallet*, and these credentials can successfully
    be verified by the OpenWallet Foundation's verifier. See the [OpenWallet Foundation libraries][owf].
- eIDAS 2.0; EUDI Wallet
  - The EU Digital Wallet is developing [issuer][eudiwi] and [verifier][eudiwv] testing for
    interoperability in mdoc and SD-JWT formats using OID4VC protocols. We follow the ongoing
    development of the testing platform and regularly test against it.

We continue to look for more opportunities for interoperability testing as the standards
and regulations mature and harden.

## Standards and technologies

| Category | Supported |
| -------- | --------- |
| Credential formats | SD-JWT VC, ISO mdoc, W3C VC |
| Issuance protocol | OpenID4VCI |
| Presentation protocols | OpenID4VP, ISO/IEC 18013-5, ISO/IEC 18013-7 |
| Transport and engagement | BLE, MQTT, NFC, QR code |
| Revocation | Bitstring Status List, Token Status List, CRL |
| Key storage | Secure Enclave, Android Keystore, Azure Key Vault, HSM, internal database |
| DID methods | did\:key, did\:web, did\:jwk, did\:webvh |
| Trust infrastructure | ETSI Trusted Lists, Lists of Trusted Lists (LoTL), and Lists of Trusted Entities (LoTE), EUDI Access and Registration Certificates |
| Cryptographic suites | ES256, Ed25519, ML-DSA-65, BBS |
| Wallet attestations | Wallet Unit Attestation (WUA) and Wallet Instance Attestation (WIA) |

For the full list of supported standards, specifications, protocol versions, and
ETSI coverage, see the [Supported Standards and Technologies][supptech] page in
the Procivis One documentation.

## Support

Need support or have feedback? [Contact us](https://www.procivis.ch/en/contact).

## License

Some rights reserved. This library is published under the [Apache License
Version 2.0](./LICENSE).

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://assets.procivis-one.com/static/logo/logo_dark_mode_Procivis.svg">
  <source media="(prefers-color-scheme: light)" srcset="https://assets.procivis-one.com/static/logo/logo_light_mode_Procivis.svg">
  <img alt="Shows a Procivis black logo in light color mode and a white one in dark color mode." src="https://assets.procivis-one.com/static/logo/logo_dark_mode_Procivis.svg">
</picture>

© Procivis AG, [https://www.procivis.ch](https://www.procivis.ch).

[apidocs]: https://docs.procivis.ch/apis
[apiref]: https://docs.procivis.ch/docs/core-api
[archi]: https://github.com/procivis#architecture
[canivc]: https://canivc.com/implementations/procivis-one-core/
[operations]: https://docs.procivis.ch/operations
[dock]: https://docs.docker.com/get-started/get-docker/
[docs]: https://docs.procivis.ch/
[eudiwi]: https://issuer.eudiw.dev/
[eudiwv]: https://verifier.eudiw.dev/home
[get-started]: https://docs.procivis.ch/getting-started/credentials
[jld]: https://www.w3.org/TR/json-ld11/
[key]: https://github.com/procivis#key-features
[owf]: https://github.com/openwallet-foundation-labs/identity-credential
[pow]: https://github.com/procivis/one-wallet
[rncore]: https://github.com/procivis/react-native-one-core
[rust]: https://rustup.rs/
[sdkref]: https://docs.procivis.ch/sdk
[supptech]: https://docs.procivis.ch/standards
[trial]: https://docs.procivis.ch/trial
