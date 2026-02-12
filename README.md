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
- [Supported standards](#supported-standards)
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

- Rust 1.92+ - [Install via rustup.rs][rust]
- Docker with Docker Compose - [Docker Desktop][dock] recommended for
  easiest setup
- Install cargo-make: `cargo install cargo-make`

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

If you want some guidance on where to go from here, see
[Issue your first credential][issue-first] on the docs.

### Troubleshooting

- Issues compiling - check `rustc --version` and run `rustup update`
  if your version is <1.88.
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
  - `ONE_issuanceProtocol__OPENID4VCI_DRAFT13__params__private__encryption=yourTokenHere`
  - `ONE_issuanceProtocol__OPENID4VCI_DRAFT13_SWIYU__params__private__encryption=yourTokenHere`
  - `ONE_keyStorage__INTERNAL__params__private__encryption=yourTokenHere`

Encryption keys must be a 32 byte hex-encoded value. Use
`openssl rand -hex 32` or another qualified tool to generate a
cryptographically-secure key.

For more, see the [configuration guide][config].

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

## Supported standards

### Credential models

#### W3C VC

- [W3C Verifiable Credentials Data Model 2.0][vcdm] in the following variations:

| Securing mechanism                           | Supported representations                           | Supported proof/signature types                                                          |
| -------------------------------------------- | ----------------------------------------- | ------------------------------------------------------------------------------ |
| [W3C Data Integrity Proofs][vcdi] (embedded) | [JSON-LD][jld] in Compacted Document Form | <ul><li>[W3C Data Integrity ECDSA Cryptosuites v1.0][ecd] / [ecdsa-rdfc-2019][ecd2019]</li><li>[W3C Data Integrity EdDSA Cryptosuites v1.0][edd] / [eddsa-rdfc-2022][edd2022]</li><li>[W3C Data Integrity BBS Cryptosuites v1.0][bbs] / [bbs-2023][bbs2023]</li></ul> |
| [W3C VC-JOSE-COSE][jose] (enveloping)        | <ul><li>[SD-JWT][sdjwt]</li><li>[JWT][jw]</li></ul> | <ul><li>JOSE / ECDSA [ES256][es2]</li><li>JOSE / EdDSA [Ed25519][ed255]</li><li>JOSE / CRYSTALS-DILITHIUM 3 [CRYDI3][crydi3]* |

\* CRYSTALS-DILITHIUM is a post-quantum resistant signature scheme, selected by NIST for [Post-Quantum Cryptography Standardization][pqc].
Support for the recently published [FIPS-204][fips] is planned for the near future.

- **Backwards compatibility**: Procivis One supports verification of proofs which use VCDM 1.1.

- **Additional VC formats**: Procivis One supports verification of VCs embedded in optical barcodes.
See [Verifiable Credentials Barcode v0.7][vcbarcode].

#### ISO mdoc

- [ISO/IEC 18013-5:2021][iso5] standard for mdoc credentials.
  - [COSE][cose] proofs
    - ECDSA [ES256][es2]
    - EdDSA [Ed25519][ed255]

#### IETF SD-JWT VC

- [IETF SD-JWT-based Verifiable Credentials][sdjwtvc]:

| Standard       | Supported representations | Supported proof/signature types                                                                                                          |
| -------------- | ------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| IETF SD-JWT VC | SD-JWT                    | <ul><li>JOSE / ECDSA [ES256][es2]</li><li>JOSE / EdDSA [Ed25519][ed255]</li><li>JOSE / CRYSTALS-DILITHIUM 3 [CRYDI3][crydi3]\*</li></ul> |

\* CRYSTALS-DILITHIUM is a post-quantum resistant signature scheme, selected by NIST for [Post-Quantum Cryptography Standardization][pqc].
Support for the recently published [FIPS-204][fips] is planned for the near future.

### Exchange and transport

- OpenID4VCI (Issuance)
  - [v1.0][vci1]
  - [ID-1][vci]
- OpenID4VP (Verification)
  - [v1.0][vp1.0]
  - [Draft 25][vp25]
  - [Draft 20][vp20]
  - [OID4VP over BLE][ble]; optimized version of Draft 00
  - OID4VP over MQTT; proprietary adaptation of "OID4VP over BLE" via MQTT channel
- ISO/IEC 18013
  - [18013-5][iso5]: Device engagement using either NFC or QR Code, data retrieval using BLE
  - [18013-7][iso7]: Online data retrieval via OID4VP

### Key storage

- Secure Enclave (iOS) and Android Keystore (TEE or Strongbox)
- Azure Key Vault (HSM)
- Internal encrypted database

### Revocation methods

- [Bitstring Status List v1.0][sl]
- [Linked Validity Verifiable Credentials (LVVC)][lvvc]
- [Token Status List - Draft 03][tsl]

### DID methods

- [Decentralized Identifiers (DIDs) v1.0][did]
  - [did:key][dk]
  - [did:web][dw]
  - [did:jwk][djw]
  - [did:webvh][webvh]
- [Universal DID resolution][univ]

See our [supported technology][supptech] page for more details.

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
[bbs]: https://www.w3.org/TR/vc-di-bbs/
[bbs2023]: https://www.w3.org/TR/vc-di-bbs/#bbs-2023
[ble]: https://openid.net/specs/openid-4-verifiable-presentations-over-ble-1_0.html
[canivc]: https://canivc.com/implementations/procivis-one-core/
[config]: https://docs.procivis.ch/configure
[cose]: https://www.rfc-editor.org/rfc/rfc9052
[crydi3]: https://datatracker.ietf.org/doc/html/draft-ietf-cose-dilithium-01
[did]: https://www.w3.org/TR/did-core/
[djw]: https://github.com/quartzjer/did-jwk/blob/main/spec.md
[dk]: https://w3c-ccg.github.io/did-method-key/
[dock]: https://docs.docker.com/get-started/get-docker/
[docs]: https://docs.procivis.ch/
[dw]: https://w3c-ccg.github.io/did-method-web/
[ecd]: https://www.w3.org/TR/vc-di-ecdsa/
[ecd2019]: https://www.w3.org/TR/vc-di-ecdsa/#ecdsa-rdfc-2019
[edd]: https://www.w3.org/TR/vc-di-eddsa/
[edd2022]: https://www.w3.org/TR/vc-di-eddsa/#eddsa-rdfc-2022
[ed255]: https://datatracker.ietf.org/doc/html/rfc8037
[es2]: https://datatracker.ietf.org/doc/html/rfc7518
[eudiwi]: https://issuer.eudiw.dev/
[eudiwv]: https://verifier.eudiw.dev/home
[fips]: https://csrc.nist.gov/pubs/fips/204/final
[iso5]: https://www.iso.org/standard/69084.html
[iso7]: https://www.iso.org/standard/82772.html
[issue-first]: https://docs.procivis.ch/get-started/issue
[jld]: https://www.w3.org/TR/json-ld11/
[jose]: https://w3c.github.io/vc-jose-cose/
[jw]: https://datatracker.ietf.org/doc/html/rfc7519
[key]: https://github.com/procivis#key-features
[lvvc]: https://eprint.iacr.org/2022/1658.pdf
[owf]: https://github.com/openwallet-foundation-labs/identity-credential
[pow]: https://github.com/procivis/one-wallet
[pqc]: https://csrc.nist.gov/pqc-standardization
[rncore]: https://github.com/procivis/react-native-one-core
[rust]: https://rustup.rs/
[sdjwt]: https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-12.html
[sdjwtvc]: https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-05.html
[sdkref]: https://docs.procivis.ch/sdk/overview
[sl]: https://www.w3.org/TR/vc-bitstring-status-list/
[supptech]: https://docs.procivis.ch/standards
[trial]: https://docs.procivis.ch/trial
[tsl]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-03
[univ]: https://dev.uniresolver.io
[vcbarcode]: https://w3c-ccg.github.io/vc-barcodes/
[vcdi]: https://www.w3.org/TR/vc-data-integrity/
[vcdm]: https://www.w3.org/TR/vc-data-model-2.0/
[vci]: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html
[vci1]: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html
[vp1.0]: https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html
[vp20]: https://openid.net/specs/openid-4-verifiable-presentations-1_0-20.html
[vp25]: https://openid.net/specs/openid-4-verifiable-presentations-1_0-25.html
[webvh]: https://identity.foundation/didwebvh/v0.3/
