use std::any::type_name;

use WalletProviderError::AppIntegrityValidationError;
use ct_codecs::{Base64, Decoder};
use itertools::Itertools;
use one_crypto::Hasher;
use one_crypto::hasher::sha256::SHA256;
use serde::Deserialize;
use serde::de::DeserializeOwned;

use crate::provider::key_algorithm::key::KeyHandle;
use crate::service::certificate::validator::{CertificateValidator, ParsedCertificate};
use crate::service::ssi_wallet_provider::dto::IOSBundle;
use crate::service::ssi_wallet_provider::error::WalletProviderError;

static CRED_CERT_EXTENSION_OID: &str = "1.2.840.113635.100.8.2";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Attestation {
    #[allow(unused)]
    fmt: String,
    #[serde(rename = "attStmt")]
    attestation_statement: AttestationStatement,
    auth_data: Vec<u8>,
}

#[derive(Debug, Deserialize)]
struct AttestationStatement {
    x5c: Vec<Vec<u8>>,
    #[allow(unused)]
    receipt: Vec<u8>,
}

pub(crate) async fn validate_attestation_ios(
    attestation: &str,
    server_nonce: &str,
    bundle: &IOSBundle,
    certificate_validator: &dyn CertificateValidator,
) -> Result<KeyHandle, WalletProviderError> {
    let attestation = decode_cbor_base64::<Attestation>(attestation)?;
    let attestation_cert = validate_against_ca_certs(
        certificate_validator,
        &bundle.trusted_attestation_cas,
        &attestation,
    )
    .await?;
    validate_nonce(
        attestation.auth_data.clone(),
        server_nonce,
        &attestation_cert,
    )?;

    // RP_ID is the first 32 bytes of the authenticator data, which must be equal to the app id hash.
    let rp_id = &attestation.auth_data[..32];
    let app_id_hash = SHA256
        .hash(bundle.bundle_id.as_bytes())
        .map_err(|err| AppIntegrityValidationError(format!("Failed to hash: {err}")))?;
    if rp_id != app_id_hash {
        return Err(AppIntegrityValidationError("App id mismatch".to_string()));
    }

    Ok(attestation_cert.public_key)
}

fn validate_nonce(
    auth_data: Vec<u8>,
    server_nonce: &str,
    attestation_cert: &ParsedCertificate,
) -> Result<(), WalletProviderError> {
    let mut client_data = auth_data;
    client_data.extend_from_slice(server_nonce.as_bytes());
    let nonce = SHA256
        .hash(&client_data)
        .map_err(|err| AppIntegrityValidationError(format!("Failed to hash: {err}")))?;
    let ext = attestation_cert
        .attributes
        .extensions
        .iter()
        .find(|ext| ext.oid == CRED_CERT_EXTENSION_OID)
        .ok_or(AppIntegrityValidationError(format!(
            "Failed to find mandatory cred cert extension {CRED_CERT_EXTENSION_OID}"
        )))?;
    // This is a DER encoded nested octet sequence, of which the last 32 bytes are the actual data
    // we are interested in.
    // Rather than parsing the sequence, we can simply drop the prefix and extract the data.
    let ext_data = hex::decode(&ext.value).map_err(|err| {
        AppIntegrityValidationError(format!("Failed to decode cred cert extension value: {err}"))
    })?;
    if ext_data.len() < 32 {
        return Err(AppIntegrityValidationError(format!(
            "Unexpected payload of cred cert extension: {}",
            ext.value
        )));
    }
    let cert_nonce = &ext_data[ext_data.len() - 32..];
    if cert_nonce != nonce.as_slice() {
        return Err(AppIntegrityValidationError("Nonce mismatch".to_string()));
    }
    Ok(())
}

async fn validate_against_ca_certs(
    certificate_validator: &dyn CertificateValidator,
    ca_certs: &[String],
    attestation: &Attestation,
) -> Result<ParsedCertificate, WalletProviderError> {
    let mut errs = vec![];
    for ca_pem in ca_certs {
        let result = certificate_validator
            .validate_der_chain_against_ca(attestation.attestation_statement.x5c.clone(), ca_pem)
            .await;
        match result {
            Ok(cert) => return Ok(cert),
            Err(err) => errs.push(err),
        }
    }
    Err(AppIntegrityValidationError(format!(
        "failed to validate attestation against CA certs: [{}]",
        errs.into_iter().join(", ")
    )))
}

pub(crate) fn decode_cbor_base64<T: DeserializeOwned>(s: &str) -> Result<T, WalletProviderError> {
    let bytes = Base64::decode_to_vec(s, None)
        .map_err(|err| AppIntegrityValidationError(format!("Base64 decoding failed: {err}")))?;
    let type_name = type_name::<T>();
    ciborium::de::from_reader(&bytes[..]).map_err(|err| {
        AppIntegrityValidationError(format!(
            "CBOR deserialization into `{type_name}` failed: {err}"
        ))
    })
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;

    use time::Duration;
    use time::macros::datetime;

    use super::*;
    use crate::config::core_config::KeyAlgorithmType;
    use crate::provider::caching_loader::x509_crl::{X509CrlCache, X509CrlResolver};
    use crate::provider::http_client::reqwest_client::ReqwestClient;
    use crate::provider::key_algorithm::KeyAlgorithm;
    use crate::provider::key_algorithm::ecdsa::Ecdsa;
    use crate::provider::key_algorithm::provider::KeyAlgorithmProviderImpl;
    use crate::provider::remote_entity_storage::in_memory::InMemoryStorage;
    use crate::service::certificate::validator::CertificateValidatorImpl;
    use crate::util::clock::MockClock;

    // Official test vector: https://developer.apple.com/documentation/devicecheck/attestation-object-validation-guide
    static APPLE_ATTESTATION_CA: &str = "-----BEGIN CERTIFICATE-----
MIICITCCAaegAwIBAgIQC/O+DvHN0uD7jG5yH2IXmDAKBggqhkjOPQQDAzBSMSYw
JAYDVQQDDB1BcHBsZSBBcHAgQXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UECgwK
QXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODMyNTNa
Fw00NTAzMTUwMDAwMDBaMFIxJjAkBgNVBAMMHUFwcGxlIEFwcCBBdHRlc3RhdGlv
biBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9y
bmlhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAERTHhmLW07ATaFQIEVwTtT4dyctdh
NbJhFs/Ii2FdCgAHGbpphY3+d8qjuDngIN3WVhQUBHAoMeQ/cLiP1sOUtgjqK9au
Yen1mMEvRq9Sk3Jm5X8U62H+xTD3FE9TgS41o0IwQDAPBgNVHRMBAf8EBTADAQH/
MB0GA1UdDgQWBBSskRBTM72+aEH/pwyp5frq5eWKoTAOBgNVHQ8BAf8EBAMCAQYw
CgYIKoZIzj0EAwMDaAAwZQIwQgFGnByvsiVbpTKwSga0kP0e8EeDS4+sQmTvb7vn
53O5+FRXgeLhpJ06ysC5PrOyAjEAp5U4xDgEgllF7En3VcE3iexZZtKeYnpqtijV
oyFraWVIyd/dganmrduC1bmTBGwD
-----END CERTIFICATE-----";
    static TEST_ATTESTATION: &str = "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";
    static APP_ID_PREFIX: &str = "0352187391";
    static BUNDLE_ID: &str = "com.apple.example_app_attest";
    static SERVER_NONCE: &str = "test_server_challenge";

    #[tokio::test]
    async fn validate_attestation_success() {
        let key_algorithm_provider =
            Arc::new(KeyAlgorithmProviderImpl::new(HashMap::from_iter(vec![(
                KeyAlgorithmType::Ecdsa,
                Arc::new(Ecdsa) as Arc<dyn KeyAlgorithm>,
            )])));

        let crl_cache = Arc::new(X509CrlCache::new(
            Arc::new(X509CrlResolver::new(Arc::new(ReqwestClient::default()))),
            Arc::new(InMemoryStorage::new(HashMap::new())),
            100,
            Duration::days(1),
            Duration::days(1),
        ));
        let mut clock = MockClock::new();
        clock
            .expect_now_utc()
            .returning(|| datetime!(2024-04-18 0:00 UTC)); // a date the test vector happens to be valid at
        let certificate_validator =
            CertificateValidatorImpl::new(key_algorithm_provider, crl_cache, Arc::new(clock));
        validate_attestation_ios(
            TEST_ATTESTATION,
            SERVER_NONCE,
            &IOSBundle {
                bundle_id: format!("{APP_ID_PREFIX}.{BUNDLE_ID}"),
                trusted_attestation_cas: vec![APPLE_ATTESTATION_CA.to_string()],
            },
            &certificate_validator,
        )
        .await
        .expect("Failed to validate attestation");
    }
}
