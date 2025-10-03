use std::any::type_name;

use WalletProviderError::AppIntegrityValidationError;
use ct_codecs::{Base64, Decoder};
use itertools::Itertools;
use one_crypto::Hasher;
use one_crypto::hasher::sha256::SHA256;
use one_crypto::utilities::ecdsa_sig_from_der;
use serde::Deserialize;
use serde::de::DeserializeOwned;

use crate::provider::key_algorithm::key::KeyHandle;
use crate::service::certificate::validator::{
    CertSelection, CertificateValidationOptions, CertificateValidator, ParsedCertificate,
};
use crate::service::error::ServiceError;
use crate::service::ssi_wallet_provider::dto::IOSBundle;
use crate::service::ssi_wallet_provider::error::WalletProviderError;
use crate::util::jwt::model::DecomposedToken;
use crate::util::x509::der_chain_into_pem_chain;

static CRED_CERT_EXTENSION_OID: &str = "1.2.840.113635.100.8.2";

static APPATEST_DEVELOP: &[u8] = "appattestdevelop".as_bytes();
static APPATEST_PRODUCTION: &[u8] = concat!("appattest", "\0\0\0\0\0\0\0").as_bytes();

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

    if attestation.auth_data.len() < 55 {
        return Err(AppIntegrityValidationError(format!(
            "Invalid auth data length: must be at least 55 bytes but was only {} bytes",
            attestation.auth_data.len()
        )));
    }

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

    // See https://www.w3.org/TR/webauthn/#sctn-attestation for a diagram of the layout of
    // authenticator data.

    // RP_ID is the first 32 bytes of the authenticator data, which must be equal to the app id hash.
    let rp_id = &attestation.auth_data[..32];
    let app_id_hash = SHA256
        .hash(bundle.bundle_id.as_bytes())
        .map_err(|err| AppIntegrityValidationError(format!("Failed to hash: {err}")))?;
    if rp_id != app_id_hash {
        return Err(AppIntegrityValidationError("App id mismatch".to_string()));
    }

    // Signature counter of the particular key
    let counter = u32::from_be_bytes(attestation.auth_data[33..37].try_into().map_err(|err| {
        AppIntegrityValidationError(format!(
            "Failed to read signature counter from authenticator data: {err}"
        ))
    })?);
    if counter != 0 {
        return Err(AppIntegrityValidationError(format!(
            "Invalid signature counter: must be 0 but was {counter}"
        )));
    }

    // Either appattestdevelop or appattest (zero padded)
    let aaguid = &attestation.auth_data[37..53];
    if !(aaguid == APPATEST_PRODUCTION
        || !bundle.enforce_production_build && aaguid == APPATEST_DEVELOP)
    {
        return Err(AppIntegrityValidationError("Invalid AAGUID".to_string()));
    }
    let credential_id_len =
        u16::from_be_bytes(attestation.auth_data[53..55].try_into().map_err(|err| {
            AppIntegrityValidationError(format!(
                "Failed to read credential id length from authenticator data: {err}"
            ))
        })?) as usize;

    if attestation.auth_data.len() < 55 + credential_id_len {
        return Err(AppIntegrityValidationError(format!(
            "Invalid credential id length: credential id does not fit in auth data by {} bytes",
            55 + credential_id_len - attestation.auth_data.len()
        )));
    }
    let credential_id = &attestation.auth_data[55..(55 + credential_id_len)];
    let cn = attestation_cert
        .subject_common_name
        .ok_or(AppIntegrityValidationError(
            "Missing common name in attestation certificate".to_string(),
        ))?;
    if credential_id
        != hex::decode(cn).map_err(|err| {
            AppIntegrityValidationError(format!("Failed to decode common name: {err}"))
        })?
    {
        return Err(AppIntegrityValidationError(
            "Credential id mismatch".to_string(),
        ));
    }

    Ok(attestation_cert.public_key)
}

fn validate_nonce(
    mut auth_data: Vec<u8>,
    server_nonce: &str,
    attestation_cert: &ParsedCertificate,
) -> Result<(), WalletProviderError> {
    let client_data_hash = SHA256
        .hash(server_nonce.as_bytes())
        .map_err(|err| AppIntegrityValidationError(format!("Failed to hash: {err}")))?;
    auth_data.extend(client_data_hash);
    let nonce = SHA256
        .hash(&auth_data)
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
    let pem_chain = der_chain_into_pem_chain(attestation.attestation_statement.x5c.clone())
        .map_err(|e| AppIntegrityValidationError(e.to_string()))?;
    let mut errs = vec![];
    for ca_pem in ca_certs {
        let result = certificate_validator
            .validate_chain_against_ca_chain(
                &pem_chain,
                ca_pem,
                CertificateValidationOptions::full_validation(None),
                CertSelection::Leaf,
            )
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

pub(crate) fn webauthn_signed_jwt_to_msg_and_sig(
    proof: &DecomposedToken<()>,
) -> Result<(Vec<u8>, Vec<u8>), ServiceError> {
    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct WebAuthnSignature {
        signature: Vec<u8>,
        authenticator_data: Vec<u8>,
    }
    let webauthn_sig: WebAuthnSignature =
        ciborium::de::from_reader(&proof.signature[..]).map_err(|err| {
            AppIntegrityValidationError(format!("Failed to deserialize webauthn signature: {err}"))
        })?;
    let mut msg = webauthn_sig.authenticator_data;
    msg.extend(SHA256.hash(proof.unverified_jwt.as_bytes()).map_err(|e| {
        WalletProviderError::CouldNotVerifyProof(format!("failed to hash token payload: {e}"))
    })?);
    let msg = SHA256.hash(&msg).map_err(|e| {
        WalletProviderError::CouldNotVerifyProof(format!("failed to hash message: {e}"))
    })?;
    let sig = ecdsa_sig_from_der(&webauthn_sig.signature).map_err(|e| {
        WalletProviderError::CouldNotVerifyProof(format!("failed parse signature: {e}"))
    })?;
    Ok((msg, sig))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;

    use serde_json::json;
    use time::Duration;
    use time::macros::datetime;
    use uuid::Uuid;

    use super::*;
    use crate::config;
    use crate::config::core_config::{CoreConfig, Fields, KeyAlgorithmType, Params};
    use crate::provider::caching_loader::android_attestation_crl::{
        AndroidAttestationCrlCache, AndroidAttestationCrlResolver,
    };
    use crate::provider::caching_loader::x509_crl::{X509CrlCache, X509CrlResolver};
    use crate::provider::http_client::reqwest_client::ReqwestClient;
    use crate::provider::key_algorithm::KeyAlgorithm;
    use crate::provider::key_algorithm::ecdsa::Ecdsa;
    use crate::provider::key_algorithm::provider::KeyAlgorithmProviderImpl;
    use crate::provider::remote_entity_storage::in_memory::InMemoryStorage;
    use crate::service::certificate::validator::{
        CertificateValidationOptions, CertificateValidatorImpl,
    };
    use crate::util::clock::{Clock, DefaultClock, MockClock};
    use crate::util::jwt::Jwt;

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

    // Attestation produced by Eugenius test phone
    const EXAMPLE_APP_ATTESTATION: &str = "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";
    #[tokio::test]
    async fn validate_attestation_success_example_app() {
        let mut clock = MockClock::new();
        clock
            .expect_now_utc()
            .returning(|| datetime!(2025-09-09 0:00 UTC)); // a date the test vector happens to be valid at
        let certificate_validator = test_cert_validator(Arc::new(clock));
        validate_attestation_ios(
            EXAMPLE_APP_ATTESTATION,
            "test",
            &IOSBundle {
                bundle_id: "AGG3V6QN4G.ch.procivis.one.wallet.dev".to_string(),
                trusted_attestation_cas: vec![APPLE_ATTESTATION_CA.to_string()],
                enforce_production_build: false,
            },
            &certificate_validator,
        )
        .await
        .expect("Failed to validate attestation");
    }

    #[tokio::test]
    async fn ios_verify_proof() {
        let certificate_validator = test_cert_validator(Arc::new(DefaultClock));

        let mut config = CoreConfig::default();
        config
            .wallet_provider
            .insert("PROCIVIS_ONE".to_string(), wallet_provider_config());
        let cert = "-----BEGIN CERTIFICATE-----
MIIDVjCCAtygAwIBAgIGAZkzmWcEMAoGCCqGSM49BAMCME8xIzAhBgNVBAMMGkFw
cGxlIEFwcCBBdHRlc3RhdGlvbiBDQSAxMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMw
EQYDVQQIDApDYWxpZm9ybmlhMB4XDTI1MDkwOTEyMjgzNVoXDTI2MDkwMjAyNDkz
NVowgZExSTBHBgNVBAMMQGY4ZDY2NjUzMWY3OTEzMjRmOWM3ZTNlZGY5NzcxODUx
MmM3NGNjNjBmYTU0N2NjMzUyNDg5MzkzOWE4OTVmNzExGjAYBgNVBAsMEUFBQSBD
ZXJ0aWZpY2F0aW9uMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxp
Zm9ybmlhMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEobAMbYiHydF3WSoObUym
coesxE3im6rg8F1qxuzxdDBoQFu/ntccaRLNE42Rd+dfxZfp8kHJcQG8K8d8Px6o
0aOCAV8wggFbMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgTwMIGXBgkqhkiG
92NkCAUEgYkwgYakAwIBCr+JMAMCAQG/iTEDAgEAv4kyAwIBAb+JMwMCAQG/iTQn
BCVBR0czVjZRTjRHLmNoLnByb2NpdmlzLm9uZS53YWxsZXQuZGV2pQYEBHNrcyC/
iTYDAgEFv4k3AwIBAL+JOQMCAQC/iToDAgEAv4k7AwIBAKoDAgEAv4k8BgIEc2tz
IDBsBgkqhkiG92NkCAcEXzBdv4p4CAQGMTcuNy4xv4hQBwIFAP////6/inkJBAcx
LjAuMTk4v4p7CAQGMjFIMjE2v4p8AgQAv4p9CAQGMTcuNy4xv4p+AwIBAL+LDBAE
DjIxLjguMjE2LjAuMCwwMDMGCSqGSIb3Y2QIAgQmMCShIgQgDpxJC18owzGw4R7G
tMMde/ll2kJYeF3eAHwtaerFM3swCgYIKoZIzj0EAwIDaAAwZQIxAJdPLI6+5fJk
2KdiPNA6v1oBFVWJu2WsAbLSKi1cV2xCCZgeYR6CyEFkd5FVhSgKvwIwX4iUzd61
Q3RkxoFO2GgviGuVD2ukPNuGJ7FHCvecJ8sNRqyqBrydvuQAO2zStDp3
-----END CERTIFICATE-----";
        let certificate = certificate_validator
            .parse_pem_chain(cert, CertificateValidationOptions::no_validation())
            .await
            .unwrap();
        let token = "eyJhbGciOiJFUzI1NiIsInR5cCI6Imp3dCJ9.eyJpYXQiOjE3NTc1MDczMTUsImV4cCI6MTc1NzUxMDkxNSwibmJmIjoxNzU3NTA3MzE1LCJhdWQiOiJodHRwczovL2NvcmUuZGV2LnByb2NpdmlzLW9uZS5jb20ifQ.omlzaWduYXR1cmVYRzBFAiEA_o4x5n1J9431oVI5HsFGfhH61g9jWLt2VuNs07s0RMECIG_aWSIG588XX8EspngSqexII8K33wx_wTbebInJCsC1cWF1dGhlbnRpY2F0b3JEYXRhWCVOsS8PJU7JWJfhD8KV_wtxOAB6WNUU_jplnvvKx-WFWkAAAAAB";
        let proof = Jwt::<()>::decompose_token(token).unwrap();
        let (msg, sig) = webauthn_signed_jwt_to_msg_and_sig(&proof).unwrap();

        let result = certificate.public_key.verify(&msg, &sig);
        assert!(result.is_ok());
    }

    fn test_cert_validator(clock: Arc<dyn Clock>) -> CertificateValidatorImpl {
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
        let android_key_attestation_crl_cache = Arc::new(AndroidAttestationCrlCache::new(
            Arc::new(AndroidAttestationCrlResolver::new(Arc::new(
                ReqwestClient::default(),
            ))),
            Arc::new(InMemoryStorage::new(HashMap::new())),
            1,
            Duration::days(1),
            Duration::days(1),
        ));
        CertificateValidatorImpl::new(
            key_algorithm_provider,
            crl_cache,
            clock,
            android_key_attestation_crl_cache,
        )
    }

    fn wallet_provider_config() -> Fields<config::core_config::WalletProviderType> {
        Fields {
            r#type: config::core_config::WalletProviderType::ProcivisOne,
            display: "display".into(),
            order: None,
            enabled: Some(true),
            capabilities: None,
            params: Some(Params {
                public: Some(json!({
                    "walletName": "Procivis One Dev Wallet",
                    "walletLink": "https://procivis.ch",
                    "ios": {
                        "bundleId": "com.procivis...",
                        "trustedAttestationCAs": ["-----BEGIN CERTIFICATE-----..."],
                        "enforceProductionBuild": true
                    },
                    "lifetime": {
                      "expirationTime": 60,
                      "minimumRefreshTime": 60
                    },
                    "issuerIdentifier": Uuid::new_v4(),
                    "integrityCheck": {
                        "enabled": true
                    }
                })),
                private: None,
            }),
        }
    }
}
