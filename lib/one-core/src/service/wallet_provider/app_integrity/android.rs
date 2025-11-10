use asn1_rs::Tag;
use itertools::Itertools;
use x509_parser::der_parser::error::BerError;
use x509_parser::der_parser::parse_der;

use crate::mapper::x509::x5c_into_pem_chain;
use crate::proto::certificate_validator::{
    CertSelection, CertificateValidationOptions, CertificateValidator, CrlMode, ParsedCertificate,
};
use crate::provider::key_algorithm::key::KeyHandle;
use crate::service::wallet_provider::dto::AndroidBundle;
use crate::service::wallet_provider::error::WalletProviderError;
use crate::service::wallet_provider::error::WalletProviderError::AppIntegrityValidationError;

// https://source.android.com/docs/security/features/keystore/attestation#attestation-extension
static ATTESTATION_EXTENSION_OID: &str = "1.3.6.1.4.1.11129.2.1.17";

pub(crate) async fn validate_attestation_android(
    attestation: &[String],
    server_nonce: &str,
    bundle: &AndroidBundle,
    certificate_validator: &dyn CertificateValidator,
) -> Result<KeyHandle, WalletProviderError> {
    let attestation_pem_chain =
        x5c_into_pem_chain(attestation).map_err(|e| AppIntegrityValidationError(e.to_string()))?;

    let cert = check_ca_certs(
        &attestation_pem_chain,
        &bundle.trusted_attestation_cas,
        certificate_validator,
    )
    .await?;

    let ext = cert
        .attributes
        .extensions
        .iter()
        .find(|ext| ext.oid == ATTESTATION_EXTENSION_OID)
        .ok_or(AppIntegrityValidationError(format!(
            "Failed to find mandatory cred cert extension {ATTESTATION_EXTENSION_OID}"
        )))?;
    let extension_data = hex::decode(&ext.value).map_err(|err| {
        AppIntegrityValidationError(format!("Failed to decode extension value: {err}"))
    })?;
    let ParsedAttestationExtension {
        attestation_challenge,
        package_name,
        signature_digests,
        keymaster_security_level,
    } = parse_attestation_extension(&extension_data).map_err(|err| {
        AppIntegrityValidationError(format!("Failed to decode extension value: {err}"))
    })?;

    if keymaster_security_level != SecurityLevel::StrongBox {
        return Err(WalletProviderError::InsufficientSecurityLevel);
    }

    validate_signing_certificate_fingerprints(bundle, signature_digests)?;

    if server_nonce != attestation_challenge {
        return Err(AppIntegrityValidationError("Nonce mismatch".to_string()));
    }

    if package_name != bundle.bundle_id {
        return Err(AppIntegrityValidationError(format!(
            "Bundle id mismatch: expected {} got {package_name}",
            bundle.bundle_id
        )));
    }
    Ok(cert.public_key)
}

struct ParsedAttestationExtension {
    pub attestation_challenge: String,
    pub package_name: String,
    pub signature_digests: Vec<String>,
    pub keymaster_security_level: SecurityLevel,
}

const TAG_ATTESTATION_APPLICATION_ID: Tag = Tag(709);

fn parse_attestation_extension(
    extension_data: &[u8],
) -> Result<ParsedAttestationExtension, BerError> {
    let (_, parsed_ext) = parse_der(extension_data)?;
    let key_description = parsed_ext.as_sequence()?;
    if key_description.len() != 8 {
        return Err(BerError::InvalidLength);
    }

    let keymaster_security_level = key_description
        .get(3)
        .ok_or(BerError::InvalidLength)?
        .as_u32()?
        .try_into()?;

    let attestation_challenge = key_description
        .get(4)
        .ok_or(BerError::InvalidLength)?
        .as_slice()?;
    let attestation_challenge = (*String::from_utf8_lossy(attestation_challenge)).to_owned();

    let software_enforced_authz_list = key_description
        .get(6)
        .ok_or(BerError::InvalidLength)?
        .as_sequence()?;

    // Nested DER encoded bytes
    let raw_app_id = software_enforced_authz_list
        .iter()
        .find(|elem| elem.tag() == TAG_ATTESTATION_APPLICATION_ID)
        .ok_or(BerError::BerValueError)?
        .content
        .as_slice()?;

    // Do a little DER-juggling to get through the custom tags.
    let (_, app_id_octet_string) = parse_der(raw_app_id)?;
    let (_, parsed_app_id) = parse_der(app_id_octet_string.as_slice()?)?;
    // sequence of package_infos and signature_digests
    let appid_seq = parsed_app_id.as_sequence()?;
    if appid_seq.len() != 2 {
        return Err(BerError::InvalidLength);
    }
    // set of (package name, version) sequences
    let package_infos = appid_seq.first().ok_or(BerError::InvalidLength)?.as_set()?;

    // List of packages should have length 1
    if package_infos.len() != 1 {
        return Err(BerError::InvalidLength);
    }

    // sequence of package name and version
    let package_info = package_infos
        .first()
        .ok_or(BerError::InvalidLength)?
        .as_sequence()?;
    if package_info.len() != 2 {
        return Err(BerError::InvalidLength);
    }
    // finally pull out name
    let package_name = (*String::from_utf8_lossy(
        package_info
            .first()
            .ok_or(BerError::InvalidLength)?
            .as_slice()?,
    ))
    .to_owned();

    // pull out signature digests
    let signature_digests = appid_seq
        .get(1)
        .ok_or(BerError::InvalidLength)?
        .as_set()?
        .iter()
        .map(|o| {
            o.as_slice()
                .map(|s| s.iter().map(|x| format!("{x:02X}")).collect::<String>())
        })
        .collect::<Result<Vec<String>, _>>()?;

    Ok(ParsedAttestationExtension {
        attestation_challenge,
        package_name,
        signature_digests,
        keymaster_security_level,
    })
}

fn validate_signing_certificate_fingerprints(
    bundle: &AndroidBundle,
    signatures: Vec<String>,
) -> Result<(), WalletProviderError> {
    signatures
        .iter()
        .all(|signature| bundle.signing_certificate_fingerprints.contains(signature))
        .then_some(())
        .ok_or(AppIntegrityValidationError(format!(
            "Invalid signing certificate fingerprints: {signatures:?}"
        )))
}

async fn check_ca_certs(
    attestation: &str,
    cas: &[String],
    certificate_validator: &dyn CertificateValidator,
) -> Result<ParsedCertificate, WalletProviderError> {
    let mut errs = vec![];
    for ca in cas {
        let result = certificate_validator
            .validate_chain_against_ca_chain(
                attestation,
                ca,
                CertificateValidationOptions {
                    leaf_only_extensions: vec![ATTESTATION_EXTENSION_OID.to_string()],
                    validity_check: Some(CrlMode::AndroidAttestation),
                    integrity_check: true,
                    require_root_termination: true,
                    required_leaf_cert_key_usage: Default::default(),
                },
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

#[derive(Debug, Eq, PartialEq)]
enum SecurityLevel {
    Software = 0,
    TrustedEnvironment = 1,
    StrongBox = 2,
}

impl TryFrom<u32> for SecurityLevel {
    type Error = BerError;
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        Ok(match value {
            0 => SecurityLevel::Software,
            1 => SecurityLevel::TrustedEnvironment,
            2 => SecurityLevel::StrongBox,
            _ => return Err(BerError::BerValueError),
        })
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;
    use std::sync::Arc;

    use maplit::hashmap;
    use time::Duration;
    use time::macros::datetime;

    use super::*;
    use crate::config::core_config::KeyAlgorithmType;
    use crate::proto::certificate_validator::CertificateValidatorImpl;
    use crate::proto::clock::MockClock;
    use crate::proto::http_client::reqwest_client::ReqwestClient;
    use crate::provider::caching_loader::android_attestation_crl::{
        AndroidAttestationCrlCache, AndroidCertificateInfo, AndroidKeyAttestationsCrl,
        CertificateStatus, MockAndroidAttestationCrlResolver,
    };
    use crate::provider::caching_loader::x509_crl::{X509CrlCache, X509CrlResolver};
    use crate::provider::key_algorithm::KeyAlgorithm;
    use crate::provider::key_algorithm::ecdsa::Ecdsa;
    use crate::provider::key_algorithm::provider::KeyAlgorithmProviderImpl;
    use crate::provider::remote_entity_storage::in_memory::InMemoryStorage;

    // Test vector generated on Galaxy S25
    static GOOGLE_CA: &str = "-----BEGIN CERTIFICATE-----
MIIFHDCCAwSgAwIBAgIJAPHBcqaZ6vUdMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNV
BAUTEGY5MjAwOWU4NTNiNmIwNDUwHhcNMjIwMzIwMTgwNzQ4WhcNNDIwMzE1MTgw
NzQ4WjAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MIICIjANBgkqhkiG9w0B
AQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xUFmOr75gvMsd/dTEDDJdS
Sxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5jlRfdnJLmN0pTy/4lj4/7
tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y//0rb+T+W8a9nsNL/ggj
nar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73XpXyTqRxB/M0n1n/W9nGq
C4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYImQQcHtGl/m00QLVWutHQ
oVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB+TxywElgS70vE0XmLD+O
JtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7quvmag8jfPioyKvxnK/Eg
sTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgpZrt3i5MIlCaY504LzSRi
igHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7gLiMm0jhO2B6tUXHI/+M
RPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82ixPvZtXQpUpuL12ab+9E
aDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/bkwSWc+NpUFgNPN9PvQi8WEg5Um
AGMCAwEAAaNjMGEwHQYDVR0OBBYEFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMB8GA1Ud
IwQYMBaAFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMA8GA1UdEwEB/wQFMAMBAf8wDgYD
VR0PAQH/BAQDAgIEMA0GCSqGSIb3DQEBCwUAA4ICAQB8cMqTllHc8U+qCrOlg3H7
174lmaCsbo/bJ0C17JEgMLb4kvrqsXZs01U3mB/qABg/1t5Pd5AORHARs1hhqGIC
W/nKMav574f9rZN4PC2ZlufGXb7sIdJpGiO9ctRhiLuYuly10JccUZGEHpHSYM2G
tkgYbZba6lsCPYAAP83cyDV+1aOkTf1RCp/lM0PKvmxYN10RYsK631jrleGdcdkx
oSK//mSQbgcWnmAEZrzHoF1/0gso1HZgIn0YLzVhLSA/iXCX4QT2h3J5z3znluKG
1nv8NQdxei2DIIhASWfu804CA96cQKTTlaae2fweqXjdN1/v2nqOhngNyz1361mF
mr4XmaKH/ItTwOe72NI9ZcwS1lVaCvsIkTDCEXdm9rCNPAY10iTunIHFXRh+7KPz
lHGewCq/8TOohBRn0/NNfh7uRslOSZ/xKbN9tMBtw37Z8d2vvnXq/YWdsm1+JLVw
n6yYD/yacNJBlwpddla8eaVMjsF6nBnIgQOf9zKSe06nSTqvgwUHosgOECZJZ1Eu
zbH4yswbt02tKtKEFhx+v+OTge/06V+jGsqTWLsfrOCNLuA8H++z+pUENmpqnnHo
vaI47gC+TNpkgYGkkBT6B/m/U01BuOBBTzhIlMEZq9qkDWuM2cA5kW5V3FJUcfHn
w1IdYIg2Wxg7yHcQZemFQg==
-----END CERTIFICATE-----";
    static ATTESTATION_CHAIN: [&str; 4] = [
        "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",
    ];

    static SIGNING_CERTIFICATE_FINGERPRINTS: [&str; 1] =
        ["FAC61745DC0903786FB9EDE62A962B399F7348F0BB6F899B8332667591033B9C"];

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
        let android_key_attestation_crl_cache = Arc::new(AndroidAttestationCrlCache::new(
            Arc::new(MockAndroidAttestationCrlResolver::default()),
            Arc::new(InMemoryStorage::new(HashMap::new())),
            1,
            Duration::days(1),
            Duration::days(1),
        ));
        let mut clock = MockClock::new();
        clock
            .expect_now_utc()
            .returning(|| datetime!(2024-10-01 0:00 UTC)); // a date the test vector happens to be valid at
        let certificate_validator = CertificateValidatorImpl::new(
            key_algorithm_provider,
            crl_cache,
            Arc::new(clock),
            Duration::minutes(1),
            android_key_attestation_crl_cache,
        );
        validate_attestation_android(
            &ATTESTATION_CHAIN
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            "INdGT5ahPwBSIASvphcj5UiS4f3N8W4BBqLOiBPCksXW",
            &AndroidBundle {
                bundle_id: "com.exampleapp".to_string(),
                signing_certificate_fingerprints: SIGNING_CERTIFICATE_FINGERPRINTS
                    .iter()
                    .map(ToString::to_string)
                    .collect(),
                trusted_attestation_cas: vec![GOOGLE_CA.to_string()],
            },
            &certificate_validator,
        )
        .await
        .expect("Failed to validate attestation");
    }

    #[tokio::test]
    async fn validate_attestation_insufficient_security() {
        // Attestation produced by Eugenius test phone
        const EXAMPLE_APP_ATTESTATION: [&str; 4] = [
            "MIICQTCCAeegAwIBAgIBATAKBggqhkjOPQQDAjApMRkwFwYDVQQFExA0OTFjMmY1ZmI0MjExZTcwMQwwCgYDVQQMDANURUUwHhcNMjUwOTAzMTY1OTE5WhcNMjgxMTMwMjIyNzM5WjAfMR0wGwYDVQQDDBRBbmRyb2lkIEtleXN0b3JlIEtleTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJDEwRnWjQRVwKyUHybxlMxT3MmqJFobMIpYUdCwHTPQtoX/KqSQMN6zpC5TTrYCpak7qyubnFchRmTX4zNjdSSjggEIMIIBBDCB9AYKKwYBBAHWeQIBEQSB5TCB4gIBAgoBAQIBAwoBAQQUQXR0ZXN0YXRpb25DaGFsbGVuZ2UEADBDv4VFPwQ9MDsxFTATBA5jb20uZXhhbXBsZWFwcAIBATEiBCD6xhdF3AkDeG+57eYqlis5n3NI8LtviZuDMmZ1kQM7nDB3oQUxAwIBAqIDAgEDowQCAgEApQUxAwIBBKoDAgEBv4N3AgUAv4U9CAIGAZkQhL8sv4U+AwIBAL+FQCowKAQgU0HmsmRpeacOV2UwB6HzEBaUIeyb3Z8aVkj3Wt4AWvEBAf8KAQC/hUEFAgMBhqC/hUIFAgMDFRgwCwYDVR0PBAQDAgeAMAoGCCqGSM49BAMCA0gAMEUCIQCjW00P/Az3e0YZiG3maKdIBzV/fnPZiEyxN2Zv5cLjiQIgCkk9mLSKpTpvuqePZEiIr9I5LgWOhMPYzIg0qFvlFys=",
            "MIICJTCCAaugAwIBAgIKAzEQRmWTgUIEcjAKBggqhkjOPQQDAjApMRkwFwYDVQQFExA0NDNkMjI4NGU5NmFiMjNiMQwwCgYDVQQMDANURUUwHhcNMTgxMjAzMjIyNzM5WhcNMjgxMTMwMjIyNzM5WjApMRkwFwYDVQQFExA0OTFjMmY1ZmI0MjExZTcwMQwwCgYDVQQMDANURUUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQCVCxxOreCs8xbHaH3+dad/fPAbcYlKtgnsAZI0YSb61Wepiq2dd6pfljTOiq0UKHzf2bIB70dPWHfaRLLnWCFo4G6MIG3MB0GA1UdDgQWBBTvtcqR6rDO5iFI0YvQ3791w8CkpDAfBgNVHSMEGDAWgBTz+kTekgvidiuHITJW3HWiylgVkzAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwICBDBUBgNVHR8ETTBLMEmgR6BFhkNodHRwczovL2FuZHJvaWQuZ29vZ2xlYXBpcy5jb20vYXR0ZXN0YXRpb24vY3JsLzAzMzExMDQ2NjU5MzgxNDIwNDcyMAoGCCqGSM49BAMCA2gAMGUCMQDGy9/K1VcovuvYNLVrVFXDYj4OLQXfnGFJYKjKFVUwB2OpsMXdtJ9jYsXD9hqHQWMCMBzSs0f+WLp3WafBh01WLgKvWsrJBRDU+WGmA4BNiCsr/2dEmDYEGKne2PycD5hgYA==",
            "MIID0TCCAbmgAwIBAgIKA4gmZ2BliZaFzjANBgkqhkiG9w0BAQsFADAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MB4XDTE4MTIwMzIyMjQxNFoXDTI4MTEzMDIyMjQxNFowKTEZMBcGA1UEBRMQNDQzZDIyODRlOTZhYjIzYjEMMAoGA1UEDAwDVEVFMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE2tYXAmHqxDPYOcCe0QQ4/aMQ1kpkOFpiBsNnnfs0nsOR5ywGNHAbRNqWSKr8FYh/GuspoW2rT5JE3WLjAF9kHEQrOJ8HTThxJS9fl2VAfQS/2gJ64oHBabj6XB5qiqfAo4G2MIGzMB0GA1UdDgQWBBTz+kTekgvidiuHITJW3HWiylgVkzAfBgNVHSMEGDAWgBQ2YeEAfIgFCVGLRGxH/xpMyepPEjAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwICBDBQBgNVHR8ESTBHMEWgQ6BBhj9odHRwczovL2FuZHJvaWQuZ29vZ2xlYXBpcy5jb20vYXR0ZXN0YXRpb24vY3JsL0U4RkExOTYzMTREMkZBMTgwDQYJKoZIhvcNAQELBQADggIBAB9OWP309acpcELw3KHF5LrHsNLYfJsaAzem4gQplevmQlTfVQnok3h5zfmB99TgtlcOfTEO3SLZO4MwjK0oBVBL3AVxGN99+1WLjDEHm35hVqzFEZ93N41boFso+448hpl43BFJwRkAUg5NJ3vgrvGgPW7UhWSYE92ao+p5qmwzZlcIloX+tEVTR6yzowYlpYMacx5IKovoUX9DmATbufSt9iH65gtiJ4CmGM/U6qyMc7rPeA+eaW65NwRkRMOM3fKBSIdR1cde5nG62kkOchbJdGwyXM+Ux/zuCiXyyV0R7HMpmM3siOjDbP6lnGIt70iGVMaQ2JECy7GjAOaHOWZf1kUvZWDg6d15DsuHEDtk/oJIt6dtJ57kGJdhO0DtB3P5zW9VhjsUHrbdYCdzP0Fy5CNJFGo8c83f8yzQknLeGbAFFxHEhEff0F3rbneC26mU9UVaAcKo+o8HH1qnI0Twp9fieMUAwaiWfkjpkvzhl5nuFu4740eV1zC9zX9cGH9MMupoDrRvI42Djhd/7W6KJ1MQWu/7m/Xst7DeBTJSri++ZPcYtxuLpHiZEuvIzYBLGbLAjQ0OkDo/KDVtRrradd1P4746PW9Zfk6I3ALRjLrUT+q4UICLh+o+dtXTN0pNzlSqKWpV6yaFscwRQ4fdZ0grBzo0pbudDU26JmTm",
            "MIIFYDCCA0igAwIBAgIJAOj6GWMU0voYMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNVBAUTEGY5MjAwOWU4NTNiNmIwNDUwHhcNMTYwNTI2MTYyODUyWhcNMjYwNTI0MTYyODUyWjAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xUFmOr75gvMsd/dTEDDJdSSxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5jlRfdnJLmN0pTy/4lj4/7tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y//0rb+T+W8a9nsNL/ggjnar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73XpXyTqRxB/M0n1n/W9nGqC4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYImQQcHtGl/m00QLVWutHQoVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB+TxywElgS70vE0XmLD+OJtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7quvmag8jfPioyKvxnK/EgsTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgpZrt3i5MIlCaY504LzSRiigHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7gLiMm0jhO2B6tUXHI/+MRPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82ixPvZtXQpUpuL12ab+9EaDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/bkwSWc+NpUFgNPN9PvQi8WEg5UmAGMCAwEAAaOBpjCBozAdBgNVHQ4EFgQUNmHhAHyIBQlRi0RsR/8aTMnqTxIwHwYDVR0jBBgwFoAUNmHhAHyIBQlRi0RsR/8aTMnqTxIwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAYYwQAYDVR0fBDkwNzA1oDOgMYYvaHR0cHM6Ly9hbmRyb2lkLmdvb2dsZWFwaXMuY29tL2F0dGVzdGF0aW9uL2NybC8wDQYJKoZIhvcNAQELBQADggIBACDIw41L3KlXG0aMiS//cqrG+EShHUGo8HNsw30W1kJtjn6UBwRM6jnmiwfBPb8VA91chb2vssAtX2zbTvqBJ9+LBPGCdw/E53Rbf86qhxKaiAHOjpvAy5Y3m00mqC0w/Zwvju1twb4vhLaJ5NkUJYsUS7rmJKHHBnETLi8GFqiEsqTWpG/6ibYCv7rYDBJDcR9W62BW9jfIoBQcxUCUJouMPH25lLNcDc1ssqvC2v7iUgI9LeoM1sNovqPmQUiG9rHli1vXxzCyaMTjwftkJLkf6724DFhuKug2jITV0QkXvaJWF4nUaHOTNA4uJU9WDvZLI1j83A+/xnAJUucIv/zGJ1AMH2boHqF8CY16LpsYgBt6tKxxWH00XcyDCdW2KlBCeqbQPcsFmWyWugxdcekhYsAWyoSf818NUsZdBWBaR/OukXrNLfkQ79IyZohZbvabO/X+MVT3rriAoKc8oE2Uws6DF+60PV7/WIPjNvXySdqspImSN78mflxDqwLqRBYkA3I75qppLGG9rp7UCdRjxMl8ZDBld+7yvHVgt1cVzJx9xnyGCC23UaicMDSXYrB4I4WHXPGjxhZuCuPBLTdOLU8YRvMYdEvYebWHMpvwGCF6bAx3JBpIeOQ1wDB5y0USicV3YgYGmi+NZfhA4URSh77Yd6uuJOJENRaNVTzk",
        ];

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
            Arc::new(MockAndroidAttestationCrlResolver::default()),
            Arc::new(InMemoryStorage::new(HashMap::new())),
            1,
            Duration::days(1),
            Duration::days(1),
        ));
        let mut clock = MockClock::new();
        clock
            .expect_now_utc()
            .returning(|| datetime!(2025-09-05 0:00 UTC)); // a date the test vector happens to be valid at
        let certificate_validator = CertificateValidatorImpl::new(
            key_algorithm_provider,
            crl_cache,
            Arc::new(clock),
            Duration::minutes(1),
            android_key_attestation_crl_cache,
        );
        let result = validate_attestation_android(
            &EXAMPLE_APP_ATTESTATION
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            "AttestationChallenge",
            &AndroidBundle {
                bundle_id: "com.exampleapp".to_string(),
                signing_certificate_fingerprints: SIGNING_CERTIFICATE_FINGERPRINTS
                    .iter()
                    .map(ToString::to_string)
                    .collect(),
                trusted_attestation_cas: vec![GOOGLE_CA.to_string()],
            },
            &certificate_validator,
        )
        .await;

        assert!(matches!(
            result,
            Err(WalletProviderError::InsufficientSecurityLevel)
        ))
    }

    #[tokio::test]
    async fn validate_attestation_failure_mid_chain_cert_revoked() {
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
            Arc::new(MockAndroidAttestationCrlResolver {
                crl: AndroidKeyAttestationsCrl {
                    entries: hashmap! {
                         "dea90f73eec5583bdc82603511ed604a".into() => AndroidCertificateInfo {
                            status: CertificateStatus::Revoked,
                            reason: None,
                            expires: None,
                            description: None
                        },
                    },
                },
            }),
            Arc::new(InMemoryStorage::new(HashMap::new())),
            1,
            Duration::days(1),
            Duration::days(1),
        ));
        let mut clock = MockClock::new();
        clock
            .expect_now_utc()
            .returning(|| datetime!(2024-10-01 0:00 UTC)); // a date the test vector happens to be valid at
        let certificate_validator = CertificateValidatorImpl::new(
            key_algorithm_provider,
            crl_cache,
            Arc::new(clock),
            Duration::minutes(1),
            android_key_attestation_crl_cache,
        );
        let result = validate_attestation_android(
            &ATTESTATION_CHAIN
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            "INdGT5ahPwBSIASvphcj5UiS4f3N8W4BBqLOiBPCksXW",
            &AndroidBundle {
                bundle_id: "com.exampleapp".to_string(),
                signing_certificate_fingerprints: SIGNING_CERTIFICATE_FINGERPRINTS
                    .iter()
                    .map(ToString::to_string)
                    .collect(),
                trusted_attestation_cas: vec![GOOGLE_CA.to_string()],
            },
            &certificate_validator,
        )
        .await;

        assert!(matches!(
            result,
            Err(WalletProviderError::AppIntegrityValidationError(_))
        ));
    }
}
