#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::sync::Arc;

use asn1_rs::{Integer, SequenceOf, ToDer};
use ct_codecs::Encoder;
use one_crypto::Signer;
use one_crypto::signer::ecdsa::ECDSASigner;
use serde::{Deserialize, Serialize};
use similar_asserts::assert_eq;
use standardized_types::etsi_119_602::xml::LoTEPayload;
use standardized_types::etsi_119_612::xml::TrustServiceStatusList;
use time::OffsetDateTime;

use super::*;
use crate::config::core_config::KeyAlgorithmType;
use crate::proto::certificate_validator::{MockCertificateValidator, ParsedCertificate};
use crate::provider::credential_formatter::model::MockSignatureProvider;
use crate::provider::key_algorithm::KeyAlgorithm;
use crate::provider::key_algorithm::ecdsa::Ecdsa;
use crate::provider::key_algorithm::key::{
    KeyHandle, MockSignaturePublicKeyHandle, SignatureKeyHandle,
};
use crate::service::certificate::dto::CertificateX509AttributesDTO;

// P-256 key pair (same as apps/core-server/tests/fixtures/certificate.rs)
const PRIV_KEY: &[u8] = &[
    56, 151, 105, 61, 235, 90, 246, 249, 183, 236, 90, 157, 106, 176, 145, 114, 36, 199, 115, 51,
    234, 102, 21, 254, 34, 219, 38, 210, 7, 172, 169, 157,
];
const PUB_KEY_COMPRESSED: &[u8] = &[
    2, 113, 223, 203, 78, 208, 144, 157, 171, 118, 94, 112, 196, 150, 233, 175, 129, 0, 12, 229,
    151, 39, 80, 197, 83, 144, 248, 160, 227, 159, 2, 215, 39,
];

#[derive(Clone, Copy)]
struct TestKey;

impl rcgen::PublicKeyData for TestKey {
    fn der_bytes(&self) -> &[u8] {
        // uncompressed SEC1 point
        static PUB_KEY_UNCOMPRESSED: std::sync::LazyLock<Vec<u8>> =
            std::sync::LazyLock::new(|| {
                ECDSASigner::parse_public_key(PUB_KEY_COMPRESSED, false).unwrap()
            });
        &PUB_KEY_UNCOMPRESSED
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_ECDSA_P256_SHA256
    }
}

impl rcgen::SigningKey for TestKey {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        let mut signature = ECDSASigner
            .sign(msg, PUB_KEY_COMPRESSED, &PRIV_KEY.to_vec().into())
            .map_err(|_| rcgen::Error::RemoteKeyError)?;

        // ASN.1 DER encoding for rcgen
        let s: [u8; 32] = signature.split_off(32).try_into().unwrap();
        let r: [u8; 32] = signature.try_into().unwrap();
        let seq =
            SequenceOf::from_iter([Integer::from_const_array(r), Integer::from_const_array(s)]);
        Ok(seq.to_der_vec().unwrap())
    }
}

struct TestFixtures {
    signer: MockSignatureProvider,
    cert_validator: MockCertificateValidator,
    x5c: Vec<String>,
}

fn make_xades_test_fixtures() -> TestFixtures {
    let mut params = rcgen::CertificateParams::new(vec![]).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "XAdES Test CA");
    let cert = params.self_signed(&TestKey).unwrap();
    let cert_der = cert.der().to_vec();
    let cert_b64 = ct_codecs::Base64::encode_to_string(&cert_der).unwrap();

    // raw r||s format as expected by SignatureProvider
    let mut mock_signer = MockSignatureProvider::new();
    mock_signer.expect_sign().returning(|msg| {
        let secret: secrecy::SecretSlice<u8> = PRIV_KEY.to_vec().into();
        Ok(ECDSASigner.sign(msg, PUB_KEY_COMPRESSED, &secret).unwrap())
    });
    mock_signer
        .expect_jose_alg()
        .returning(|| Ok("ES256".to_string()));
    mock_signer.expect_get_key_id().returning(|| None);
    mock_signer
        .expect_get_key_algorithm()
        .returning(|| Ok(KeyAlgorithmType::Ecdsa));
    mock_signer.expect_get_public_key().returning(Vec::new);

    let ecdsa = Ecdsa;
    let (_, parsed_cert) = x509_parser::parse_x509_certificate(&cert_der).unwrap();
    let key_handle = ecdsa
        .parse_der(parsed_cert.tbs_certificate.subject_pki.raw)
        .unwrap();

    let mut cert_validator = MockCertificateValidator::new();
    cert_validator
        .expect_parse_pem_chain()
        .returning(move |_, _| {
            let now = OffsetDateTime::now_utc();
            Ok(ParsedCertificate {
                attributes: CertificateX509AttributesDTO {
                    serial_number: "test".to_string(),
                    not_before: now,
                    not_after: now,
                    issuer: "XAdES Test CA".to_string(),
                    subject: "XAdES Test CA".to_string(),
                    fingerprint: "test".to_string(),
                    extensions: vec![],
                },
                subject_common_name: Some("XAdES Test CA".to_string()),
                subject_key_identifier: None,
                public_key: key_handle.clone(),
            })
        });

    TestFixtures {
        signer: mock_signer,
        cert_validator,
        x5c: vec![cert_b64],
    }
}

#[tokio::test]
async fn sign_and_verify_roundtrip() {
    let TestFixtures {
        signer,
        cert_validator,
        x5c,
    } = make_xades_test_fixtures();
    let unsigned_xml = "<Root xmlns=\"http://test\"><Data>hello</Data></Root>";

    let xades = XAdES {
        certificate_validator: Arc::new(cert_validator),
    };

    let signed_xml = xades
        .create_enveloped_signature(unsigned_xml, &signer, x5c)
        .await
        .expect("signing should succeed");

    let decomposed: XAdESSignedXML<serde_json::Value> =
        XAdESSignedXML::decompose_document(&signed_xml).expect("decompose should succeed");

    assert!(decomposed.envelope().signature.id.is_some());
    assert!(
        decomposed
            .envelope()
            .signature
            .signed_info
            .signature_method
            .algorithm
            .contains("ecdsa-sha256")
    );

    xades
        .verify_enveloped_signature(decomposed.envelope())
        .await
        .expect("verification should succeed");
}

#[tokio::test]
async fn tampered_document_fails() {
    let TestFixtures {
        signer,
        cert_validator,
        x5c,
    } = make_xades_test_fixtures();
    let unsigned_xml = "<Root xmlns=\"http://test\"><Data>hello</Data></Root>";

    let xades = XAdES {
        certificate_validator: Arc::new(cert_validator),
    };
    let signed_xml = xades
        .create_enveloped_signature(unsigned_xml, &signer, x5c)
        .await
        .unwrap();

    let tampered = signed_xml.replace("<Data>hello</Data>", "<Data>world</Data>");

    let decomposed = XAdESSignedXML::<serde_json::Value>::decompose_document(&tampered)
        .expect("decompose should succeed");

    let err = xades
        .verify_enveloped_signature(decomposed.envelope())
        .await
        .expect_err("verification should fail on tampered document");

    assert!(matches!(err, Error::IncorrectDigest(_)), "{err}");
}

#[tokio::test]
async fn signed_xml_contains_expected_elements() {
    let TestFixtures { signer, x5c, .. } = make_xades_test_fixtures();
    let cert_b64 = x5c[0].clone();
    let unsigned_xml = "<Root xmlns=\"http://test\"><Data>test</Data></Root>";

    let xades = XAdES {
        certificate_validator: Arc::new(MockCertificateValidator::new()),
    };
    let signed_xml = xades
        .create_enveloped_signature(unsigned_xml, &signer, x5c)
        .await
        .unwrap();

    assert!(signed_xml.contains("<ds:Signature"));
    assert!(signed_xml.contains("<xades:SignedProperties"));
    assert!(signed_xml.contains("<xades:SigningTime>"));
    assert!(signed_xml.contains("<ds:X509Certificate>"));
    assert!(signed_xml.contains(&cert_b64));
    assert!(signed_xml.contains("<Data>test</Data>"));
}

#[tokio::test]
async fn decompose_ignores_non_xmldsig_signature_elements() {
    // GIVEN a payload that includes a Signature field
    let TestFixtures {
        signer,
        cert_validator,
        x5c,
        ..
    } = make_xades_test_fixtures();

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct PayloadWithSignature {
        #[serde(rename = "@xmlns:test")]
        namespace: String,
        description: String,
        #[serde(rename = "test:Signature", alias = "Signature")]
        signature: String,
    }

    let payload = PayloadWithSignature {
        namespace: "http://example.test".to_string(),
        description: "Test Payload".to_string(),
        signature: "Not a digital signature".to_string(),
    };

    // WHEN we serialize, sign, parse and verify the signature
    let unsigned_xml = quick_xml::se::to_string(&payload).expect("should serialize struct as xml");

    let xades = XAdES {
        certificate_validator: Arc::new(cert_validator),
    };

    let signed_xml = xades
        .create_enveloped_signature(&unsigned_xml, &signer, x5c)
        .await
        .expect("signing should succeed despite non-xmldsig Signature element");

    let decomposed: XAdESSignedXML<PayloadWithSignature> =
        XAdESSignedXML::decompose_document(&signed_xml).expect("decompose should succeed");

    assert!(signed_xml.contains("<ds:Signature"));
    assert!(signed_xml.contains("<test:Signature>"));

    // Signature verification works as expected
    xades
        .verify_enveloped_signature(decomposed.envelope())
        .await
        .expect("verification should succeed");

    // No data was lost in the process
    assert_eq!(decomposed.content, payload);
}

#[tokio::test]
async fn verify_returns_signer_chain() {
    let TestFixtures {
        signer,
        cert_validator,
        x5c,
    } = make_xades_test_fixtures();
    let unsigned_xml = "<Root xmlns=\"http://test\"><Data>hello</Data></Root>";

    let xades = XAdES {
        certificate_validator: Arc::new(cert_validator),
    };

    let signed_xml = xades
        .create_enveloped_signature(unsigned_xml, &signer, x5c)
        .await
        .expect("signing should succeed");

    let decomposed: XAdESSignedXML<serde_json::Value> =
        XAdESSignedXML::decompose_document(&signed_xml).expect("decompose should succeed");

    let verified = xades
        .verify_enveloped_signature(decomposed.envelope())
        .await
        .expect("verification should succeed");

    assert!(
        verified
            .signer_chain_pem
            .starts_with("-----BEGIN CERTIFICATE-----"),
        "expected PEM chain, got: {}",
        verified.signer_chain_pem
    );
}

// DSS LoTE test vector (RSA-SHA256 signed).
// https://github.com/esig/dss/blob/master/specs-lote-xml/src/test/resources/valid-signed.xml
// Verifies decompose + canonicalization and digest matching works for a third-party LoTE document.
// RSA signature verification is mocked (unsupported algorithm).
#[tokio::test]
async fn dss_lote_verify_digests() {
    let xml = include_str!("./fixtures/dss-lote-signed.xml");

    let mut cert_validator = MockCertificateValidator::new();

    let decomposed: XAdESSignedXML<LoTEPayload> =
        XAdESSignedXML::decompose_document(xml).expect("decompose should succeed");

    cert_validator
        .expect_parse_pem_chain()
        .returning(move |_, _| {
            let mut mock_public_key_handle = MockSignaturePublicKeyHandle::default();
            mock_public_key_handle
                .expect_verify()
                .returning(|_, _| Ok(()));

            let now = OffsetDateTime::now_utc();
            Ok(ParsedCertificate {
                attributes: CertificateX509AttributesDTO {
                    serial_number: "test".to_string(),
                    not_before: now,
                    not_after: now,
                    issuer: "test".to_string(),
                    subject: "test".to_string(),
                    fingerprint: "test".to_string(),
                    extensions: vec![],
                },
                subject_common_name: None,
                subject_key_identifier: None,
                public_key: KeyHandle::SignatureOnly(SignatureKeyHandle::PublicKeyOnly(Arc::new(
                    mock_public_key_handle,
                ))),
            })
        });

    decomposed
        .envelope()
        .verify_signature(&cert_validator)
        .await
        .expect("digest verification should succeed");
}

#[tokio::test]
async fn dss_lote_tampered_document_fails() {
    let xml =
        include_str!("./fixtures/dss-lote-signed.xml").replace("Trust Provider Inc.", "Evil Corp");

    let decomposed: XAdESSignedXML<LoTEPayload> =
        XAdESSignedXML::decompose_document(&xml).expect("decompose should succeed");

    let cert_validator = MockCertificateValidator::new();

    let err = decomposed
        .envelope()
        .verify_signature(&cert_validator)
        .await
        .expect_err("tampered document should fail verification");

    assert!(matches!(err, Error::IncorrectDigest(_)), "{err}");
}

// Real EU member trusted list, signed by EU DSS with inclusive C14N. Verifying
// its three `ds:Reference` digests checks our inclusive canonicalizer against
// real output. Only the ECDSA signature is mocked (cert revocation needs
// network).
#[tokio::test]
async fn real_eudi_inclusive_tsl_verifies_reference_digests() {
    let xml = include_str!("./fixtures/eudiw_member_tsl.xml");

    let mut cert_validator = MockCertificateValidator::new();
    cert_validator.expect_parse_pem_chain().returning(|_, _| {
        let mut public_key = MockSignaturePublicKeyHandle::default();
        public_key.expect_verify().returning(|_, _| Ok(()));
        let now = OffsetDateTime::now_utc();
        Ok(ParsedCertificate {
            attributes: CertificateX509AttributesDTO {
                serial_number: "test".to_string(),
                not_before: now,
                not_after: now,
                issuer: "test".to_string(),
                subject: "test".to_string(),
                fingerprint: "test".to_string(),
                extensions: vec![],
            },
            subject_common_name: None,
            subject_key_identifier: None,
            public_key: KeyHandle::SignatureOnly(SignatureKeyHandle::PublicKeyOnly(Arc::new(
                public_key,
            ))),
        })
    });

    let decomposed: XAdESSignedXML<TrustServiceStatusList> =
        XAdESSignedXML::decompose_document(xml).expect("decompose real EUDI member TSL");

    decomposed
        .envelope()
        .verify_signature(&cert_validator)
        .await
        .expect("inclusive-C14N reference digests must verify against real EU DSS data");
}
