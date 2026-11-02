use std::assert_matches;
use std::collections::HashMap;
use std::sync::Arc;

use similar_asserts::assert_eq;
use standardized_types::etsi_119_612::xml::{
    AdditionalInformation, DigitalId, OtherInformation, OtherTslPointer, ServiceDigitalIdentities,
    ServiceDigitalIdentity,
};
use standardized_types::etsi_119_612::{MIME_TSL_XML, ServiceType, TslType};
use time::Duration;
use time::macros::datetime;
use url::Url;

use super::model::{PreprocessedLotl, TslServiceEntry};
use super::resolver::{PointerKind, classify_pointer};
use super::{EtsiLotlSubscriber, find_matching_for_identifier};
use crate::mapper::etsi_lotl::role_for_service_type;
use crate::proto::certificate_validator::{
    Error as CertValidatorError, MockCertificateValidator, ParsedCertificate,
};
use crate::provider::caching_loader::etsi_lotl::EtsiLotlCache;
use crate::provider::caching_loader::{ResolveResult, Resolver, ResolverError};
use crate::provider::key_algorithm::key::{
    KeyHandle, MockSignaturePublicKeyHandle, SignatureKeyHandle,
};
use crate::provider::remote_entity_storage::in_memory::InMemoryStorage;
use crate::provider::trust_list_subscriber::{
    Feature, TrustEntityMetadata, TrustEntityResponse, TrustListSubscriber,
};
use crate::service::certificate::dto::CertificateX509AttributesDTO;

// German Registrar self-signed cert; its AKI equals its SKI
const TRUSTED_CERT: &str = r#"-----BEGIN CERTIFICATE-----
MIICLzCCAdSgAwIBAgIUHyRjE466YA7tc888k03Ou2QodF4wCgYIKoZIzj0EAwIw
KDELMAkGA1UEBhMCREUxGTAXBgNVBAMMEEdlcm1hbiBSZWdpc3RyYXIwHhcNMjYw
MTE2MTExNTU0WhcNMjgwMTE2MTExNTU0WjAoMQswCQYDVQQGEwJERTEZMBcGA1UE
AwwQR2VybWFuIFJlZ2lzdHJhcjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABMef
Y2X4ixfRkWEvp9grF2i21z6PKZsr8zzBaJ/+GnotCeH2cJ6GtLhxXhHfJjrETsMN
IGhVaJoHoHcZTBHJrfyjgdswgdgwHQYDVR0OBBYEFKnCo9ovbaxU7s65TugsySwA
g4AzMB8GA1UdIwQYMBaAFKnCo9ovbaxU7s65TugsySwAg4AzMBIGA1UdEwEB/wQI
MAYBAf8CAQAwDgYDVR0PAQH/BAQDAgEGMCoGA1UdEgQjMCGGH2h0dHBzOi8vc2Fu
ZGJveC5ldWRpLXdhbGxldC5vcmcwRgYDVR0fBD8wPTA7oDmgN4Y1aHR0cHM6Ly9z
YW5kYm94LmV1ZGktd2FsbGV0Lm9yZy9zdGF0dXMtbWFuYWdlbWVudC9jcmwwCgYI
KoZIzj0EAwIDSQAwRgIhAIY7ERpRrDRl0lr5H5uxjJ83JR4qua2sfPKxX+pl4Qw+
AiEA2qL6LXVORA2r2VZjSEknfciwIG7laA12kjnyGAD3V/A=
-----END CERTIFICATE-----
"#;

const TRUSTED_AKI: &str = "a9:c2:a3:da:2f:6d:ac:54:ee:ce:b9:4e:e8:2c:c9:2c:00:83:80:33";
const TRUSTED_FINGERPRINT: &str =
    "7421221cb1da97b3edb4ad2ccb4d00cbdced1e1316bf6768e677218cdb246d3e";

const EAA_Q_SERVICE_TYPE: &str = "http://uri.etsi.org/TrstSvc/Svctype/EAA/Q";

fn entry() -> TslServiceEntry {
    TslServiceEntry {
        service_name: "QEAA Provider".to_string(),
        service_type_identifier: EAA_Q_SERVICE_TYPE.to_string(),
        service_status: "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted".to_string(),
    }
}

fn parsed_cert(fingerprint: &str) -> ParsedCertificate {
    let mut handle = MockSignaturePublicKeyHandle::new();
    handle.expect_verify().returning(|_, _| Ok(()));
    ParsedCertificate {
        attributes: CertificateX509AttributesDTO {
            serial_number: "00".to_string(),
            not_before: datetime!(2025-03-01 00:00 UTC),
            not_after: datetime!(2028-03-01 00:00 UTC),
            issuer: "CN=German Registrar, C=DE".to_string(),
            subject: "CN=German Registrar, C=DE".to_string(),
            fingerprint: fingerprint.to_string(),
            extensions: vec![],
        },
        subject_common_name: None,
        subject_key_identifier: None,
        public_key: KeyHandle::SignatureOnly(SignatureKeyHandle::PublicKeyOnly(Arc::new(handle))),
    }
}

fn key_identifier(hex: &str) -> standardized_types::x509::KeyIdentifier {
    standardized_types::x509::KeyIdentifier::from(
        hex.split(':')
            .map(|b| u8::from_str_radix(b, 16).unwrap())
            .collect::<Vec<u8>>(),
    )
}

/// Index whose entry is reachable via AKI→CA-SKI.
fn index_with_ca_ski() -> PreprocessedLotl {
    let mut index = PreprocessedLotl {
        entries: vec![entry()],
        ..Default::default()
    };
    index.cert_index.insert(
        TRUSTED_FINGERPRINT.to_string(),
        Some(key_identifier(TRUSTED_AKI)),
        TRUSTED_CERT.to_string(),
        0,
    );
    index
}

/// Index whose entry is reachable only by leaf fingerprint.
fn index_with_fingerprint() -> PreprocessedLotl {
    let mut index = PreprocessedLotl {
        entries: vec![entry()],
        ..Default::default()
    };
    index
        .cert_index
        .insert(TRUSTED_FINGERPRINT.to_string(), None, String::new(), 0);
    index
}

fn subscriber(validator: MockCertificateValidator) -> EtsiLotlSubscriber {
    // matcher tests call find_matching_for_certificate directly; the cache is only used by
    // validate_subscription
    let storage = Arc::new(InMemoryStorage::new(HashMap::new()));
    let cache = EtsiLotlCache::new(
        Arc::new(EmptyResolver),
        storage,
        100,
        Duration::seconds(60),
        Duration::seconds(60),
    );
    EtsiLotlSubscriber::new(cache, Arc::new(validator), vec![])
}

/// Resolver returning an empty (default) serialized `PreprocessedLotl`.
struct EmptyResolver;

#[async_trait::async_trait]
impl Resolver for EmptyResolver {
    type Error = ResolverError;

    async fn do_resolve(
        &self,
        _key: &str,
        _last_modified: Option<&time::OffsetDateTime>,
    ) -> Result<ResolveResult, Self::Error> {
        Ok(ResolveResult::NewValue {
            content: serde_json::to_vec(&PreprocessedLotl::default())?,
            media_type: Some("application/json".to_string()),
            expiry_date: None,
        })
    }
}

#[test]
fn capabilities_are_roleless_with_remote_identifiers() {
    let caps = subscriber(MockCertificateValidator::new()).get_capabilities();
    assert!(caps.roles.is_empty());
    assert!(caps.features.contains(&Feature::SupportsRemoteIdentifiers));
    assert!(
        caps.resolvable_identifier_types
            .contains(&crate::model::identifier::IdentifierType::Certificate)
    );
}

#[tokio::test]
async fn validate_subscription_returns_no_role() {
    let reference = Url::parse("https://example.com/lotl").unwrap();
    let result = subscriber(MockCertificateValidator::new())
        .validate_subscription(&reference, None)
        .await
        .unwrap();
    assert_eq!(result.role, None);
}

#[tokio::test]
async fn matches_certificate_via_aki_when_consistency_check_passes() {
    let mut validator = MockCertificateValidator::new();
    // AKI → CA-SKI hit; the chain-consistency check is mocked to succeed.
    validator
        .expect_validate_chain_against_ca_chain()
        .returning(|_, _, _, _| Ok(parsed_cert(TRUSTED_FINGERPRINT)));
    let subscriber = subscriber(validator);

    let index = index_with_ca_ski();
    let result = subscriber
        .find_matching_for_certificate(&index, TRUSTED_CERT)
        .await
        .unwrap();

    let entry = result
        .first()
        .expect("AKI match with passing consistency must resolve");
    assert_eq!(entry.service_type_identifier, EAA_Q_SERVICE_TYPE);
}

#[tokio::test]
async fn aki_match_is_rejected_when_consistency_check_fails() {
    let mut validator = MockCertificateValidator::new();
    // AKI → CA-SKI hit but the consistency check fails: the entry must not be accepted
    validator
        .expect_validate_chain_against_ca_chain()
        .returning(|_, _, _, _| {
            Err(CertValidatorError::InvalidCaCertificateChain(
                "inconsistent chain".to_string(),
            ))
        });
    // fallback parse returns a non-indexed fingerprint, so the fallback also misses
    validator
        .expect_parse_pem_chain()
        .returning(|_, _| Ok(parsed_cert("not-indexed")));
    let subscriber = subscriber(validator);

    let index = index_with_ca_ski();
    let result = subscriber
        .find_matching_for_certificate(&index, TRUSTED_CERT)
        .await
        .unwrap();

    assert!(
        result.is_empty(),
        "consistency-check failure must reject the AKI match"
    );
}

#[tokio::test]
async fn matches_certificate_via_leaf_fingerprint_fallback() {
    let mut validator = MockCertificateValidator::new();
    // No AKI entry in this index; the leaf fingerprint matches instead.
    validator
        .expect_parse_pem_chain()
        .returning(|_, _| Ok(parsed_cert(TRUSTED_FINGERPRINT)));
    let subscriber = subscriber(validator);

    let index = index_with_fingerprint();
    let result = subscriber
        .find_matching_for_certificate(&index, TRUSTED_CERT)
        .await
        .unwrap();

    let entry = result
        .first()
        .expect("leaf-fingerprint fallback must resolve");
    assert_eq!(entry.service_type_identifier, EAA_Q_SERVICE_TYPE);
}

#[tokio::test]
async fn no_match_returns_none() {
    let mut validator = MockCertificateValidator::new();
    validator
        .expect_parse_pem_chain()
        .returning(|_, _| Ok(parsed_cert("unknown-fingerprint")));
    let subscriber = subscriber(validator);

    let index = PreprocessedLotl::default();
    let result = subscriber
        .find_matching_for_certificate(&index, TRUSTED_CERT)
        .await
        .unwrap();
    assert!(result.is_empty());
}

#[tokio::test]
async fn resolve_entries_rejects_unsupported_identifier_type() {
    let subscriber = subscriber(MockCertificateValidator::new());
    let index = PreprocessedLotl::default();
    let identifier = crate::service::test_utilities::dummy_identifier();

    let err = find_matching_for_identifier(&subscriber, &index, &identifier)
        .await
        .expect_err("Did identifiers are unsupported");
    assert_matches!(
        err,
        crate::provider::trust_list_subscriber::error::TrustListSubscriberError::UnsupportedIdentifierType(_)
    );
}

fn subscriber_with_delegate(
    validator: MockCertificateValidator,
    delegate: std::sync::Arc<dyn crate::provider::trust_list_subscriber::TrustListSubscriber>,
) -> EtsiLotlSubscriber {
    let storage = Arc::new(InMemoryStorage::new(HashMap::new()));
    let cache = EtsiLotlCache::new(
        Arc::new(EmptyResolver),
        storage,
        100,
        Duration::seconds(60),
        Duration::seconds(60),
    );
    EtsiLotlSubscriber::new(cache, Arc::new(validator), vec![delegate])
}

#[tokio::test]
async fn resolve_entries_delegates_to_lote_when_local_miss() {
    use crate::provider::trust_list_subscriber::MockTrustListSubscriber;

    // Index has a LoTE member URL but no local entries that match our cert.
    let index = PreprocessedLotl {
        delegated_member_urls: vec!["https://example.com/lote".to_string()],
        ..Default::default()
    };

    // no AKI match; fallback parse returns a fingerprint absent from the index
    let mut validator = MockCertificateValidator::new();
    validator
        .expect_parse_pem_chain()
        .returning(|_, _| Ok(parsed_cert("not-in-local-index")));

    // LoTE delegate returns a hit.
    let expected = entry();
    let mut delegate = MockTrustListSubscriber::new();
    delegate
        .expect_resolve_certificate()
        .withf(|url, pem| url.as_str() == "https://example.com/lote" && pem == TRUSTED_CERT)
        .returning({
            let expected = expected.clone();
            move |_, _| {
                Ok(vec![TrustEntityResponse {
                    derived_role: role_for_service_type(&ServiceType::from(
                        expected.service_type_identifier.clone(),
                    )),
                    metadata: TrustEntityMetadata::Tsl(expected.clone()),
                }])
            }
        });

    let sub = subscriber_with_delegate(validator, Arc::new(delegate));

    // Build a Certificate identifier with one active cert whose chain = TRUSTED_CERT.
    let identifier_id = shared_types::IdentifierId::from(uuid::Uuid::new_v4());
    let mut identifier = crate::service::test_utilities::dummy_identifier();
    identifier.id = identifier_id;
    let mut cert = crate::service::test_utilities::dummy_certificate(identifier_id);
    cert.chain = TRUSTED_CERT.to_string();
    identifier.data = crate::model::identifier::IdentifierData::Certificate(
        crate::model::relation::RelatedVec::from(vec![cert]),
    );

    let entities = super::find_matching_for_identifier(&sub, &index, &identifier)
        .await
        .expect("should not error");
    let entity = entities
        .into_iter()
        .next()
        .expect("resolve_entries must surface LoTE-delegated entry");
    match entity.metadata {
        TrustEntityMetadata::Tsl(e) => {
            assert_eq!(e.service_type_identifier, EAA_Q_SERVICE_TYPE);
        }
        other => panic!("expected TSL entry, got {other:?}"),
    }
}

fn pointer(mime: Option<&str>, tsl_type: Option<TslType>) -> OtherTslPointer {
    OtherTslPointer {
        service_digital_identities: ServiceDigitalIdentities {
            identities: vec![ServiceDigitalIdentity {
                digital_ids: vec![DigitalId {
                    x509_certificate: None,
                    x509_ski: None,
                    x509_subject_name: None,
                }],
            }],
        },
        tsl_location: "https://example.test/member/01.xml".to_string(),
        additional_information: Some(AdditionalInformation {
            other_information: vec![OtherInformation {
                tsl_type,
                scheme_territory: None,
                mime_type: mime.map(str::to_string),
            }],
        }),
    }
}

#[test]
fn classifies_generic_xml_pointer_as_member() {
    let p = pointer(Some(MIME_TSL_XML), Some(TslType::Generic));
    assert_eq!(classify_pointer(&p), PointerKind::Member);
}

#[test]
fn delegates_non_612_list_type() {
    let p = pointer(
        Some("application/jwt"),
        Some(TslType::from(
            "http://uri.etsi.org/019602/LoTEType/EURegistrarsAndRegistersList".to_string(),
        )),
    );
    assert_eq!(classify_pointer(&p), PointerKind::Delegate);
}
