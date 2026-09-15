use std::borrow::Cow;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

use shared_types::{
    DidValue, EcosystemId, OrganisationId, TrustCollectionId, TrustListSubscriberId,
};
use similar_asserts::assert_eq;
use standardized_types::etsi_119_475::registration_certificate::{
    Payload, Status, SupervisoryAuthority,
};
use standardized_types::etsi_119_475::registry::LegalEntity;
use standardized_types::jwk::{PublicJwk, PublicJwkEc};
use time::OffsetDateTime;
use url::Url;

use super::{QUALIFIED_EAA_CATEGORY, TrustEntityIdentifier, WRPValidatorImpl};
use crate::model::list_filter::ListFilterCondition;
use crate::model::trust_collection::{
    GetTrustCollectionList, TrustCollection, TrustCollectionFilterValue,
};
use crate::model::trust_list_role::TrustListRoleEnum;
use crate::model::trust_list_subscription::{
    GetTrustListSubscriptionList, TrustListSubscription, TrustListSubscriptionFilterValue,
    TrustListSubscriptionState,
};
use crate::proto::certificate_validator::MockCertificateValidator;
use crate::proto::http_client::{
    HttpClient, Method, MockHttpClient, Request, RequestBuilder, Response, StatusCode,
};
use crate::proto::jwt::model::{DecomposedJwt, JWTHeader, JWTPayload};
use crate::proto::wrp_validator::WRPValidator;
use crate::proto::wrp_validator::error::WRPValidatorError;
use crate::proto::wrp_validator::model::{TrustScope, WRPPayload, WRPPayloadData};
use crate::provider::credential_formatter::model::{PublicKeySource, X5References};
use crate::provider::did_method::provider::MockDidMethodProvider;
use crate::provider::key_algorithm::provider::MockKeyAlgorithmProvider;
use crate::provider::revocation::provider::MockRevocationMethodProvider;
use crate::provider::trust_list_subscriber::etsi_lotl::model::TslServiceEntry;
use crate::provider::trust_list_subscriber::provider::MockTrustListSubscriberProvider;
use crate::provider::trust_list_subscriber::{
    MockTrustListSubscriber, TrustEntityMetadata, TrustEntityResponse,
};
use crate::repository::trust_collection_repository::MockTrustCollectionRepository;
use crate::repository::trust_list_subscription_repository::MockTrustListSubscriptionRepository;
use crate::service::test_utilities::{
    dummy_credential_schema, dummy_organisation, dummy_trust_collection,
};

fn make_validator() -> WRPValidatorImpl {
    WRPValidatorImpl::new(
        Arc::new(MockTrustCollectionRepository::default()),
        Arc::new(MockTrustListSubscriptionRepository::default()),
        Arc::new(MockTrustListSubscriberProvider::default()),
        Arc::new(MockDidMethodProvider::default()),
        Arc::new(MockKeyAlgorithmProvider::default()),
        Arc::new(MockCertificateValidator::default()),
        Arc::new(MockHttpClient::default()),
        Arc::new(MockRevocationMethodProvider::default()),
    )
}

fn make_validator_with_client(client: Arc<dyn HttpClient>) -> WRPValidatorImpl {
    WRPValidatorImpl::new(
        Arc::new(MockTrustCollectionRepository::default()),
        Arc::new(MockTrustListSubscriptionRepository::default()),
        Arc::new(MockTrustListSubscriberProvider::default()),
        Arc::new(MockDidMethodProvider::default()),
        Arc::new(MockKeyAlgorithmProvider::default()),
        Arc::new(MockCertificateValidator::default()),
        client,
        Arc::new(MockRevocationMethodProvider::default()),
    )
}

fn make_validator_with_subscription(
    subscription: TrustListSubscription,
    resolved_entity: Option<TrustEntityResponse>,
) -> WRPValidatorImpl {
    let collection = TrustCollection {
        ecosystem: TEST_ECOSYSTEM.into(),
        id: TrustCollectionId::from(uuid::Uuid::new_v4()),
        name: "collection".to_string(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        deactivated_at: None,
        remote_trust_collection_url: None,
        organisation: dummy_organisation(None).into(),
    };
    let collection_id = collection.id;

    let mut collection_repo = MockTrustCollectionRepository::default();
    // mimics the DB: the collection is only returned when the query asks for its ecosystem
    collection_repo.expect_list().returning(move |query| {
        let filtering = query.filtering.as_ref().expect("expected a filter");
        let values = if filtered_ecosystems(filtering).contains(&collection.ecosystem) {
            vec![collection.clone()]
        } else {
            vec![]
        };

        Ok(GetTrustCollectionList {
            total_pages: 1,
            total_items: values.len() as u64,
            values,
        })
    });

    let mut subscription_repo = MockTrustListSubscriptionRepository::default();
    // mimics the DB: subscriptions are only returned for the collections queried for
    subscription_repo.expect_list().returning(move |query| {
        let filtering = query.filtering.as_ref().expect("expected a filter");
        let values = if filtered_trust_collection_ids(filtering).contains(&collection_id) {
            vec![subscription.clone()]
        } else {
            vec![]
        };

        Ok(GetTrustListSubscriptionList {
            total_pages: 1,
            total_items: values.len() as u64,
            values,
        })
    });

    let mut subscriber = MockTrustListSubscriber::default();
    subscriber
        .expect_resolve_certificate()
        .returning(move |_, _| Ok(resolved_entity.clone().into_iter().collect()));

    let subscriber = Arc::new(subscriber);
    let mut subscriber_provider = MockTrustListSubscriberProvider::default();
    subscriber_provider
        .expect_get()
        .returning(move |_| Ok(subscriber.clone()));

    WRPValidatorImpl::new(
        Arc::new(collection_repo),
        Arc::new(subscription_repo),
        Arc::new(subscriber_provider),
        Arc::new(MockDidMethodProvider::default()),
        Arc::new(MockKeyAlgorithmProvider::default()),
        Arc::new(MockCertificateValidator::default()),
        Arc::new(MockHttpClient::default()),
        Arc::new(MockRevocationMethodProvider::default()),
    )
}

const TEST_ECOSYSTEM: &str = "EUDI";

fn trust_scope(ecosystem: &str) -> TrustScope {
    TrustScope {
        organisation_id: OrganisationId::from(uuid::Uuid::new_v4()),
        ecosystem: ecosystem.into(),
    }
}

/// Collects the ecosystems a trust collection list query filters on.
fn filtered_ecosystems(
    condition: &ListFilterCondition<TrustCollectionFilterValue>,
) -> Vec<EcosystemId> {
    match condition {
        ListFilterCondition::And(conditions) | ListFilterCondition::Or(conditions) => {
            conditions.iter().flat_map(filtered_ecosystems).collect()
        }
        ListFilterCondition::Value(TrustCollectionFilterValue::Ecosystems(ecosystems)) => {
            ecosystems.to_owned()
        }
        ListFilterCondition::Value(_) => vec![],
    }
}

/// Collects the trust collection ids a subscription list query filters on.
fn filtered_trust_collection_ids(
    condition: &ListFilterCondition<TrustListSubscriptionFilterValue>,
) -> Vec<TrustCollectionId> {
    match condition {
        ListFilterCondition::And(conditions) | ListFilterCondition::Or(conditions) => conditions
            .iter()
            .flat_map(filtered_trust_collection_ids)
            .collect(),
        ListFilterCondition::Value(TrustListSubscriptionFilterValue::TrustCollectionId(ids)) => {
            ids.to_owned()
        }
        ListFilterCondition::Value(_) => vec![],
    }
}

fn dummy_subscription(role: Option<TrustListRoleEnum>) -> TrustListSubscription {
    TrustListSubscription {
        id: uuid::Uuid::new_v4().into(),
        name: "subscription".to_string(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        deactivated_at: None,
        r#type: TrustListSubscriberId::from_str("ETSI_LOTL").unwrap(),
        reference: "https://example.com/lotl".to_string(),
        role,
        state: TrustListSubscriptionState::Active,
        trust_collection: dummy_trust_collection().into(),
    }
}

fn tsl_entity(derived_role: Option<TrustListRoleEnum>) -> TrustEntityResponse {
    TrustEntityResponse {
        derived_role,
        metadata: TrustEntityMetadata::Tsl(TslServiceEntry {
            service_name: "service".to_string(),
            service_type_identifier: "http://example.com/svc".to_string(),
            service_status: "active".to_string(),
        }),
    }
}

#[tokio::test]
async fn test_roleless_subscription_accepts_when_derived_role_matches() {
    // given: a roleless (LOTL) subscription resolving a TSL entry with derived QeaaProvider
    let validator = make_validator_with_subscription(
        dummy_subscription(None),
        Some(tsl_entity(Some(TrustListRoleEnum::QeaaProvider))),
    );

    // when: requesting trust for the matching role
    let result = validator
        .perform_trust_validation(
            TrustEntityIdentifier::PemChain(Cow::from("pem")),
            TrustListRoleEnum::QeaaProvider,
            &trust_scope(TEST_ECOSYSTEM),
        )
        .await
        .unwrap();

    // then: the entity is accepted
    assert!(result.is_some(), "expected entity to be accepted");
}

#[tokio::test]
async fn test_roleless_subscription_rejects_when_derived_role_mismatches() {
    // given: a roleless (LOTL) subscription resolving a TSL entry with derived QeaaProvider
    let validator = make_validator_with_subscription(
        dummy_subscription(None),
        Some(tsl_entity(Some(TrustListRoleEnum::QeaaProvider))),
    );

    // when: requesting trust for a different role, even though the cert resolves
    let result = validator
        .perform_trust_validation(
            TrustEntityIdentifier::PemChain(Cow::from("pem")),
            TrustListRoleEnum::PidProvider,
            &trust_scope(TEST_ECOSYSTEM),
        )
        .await
        .unwrap();

    // then: the entity is rejected because the derived role does not match
    assert!(result.is_none(), "expected entity to be rejected");
}

#[tokio::test]
async fn test_role_bearing_subscription_accepts_without_derived_role_check() {
    // given: a role-bearing subscription that resolves a TSL entry with a *mismatching*
    // derived role (which must NOT be checked because the subscription was role-filtered)
    let validator = make_validator_with_subscription(
        dummy_subscription(Some(TrustListRoleEnum::PidProvider)),
        Some(tsl_entity(Some(TrustListRoleEnum::QeaaProvider))),
    );

    // when
    let result = validator
        .perform_trust_validation(
            TrustEntityIdentifier::PemChain(Cow::from("pem")),
            TrustListRoleEnum::PidProvider,
            &trust_scope(TEST_ECOSYSTEM),
        )
        .await
        .unwrap();

    // then: accepted as-is, no derived-role gate for role-bearing subscriptions
    assert!(
        result.is_some(),
        "expected role-bearing subscription entity to be accepted unchanged"
    );
}

#[tokio::test]
async fn test_trust_collections_are_filtered_by_the_scoped_ecosystem() {
    // given: a repository asserting on the filter it is queried with
    let scope = trust_scope(TEST_ECOSYSTEM);
    let expected = vec![EcosystemId::from(TEST_ECOSYSTEM)];

    let mut collection_repo = MockTrustCollectionRepository::default();
    collection_repo
        .expect_list()
        .times(1)
        .withf(move |query| {
            filtered_ecosystems(query.filtering.as_ref().expect("expected a filter")) == expected
        })
        .returning(|_| {
            Ok(GetTrustCollectionList {
                values: vec![],
                total_pages: 0,
                total_items: 0,
            })
        });

    let mut subscription_repo = MockTrustListSubscriptionRepository::default();
    subscription_repo.expect_list().returning(|_| {
        Ok(GetTrustListSubscriptionList {
            values: vec![],
            total_pages: 0,
            total_items: 0,
        })
    });

    let validator = WRPValidatorImpl::new(
        Arc::new(collection_repo),
        Arc::new(subscription_repo),
        Arc::new(MockTrustListSubscriberProvider::default()),
        Arc::new(MockDidMethodProvider::default()),
        Arc::new(MockKeyAlgorithmProvider::default()),
        Arc::new(MockCertificateValidator::default()),
        Arc::new(MockHttpClient::default()),
        Arc::new(MockRevocationMethodProvider::default()),
    );

    // when
    validator
        .perform_trust_validation(
            TrustEntityIdentifier::PemChain(Cow::from("pem")),
            TrustListRoleEnum::QeaaProvider,
            &scope,
        )
        .await
        .unwrap();

    // then: the `withf` expectation above asserts the ecosystem filter was applied
}

#[tokio::test]
async fn test_trust_of_another_ecosystem_is_not_resolved() {
    // given: a subscription that would resolve the certificate, but its trust collection
    // belongs to `TEST_ECOSYSTEM`
    let validator = make_validator_with_subscription(
        dummy_subscription(None),
        Some(tsl_entity(Some(TrustListRoleEnum::QeaaProvider))),
    );

    // when: acting within a different ecosystem
    let result = validator
        .perform_trust_validation(
            TrustEntityIdentifier::PemChain(Cow::from("pem")),
            TrustListRoleEnum::QeaaProvider,
            &trust_scope("OTHER_ECOSYSTEM"),
        )
        .await
        .unwrap();

    // then: the other ecosystem's trust collection must not be consulted
    assert!(
        result.is_none(),
        "trust must not be resolved from a different ecosystem's collections"
    );
}

fn all_x5_references() -> X5References {
    X5References {
        x5c: true,
        x5u: true,
        x5t_s256: true,
    }
}

#[tokio::test]
async fn test_qeaa_issuer_trusted_when_in_tsl_with_full_x5_references() {
    let validator = make_validator_with_subscription(
        dummy_subscription(None),
        Some(tsl_entity(Some(TrustListRoleEnum::QeaaProvider))),
    );

    let result = validator
        .validate_credential_issuer(
            Some("pem"),
            &dummy_credential_schema(),
            &[],
            Some(QUALIFIED_EAA_CATEGORY),
            all_x5_references(),
            &trust_scope(TEST_ECOSYSTEM),
        )
        .await
        .unwrap();

    assert!(result.is_some(), "QEAA issuer in the TSL must be trusted");
}

#[tokio::test]
async fn test_qeaa_issuer_trusted_without_x5c() {
    let validator = make_validator_with_subscription(
        dummy_subscription(None),
        Some(tsl_entity(Some(TrustListRoleEnum::QeaaProvider))),
    );

    // ETSI TS 119 472-1 marks x5c as recommended only; x5u + x5t#S256 suffice.
    let result = validator
        .validate_credential_issuer(
            Some("pem"),
            &dummy_credential_schema(),
            &[],
            Some(QUALIFIED_EAA_CATEGORY),
            X5References {
                x5c: false,
                ..all_x5_references()
            },
            &trust_scope(TEST_ECOSYSTEM),
        )
        .await
        .unwrap();

    assert!(
        result.is_some(),
        "QEAA issuer referencing its certificate via x5u alone must be trusted"
    );
}

#[tokio::test]
async fn test_qeaa_issuer_rejected_when_x5_reference_missing() {
    let validator = make_validator_with_subscription(
        dummy_subscription(None),
        Some(tsl_entity(Some(TrustListRoleEnum::QeaaProvider))),
    );

    let result = validator
        .validate_credential_issuer(
            Some("pem"),
            &dummy_credential_schema(),
            &[],
            Some(QUALIFIED_EAA_CATEGORY),
            X5References {
                x5u: false,
                ..all_x5_references()
            },
            &trust_scope(TEST_ECOSYSTEM),
        )
        .await;

    assert!(
        matches!(result, Err(WRPValidatorError::IssuerNotTrusted { .. })),
        "a QEAA issuer missing x5u must be rejected"
    );
}

#[tokio::test]
async fn test_non_qualified_category_skips_issuer_trust_check() {
    let validator = make_validator_with_subscription(
        dummy_subscription(None),
        Some(tsl_entity(Some(TrustListRoleEnum::QeaaProvider))),
    );

    let result = validator
        .validate_credential_issuer(
            Some("pem"),
            &dummy_credential_schema(),
            &[],
            Some("urn:etsi:esi:eaa:eu:pub"),
            all_x5_references(),
            &trust_scope(TEST_ECOSYSTEM),
        )
        .await
        .unwrap();

    assert!(
        result.is_none(),
        "non-qualified EAA is out of scope and must not be trust-checked"
    );
}

#[tokio::test]
async fn test_pid_with_non_qualified_category_still_requires_pid_provider() {
    let validator = make_validator_with_subscription(
        dummy_subscription(None),
        Some(tsl_entity(Some(TrustListRoleEnum::QeaaProvider))),
    );
    let schema = dummy_credential_schema();
    let pid_schema_ids = vec![schema.schema_id().await.unwrap()];

    let result = validator
        .validate_credential_issuer(
            Some("pem"),
            &schema,
            &pid_schema_ids,
            Some("urn:etsi:esi:eaa:eu:pub"),
            all_x5_references(),
            &trust_scope(TEST_ECOSYSTEM),
        )
        .await;

    assert!(
        matches!(
            result,
            Err(WRPValidatorError::IssuerNotTrusted {
                role: "PID provider"
            })
        ),
        "an issuer-supplied category must not bypass the PID provider check"
    );
}

#[tokio::test]
async fn test_pid_with_qualified_category_still_requires_pid_provider() {
    let validator = make_validator_with_subscription(
        dummy_subscription(None),
        Some(tsl_entity(Some(TrustListRoleEnum::QeaaProvider))),
    );
    let schema = dummy_credential_schema();
    let pid_schema_ids = vec![schema.schema_id().await.unwrap()];

    let result = validator
        .validate_credential_issuer(
            Some("pem"),
            &schema,
            &pid_schema_ids,
            Some(QUALIFIED_EAA_CATEGORY),
            all_x5_references(),
            &trust_scope(TEST_ECOSYSTEM),
        )
        .await;

    assert!(
        matches!(
            result,
            Err(WRPValidatorError::IssuerNotTrusted {
                role: "PID provider"
            })
        ),
        "a PID must be checked against the PID provider role, not the QEAA role"
    );
}

fn dummy_wrp_payload() -> WRPPayload {
    WRPPayload {
        data: WRPPayloadData {
            trade_name: None,
            support_uri: vec![],
            srv_description: vec![],
            intended_use: vec![],
            is_psb: None,
            entitlement: vec![],
            provides_attestations: vec![],
            supervisory_authority: LegalEntity {
                legal_person: None,
                natural_person: None,
                identifier: vec![],
                postal_address: None,
                country: "AT".to_string(),
                email: vec![],
                phone: vec![],
                info_uri: vec![],
            },
            registry_uri: Url::parse("https://registry.example.com").unwrap(),
            uses_intermediary: None,
            legal_person: None,
            natural_person: None,
            identifier: vec![],
            postal_address: None,
            country: "AT".to_string(),
            email: vec![],
            phone: vec![],
            info_uri: vec![],
        },
    }
}

fn dummy_decomposed_jwt(
    key_id: Option<String>,
    x5c: Option<Vec<String>>,
) -> DecomposedJwt<WRPPayload> {
    DecomposedJwt {
        header: JWTHeader {
            algorithm: "ES256".to_string(),
            key_id,
            r#type: None,
            jwk: None,
            jwt: None,
            key_attestation: None,
            x5c,
            x5u: None,
            x5t_s256: None,
        },
        payload: JWTPayload {
            issued_at: None,
            expires_at: None,
            invalid_before: None,
            issuer: None,
            subject: None,
            audience: None,
            jwt_id: None,
            proof_of_possession_key: None,
            custom: dummy_wrp_payload(),
        },
        signature: vec![],
        unverified_jwt: String::new(),
    }
}

fn make_http_response(body: Vec<u8>, url: &str) -> Response {
    Response {
        body,
        headers: Default::default(),
        status: StatusCode(200),
        request: Request {
            body: None,
            headers: Default::default(),
            method: Method::Get,
            url: url.to_owned(),
            timeout: None,
        },
    }
}

fn dummy_payload() -> Payload {
    Payload {
        name: "Test RP".to_string(),
        sub_ln: Some("Test Legal Name".to_string()),
        sub_gn: None,
        sub_fn: None,
        country: "AT".to_string(),
        registry_uri: Url::parse("https://registry.example.com").unwrap(),
        service_descriptions: vec![],
        entitlements: vec![],
        privacy_policy: Url::parse("https://example.com/privacy").unwrap(),
        info_uri: Url::parse("https://example.com/info").unwrap(),
        supervisory_authority: SupervisoryAuthority {
            email: "auth@example.com".to_string(),
            phone: "+43123456".to_string(),
            uri: "https://authority.example.com".to_string(),
        },
        policy_id: vec![],
        certificate_policy: Url::parse("https://example.com/policy").unwrap(),
        status: Status {
            status_list: HashMap::new(),
        },
        provides_attestations: None,
        credentials: None,
        purpose: None,
        intended_use_id: None,
        public_body: None,
        support_uri: Url::parse("https://example.com/support").unwrap(),
        intermediary: None,
    }
}

#[test]
fn test_consistency_identical_payloads_returns_ok() {
    // given
    let validator = make_validator();
    let payload = dummy_payload();

    // when
    let result = validator.validate_registration_certificates_consistency(&payload, &payload);

    // then
    assert!(result.is_ok());
}

#[test]
fn test_consistency_name_mismatch_returns_error() {
    // given
    let validator = make_validator();
    let first = dummy_payload();
    let mut second = dummy_payload();
    second.name = "Different RP Name".to_string();

    // when
    let err = validator
        .validate_registration_certificates_consistency(&first, &second)
        .unwrap_err();

    // then
    assert!(
        matches!(
            &err,
            WRPValidatorError::RegistrationCertificateMissmatch { field_name, .. }
                if field_name == "name"
        ),
        "unexpected error: {err}"
    );
}

#[test]
fn test_consistency_country_mismatch_returns_error() {
    // given
    let validator = make_validator();
    let first = dummy_payload();
    let mut second = dummy_payload();
    second.country = "DE".to_string();

    // when
    let err = validator
        .validate_registration_certificates_consistency(&first, &second)
        .unwrap_err();

    // then
    assert!(
        matches!(
            &err,
            WRPValidatorError::RegistrationCertificateMissmatch { field_name, .. }
                if field_name == "country"
        ),
        "unexpected error: {err}"
    );
}

#[test]
fn test_consistency_registry_uri_mismatch_returns_error() {
    // given
    let validator = make_validator();
    let first = dummy_payload();
    let mut second = dummy_payload();
    second.registry_uri = Url::parse("https://other-registry.example.com").unwrap();

    // when
    let err = validator
        .validate_registration_certificates_consistency(&first, &second)
        .unwrap_err();

    // then
    assert!(
        matches!(
            &err,
            WRPValidatorError::RegistrationCertificateMissmatch { field_name, .. }
                if field_name == "registry_uri"
        ),
        "unexpected error: {err}"
    );
}

#[test]
fn test_consistency_support_uri_mismatch_returns_error() {
    // given
    let validator = make_validator();
    let first = dummy_payload();
    let mut second = dummy_payload();
    second.support_uri = Url::parse("https://other-support.example.com").unwrap();

    // when
    let err = validator
        .validate_registration_certificates_consistency(&first, &second)
        .unwrap_err();

    // then
    assert!(
        matches!(
            &err,
            WRPValidatorError::RegistrationCertificateMissmatch { field_name, .. }
                if field_name == "support_uri"
        ),
        "unexpected error: {err}"
    );
}

#[test]
fn test_consistency_non_validated_fields_are_ignored() {
    // given
    let validator = make_validator();
    let first = dummy_payload();
    let mut second = dummy_payload();
    // `credentials`, `purpose`, `provides_attestations`, and `intended_use_id`
    // are intentionally excluded from the consistency check
    second.credentials = Some(vec![]);
    second.purpose = Some(vec![]);
    second.intended_use_id = Some("different_use_id".to_string());
    second.public_body = Some(true);

    // when
    let result = validator.validate_registration_certificates_consistency(&first, &second);

    // then
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_resolve_signing_method_returns_error_when_no_jwks_url_and_no_x5c() {
    // given
    let validator = make_validator();
    let token = dummy_decomposed_jwt(None, None);

    // when
    let result = validator.resolve_signing_method(&token, None).await;

    // then
    assert!(
        matches!(result, Err(WRPValidatorError::MissingSigningDetails)),
        "unexpected result: {result:?}"
    );
}

#[tokio::test]
async fn test_resolve_signing_method_falls_back_to_x5c_when_no_jwks_url() {
    // given
    let validator = make_validator();
    let x5c = vec!["cert-data".to_string()];
    let token = dummy_decomposed_jwt(None, Some(x5c.clone()));

    // when
    let result = validator
        .resolve_signing_method(&token, None)
        .await
        .unwrap();

    // then
    assert!(
        matches!(result, PublicKeySource::X5c { x5c: refs } if refs == x5c.as_slice()),
        "expected X5c signing method"
    );
}

#[tokio::test]
async fn test_resolve_signing_method_fetches_jwks_and_returns_matching_key() {
    // given
    const JWKS_URL: &str = "https://jwks.example.com/keys";
    const KEY_ID: &str = "test-key-id";

    let mut mock_client = MockHttpClient::new();
    mock_client
        .expect_get()
        .withf(|url| url == JWKS_URL)
        .returning(|url| {
            let mut inner = MockHttpClient::new();
            let body = serde_json::json!({
                "keys": [{"kty": "EC", "crv": "P-256", "x": "AAAA", "kid": "test-key-id"}]
            })
            .to_string()
            .into_bytes();
            inner
                .expect_send()
                .returning(move |url, _, _, _, _| Ok(make_http_response(body.clone(), url)));
            RequestBuilder::new(Arc::new(inner), Method::Get, url)
        });

    let validator = make_validator_with_client(Arc::new(mock_client));
    let token = dummy_decomposed_jwt(Some(KEY_ID.to_string()), None);

    // when
    let result = validator
        .resolve_signing_method(&token, Some(JWKS_URL))
        .await
        .unwrap();

    // then
    let PublicKeySource::Jwk { jwk } = result else {
        panic!("expected Jwk signing method, got something else");
    };
    assert_eq!(jwk.kid(), Some(KEY_ID));
}

#[tokio::test]
async fn test_resolve_signing_method_returns_error_when_key_not_found_in_jwks() {
    // given
    const JWKS_URL: &str = "https://jwks.example.com/keys";

    let mut mock_client = MockHttpClient::new();
    mock_client
        .expect_get()
        .withf(|url| url == JWKS_URL)
        .returning(|url| {
            let mut inner = MockHttpClient::new();
            let body = serde_json::json!({
                "keys": [{"kty": "EC", "crv": "P-256", "x": "AAAA", "kid": "other-key-id"}]
            })
            .to_string()
            .into_bytes();
            inner
                .expect_send()
                .returning(move |url, _, _, _, _| Ok(make_http_response(body.clone(), url)));
            RequestBuilder::new(Arc::new(inner), Method::Get, url)
        });

    let validator = make_validator_with_client(Arc::new(mock_client));
    let token = dummy_decomposed_jwt(Some("requested-key-id".to_string()), None);

    // when
    let result = validator
        .resolve_signing_method(&token, Some(JWKS_URL))
        .await;

    // then
    assert!(
        matches!(
            result,
            Err(WRPValidatorError::MissingRegistryKey(Some(ref kid))) if kid == "requested-key-id"
        ),
        "unexpected result: {result:?}"
    );
}

#[test]
fn test_try_from_did_public_key_source_returns_invalid_signing_method() {
    // given
    let did = DidValue::try_from("did:example:123".to_string()).unwrap();
    let source: PublicKeySource<'_> = PublicKeySource::Did {
        did: Cow::Owned(did),
        key_id: None,
    };

    // when
    let result: Result<TrustEntityIdentifier<'_>, WRPValidatorError> = source.try_into();

    // then
    assert!(
        matches!(
            result,
            Err(WRPValidatorError::InvalidSigningMethod(ref method)) if method == "DID"
        ),
        "expected InvalidSigningMethod(DID)"
    );
}

#[test]
fn test_try_from_jwk_public_key_source_returns_jwk_identifier() {
    // given
    let jwk = PublicJwk::Ec(PublicJwkEc {
        alg: None,
        r#use: None,
        kid: Some("key-1".to_string()),
        crv: "P-256".to_string(),
        x: "AAAA".to_string(),
        y: None,
    });
    let source: PublicKeySource<'_> = PublicKeySource::Jwk {
        jwk: Cow::Owned(jwk),
    };

    // when
    let result: Result<TrustEntityIdentifier<'_>, WRPValidatorError> = source.try_into();

    // then
    assert!(
        matches!(result, Ok(TrustEntityIdentifier::Jwk(_))),
        "expected TrustEntityIdentifier::Jwk"
    );
}
