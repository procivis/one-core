use hex_literal::hex;
use one_core::model::certificate::CertificateState;
use one_core::model::identifier::IdentifierType;
use one_core::model::remote_entity_cache::{CacheType, RemoteEntityCacheEntry};
use one_core::model::trust_list_role::TrustListRoleEnum;
use one_core::model::trust_list_subscription::TrustListSubscriptionState;
use shared_types::TrustListSubscriberId;
use similar_asserts::assert_eq;
use standardized_types::etsi_119_602::{MultiLangString, TrustedEntityInformation};
use standardized_types::x509::KeyIdentifier;
use uuid::Uuid;
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::fixtures::TestingIdentifierParams;
use crate::utils::api_clients::Response;
use crate::utils::context::TestContext;
use crate::utils::db_clients::certificates::TestingCertificateParams;
use crate::utils::db_clients::trust_collections::TestTrustCollectionParams;

#[tokio::test]
async fn test_resolve_trust_entries_unauthorized() {
    // GIVEN
    let context = TestContext::new_with_token("", None).await;

    // WHEN
    let resp: Response = context
        .api
        .identifiers
        .client
        .post(
            "/api/identifier/v1/resolve-trust-entries",
            serde_json::json!({
                "identifiers": [Uuid::new_v4()]
            }),
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_resolve_trust_entries_success_empty() {
    // GIVEN
    let context = TestContext::new(None).await;
    let identifier_id = Uuid::new_v4().into();

    // WHEN
    let resp = context
        .api
        .identifiers
        .resolve_trust_entries(&[identifier_id], None, None)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let body = resp.json_value().await;
    assert!(body.as_array().unwrap().is_empty());
}

#[tokio::test]
async fn test_resolve_trust_entries_identifiers_of_different_organisations() {
    // GIVEN
    let context = TestContext::new(None).await;
    let organisation = context.db.organisations.create().await;
    let other_organisation = context.db.organisations.create().await;
    let params = || TestingIdentifierParams {
        r#type: Some(IdentifierType::Certificate),
        ..Default::default()
    };
    let identifier = context.db.identifiers.create(&organisation, params()).await;
    let other_identifier = context
        .db
        .identifiers
        .create(&other_organisation, params())
        .await;

    // WHEN
    let resp = context
        .api
        .identifiers
        .resolve_trust_entries(&[identifier.id, other_identifier.id], None, None)
        .await;

    // THEN
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn test_resolve_trust_entries_from_cache_success() {
    // GIVEN
    let additional_config = r#"
trustListSubscriber:
  ETSI-LOTE:
    type: ETSI_LOTE
    display:
      translationId: ETSI LoTE
    enabled: true
    params:
      public:
        accepts: application/jwt
        leewaySeconds: 0
    "#;
    let context = TestContext::new(Some(additional_config.to_string())).await;
    let organisation = context.db.organisations.create().await;

    let pem = r#"-----BEGIN CERTIFICATE-----
MIHkMIGXoAMCAQICFGplpJ84r+DSD8MnjFLdyhcQiGc8MAUGAytlcDAAMCAXDTI1
MDYxNjE1MDQxMloYDzQ3NjMwNTEzMTUwNDEyWjAAMCowBQYDK2VwAyEADPgdSzff
JD51EE4P8hvRxcwsuVAbfbn/6XozFbn4GT+jITAfMB0GA1UdDgQWBBRsnYgGqNo/
0Yrapt79gdzc258hbTAFBgMrZXADQQAGooxtr6luOPyLyhJLDTZMz75hzhbokc4Q
X2qJiGDrkN4Lr/85kRw7KHlsHq/w1aXLp0/Eg/c5aMur6qSWBjMD
-----END CERTIFICATE-----
"#;
    let ski: KeyIdentifier = hex!("6C9D8806A8DA3FD18ADAA6DEFD81DCDCDB9F216D")
        .to_vec()
        .into();
    let fingerprint = "6d10f03019ebbf6eb5eb50a85664dcd81ab162f178657f76adc2b8885a9bdb5a";

    // 1. Prepare PreprocessedLote
    let trusted_entity = TrustedEntityInformation {
        te_name: vec![MultiLangString {
            lang: "en".to_string(),
            value: "Test Entity".to_string(),
        }],
        ..Default::default()
    };

    let ski = serde_json::to_string(&ski).unwrap();
    let ski = ski.trim_matches('"');
    let preprocessed_lote = serde_json::json!({
        "role": "ISSUER",
        "trusted_entities": [{ "info": trusted_entity, "derived_role": null }],
        "cert_index": {
            "fingerprint_to_entries": {
                fingerprint: [0]
            },
            "ca_ski_to_entries": {
                ski: [{
                    "idx": 0,
                    "pem": pem
                }]
            }
        }
    });

    let value = serde_json::to_vec(&preprocessed_lote).unwrap();

    // 2. Mock two trust lists in cache
    let url1 = "https://list1.com/";
    let url2 = "https://list2.com/";

    for url in [url1, url2] {
        context
            .db
            .remote_entities
            .add_entry(RemoteEntityCacheEntry {
                id: Uuid::new_v4().into(),
                created_date: one_core::clock::now_utc(),
                last_modified: one_core::clock::now_utc(),
                last_used: one_core::clock::now_utc(),
                expiration_date: None,
                key: url.to_string(),
                value: value.clone(),
                r#type: CacheType::TrustList,
                media_type: Some("application/jose".to_string()),
            })
            .await;
    }

    // 3. Setup Identifier with certificate
    let identifier = context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                r#type: Some(IdentifierType::Certificate),
                is_remote: Some(true),
                ..Default::default()
            },
        )
        .await;

    context
        .db
        .certificates
        .create(
            identifier.id,
            organisation.clone(),
            TestingCertificateParams {
                state: Some(CertificateState::Active),
                chain: Some(pem.to_string()),
                fingerprint: Some(fingerprint.to_string()),
                ..Default::default()
            },
        )
        .await;

    // 4. Setup two trust collections and subscriptions
    let subscriber_id = TrustListSubscriberId::from("ETSI-LOTE");
    for (i, url) in [url1, url2].into_iter().enumerate() {
        let tc = context
            .db
            .trust_collections
            .create(
                organisation.clone(),
                TestTrustCollectionParams {
                    name: Some(format!("Collection {}", i)),
                    ..Default::default()
                },
            )
            .await;

        context
            .db
            .trust_list_subscriptions
            .create(
                &format!("Subscription {}", i),
                Some(TrustListRoleEnum::Issuer),
                subscriber_id.clone(),
                url,
                TrustListSubscriptionState::Active,
                tc.id,
            )
            .await;
    }

    // subscriptions of other organisations are not considered
    let other_organisation = context.db.organisations.create().await;
    let other_collection = context
        .db
        .trust_collections
        .create(
            other_organisation.clone(),
            TestTrustCollectionParams {
                name: Some("Other collection".to_string()),
                ..Default::default()
            },
        )
        .await;
    context
        .db
        .trust_list_subscriptions
        .create(
            "Other subscription",
            Some(TrustListRoleEnum::Issuer),
            subscriber_id.clone(),
            url1,
            TrustListSubscriptionState::Active,
            other_collection.id,
        )
        .await;

    let organisation_without_collections = context.db.organisations.create().await;
    let identifier_without_collections = context
        .db
        .identifiers
        .create(
            &organisation_without_collections,
            TestingIdentifierParams {
                r#type: Some(IdentifierType::Certificate),
                is_remote: Some(true),
                ..Default::default()
            },
        )
        .await;
    context
        .db
        .certificates
        .create(
            identifier_without_collections.id,
            organisation_without_collections,
            TestingCertificateParams {
                state: Some(CertificateState::Active),
                chain: Some(pem.to_string()),
                fingerprint: Some(fingerprint.to_string()),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context
        .api
        .identifiers
        .resolve_trust_entries(&[identifier.id], None, None)
        .await;
    let resp_without_collections = context
        .api
        .identifiers
        .resolve_trust_entries(&[identifier_without_collections.id], None, None)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let body = resp.json_value().await;
    assert_eq!(body.as_array().unwrap().len(), 1);
    assert_eq!(body[0]["identifier"]["id"], identifier.id.to_string());

    let trust_entries = body[0]["trustEntries"].as_array().unwrap();
    assert_eq!(trust_entries.len(), 2);

    assert_eq!(resp_without_collections.status(), 200);
    let body = resp_without_collections.json_value().await;
    assert!(body[0]["trustEntries"].as_array().unwrap().is_empty());

    let mut collection_names: Vec<_> = trust_entries
        .iter()
        .map(|e| {
            e["source"]["trustCollection"]["name"]
                .as_str()
                .unwrap_or_else(|| panic!("Missing trust collection name in entry: {:?}", e))
        })
        .collect();
    collection_names.sort();
    assert_eq!(collection_names, vec!["Collection 0", "Collection 1"]);
}

#[tokio::test]
async fn test_resolve_trust_entries_did_identifier() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let did = context
        .db
        .dids
        .create(organisation.clone(), Default::default())
        .await;
    let identifier = context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                r#type: Some(IdentifierType::Did),
                did: Some(did),
                is_remote: Some(true),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context
        .api
        .identifiers
        .resolve_trust_entries(&[identifier.id], None, None)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let body = resp.json_value().await;
    assert_eq!(body.as_array().unwrap().len(), 1);
    assert_eq!(body[0]["identifier"]["id"], identifier.id.to_string());
    // DID identifiers should not be sent for resolution, so trustEntries should be empty
    assert!(body[0]["trustEntries"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn test_resolve_trust_entries_key_identifier() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let key = context
        .db
        .keys
        .create(&organisation, Default::default())
        .await;
    let identifier = context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                r#type: Some(IdentifierType::Key),
                key: Some(key),
                is_remote: Some(true),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context
        .api
        .identifiers
        .resolve_trust_entries(&[identifier.id], None, None)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let body = resp.json_value().await;
    assert_eq!(body.as_array().unwrap().len(), 1);
    assert_eq!(body[0]["identifier"]["id"], identifier.id.to_string());
    // Key identifiers should not be sent for resolution, so trustEntries should be empty
    assert!(body[0]["trustEntries"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn test_resolve_trust_entries_non_remote_identifier() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let identifier = context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                r#type: Some(IdentifierType::Certificate),
                is_remote: Some(false),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context
        .api
        .identifiers
        .resolve_trust_entries(&[identifier.id], None, None)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let body = resp.json_value().await;
    assert_eq!(body.as_array().unwrap().len(), 1);
    assert_eq!(body[0]["identifier"]["id"], identifier.id.to_string());
    // Non-remote identifiers should not be sent for resolution, so trustEntries should be empty
    assert!(body[0]["trustEntries"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn test_resolve_trust_entries_resolution_fails() {
    // GIVEN
    let additional_config = r#"
trustListSubscriber:
  ETSI-LOTE:
    type: ETSI_LOTE
    display:
      translationId: ETSI LoTE
    enabled: true
    params:
      public:
        accepts: application/jwt
        leewaySeconds: 0
    "#;
    let context = TestContext::new(Some(additional_config.to_string())).await;
    let organisation = context.db.organisations.create().await;
    let fingerprint = "test-fingerprint";

    // 1. Mock trust list reference
    let mock_server = MockServer::start().await;
    mock_server
        .register(Mock::given(method("GET")).respond_with(ResponseTemplate::new(404)))
        .await;

    // 2. Setup Identifier with certificate
    let identifier = context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                r#type: Some(IdentifierType::Certificate),
                is_remote: Some(true),
                ..Default::default()
            },
        )
        .await;

    context
        .db
        .certificates
        .create(
            identifier.id,
            organisation.clone(),
            TestingCertificateParams {
                fingerprint: Some(fingerprint.to_string()),
                state: Some(CertificateState::Active),
                ..Default::default()
            },
        )
        .await;

    // 3. Setup trust collection and subscription
    let reference_uri = mock_server.uri();
    let subscriber_id = TrustListSubscriberId::from("ETSI-LOTE");
    let tc = context
        .db
        .trust_collections
        .create(
            organisation.clone(),
            TestTrustCollectionParams {
                name: Some("Trust Collection".to_string()),
                ..Default::default()
            },
        )
        .await;

    context
        .db
        .trust_list_subscriptions
        .create(
            "Trust list subscription",
            Some(TrustListRoleEnum::Issuer),
            subscriber_id.clone(),
            &reference_uri,
            TrustListSubscriptionState::Active,
            tc.id,
        )
        .await;

    // WHEN
    let resp = context
        .api
        .identifiers
        .resolve_trust_entries(&[identifier.id], None, None)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let body = resp.json_value().await;
    assert_eq!(body.as_array().unwrap().len(), 1);
    assert_eq!(body[0]["identifier"]["id"], identifier.id.to_string());

    let trust_entries = body[0]["trustEntries"].as_array().unwrap();
    assert_eq!(trust_entries.len(), 0);
}
