use one_core::model::history::HistoryMetadata;
use one_core::model::instance::InstanceStatus;
use one_core::model::managed_instance_attestation::ManagedInstanceAttestation;
use one_core::model::wallet_attestation::AttestationType;
use one_core::provider::key_algorithm::KeyAlgorithm;
use one_core::provider::key_algorithm::ecdsa::Ecdsa;
use one_crypto::Hasher;
use one_crypto::hasher::sha256::SHA256;
use similar_asserts::assert_eq;
use time::Duration;
use uuid::Uuid;

use crate::api_wallet_unit_tests::create_wallet_instance_attestation;
use crate::utils::api_clients::managed_instances::ListFilters;
use crate::utils::context::TestContext;
use crate::utils::db_clients::histories::TestingHistoryParams;
use crate::utils::db_clients::managed_instances::TestWalletInstance;

#[tokio::test]
async fn test_list_wallet_instance_success() {
    // GIVEN
    let (context, org) = TestContext::new_with_organisation(None).await;

    for i in 1..15 {
        let holder_key_pair = Ecdsa.generate_key().unwrap();
        let holder_public_jwk = holder_key_pair.key.public_key_as_jwk().unwrap();
        context
            .db
            .managed_instances
            .create(
                org.clone(),
                TestWalletInstance {
                    name: Some(format!("wallet_{i}")),
                    public_key: Some(holder_public_jwk),
                    ..Default::default()
                },
            )
            .await;
    }

    // WHEN
    let resp = context
        .api
        .managed_instances
        .list(ListFilters::new(org.id))
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    assert_eq!(resp["totalPages"], 1);
    assert_eq!(resp["totalItems"], 14);
    let values = resp["values"].as_array().unwrap();
    assert_eq!(values.len(), 14);
    assert!(values[0]["name"].is_string());
    assert!(values[0]["id"].is_string());
    assert!(values[0]["createdDate"].is_string());
    assert!(values[0]["lastModified"].is_string());
    assert!(values[0]["lastIssuance"].is_string());
    assert!(values[0]["os"].is_string());
    assert!(values[0]["status"].is_string());
    assert!(values[0]["providerType"].is_string());
    assert!(values[0]["providerName"].is_string());
    assert_eq!(values[0]["role"], "WALLET");
    assert!(values[0]["walletProviderType"].is_null());
    assert!(values[0]["walletProviderName"].is_null());
    assert!(values[0]["authenticationKeyJwk"].is_object()); // JWK
}

#[tokio::test]
async fn test_list_wallet_instance_revoked_success() {
    // GIVEN
    let (context, org) = TestContext::new_with_organisation(None).await;

    for i in 1..10 {
        context
            .db
            .managed_instances
            .create(
                org.clone(),
                TestWalletInstance {
                    name: Some(format!("wallet_{i}")),
                    ..Default::default()
                },
            )
            .await;
    }

    for _i in 10..15 {
        context
            .db
            .managed_instances
            .create(
                org.clone(),
                TestWalletInstance {
                    status: Some(InstanceStatus::Revoked),
                    ..Default::default()
                },
            )
            .await;
    }

    // WHEN
    let resp = context
        .api
        .managed_instances
        .list(ListFilters::new(org.id))
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    assert_eq!(resp["totalPages"], 1);
    assert_eq!(resp["totalItems"], 14);
    let values = resp["values"].as_array().unwrap();
    assert_eq!(values.len(), 14);

    // Check that we have both active and revoked wallet units
    let statuses: Vec<&str> = values
        .iter()
        .map(|v| v["status"].as_str().unwrap())
        .collect();
    assert!(statuses.contains(&"ACTIVE"));
    assert!(statuses.contains(&"REVOKED"));
}

#[tokio::test]
async fn test_list_wallet_instance_by_attestation_success() {
    // GIVEN
    const TEST_ELEMENTS: u32 = 5;
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let mut attestations = Vec::with_capacity(TEST_ELEMENTS as usize);

    for i in 0..TEST_ELEMENTS {
        let holder_key_pair = Ecdsa.generate_key().unwrap();
        let holder_public_jwk = holder_key_pair.key.public_key_as_jwk().unwrap();
        let attestation = create_wallet_instance_attestation(
            holder_key_pair.key.public_key_as_jwk().unwrap(),
            "http://127.0.0.1:12312".to_string(),
        )
        .await;
        let attestation_hash = SHA256.hash_base64(attestation.as_bytes()).unwrap();

        let wallet_unit_id = Uuid::new_v4().into();
        let attestation_id = Uuid::new_v4().into();
        let wallet_unit = context
            .db
            .managed_instances
            .create(
                organisation.clone(),
                TestWalletInstance {
                    id: Some(wallet_unit_id),
                    name: Some(format!("wallet_{i}")),
                    public_key: Some(holder_public_jwk),
                    attestations: Some(vec![ManagedInstanceAttestation {
                        id: attestation_id,
                        instance_id: wallet_unit_id,
                        created_date: one_core::clock::now_utc(),
                        last_modified: one_core::clock::now_utc(),
                        expiration_date: one_core::clock::now_utc() + Duration::days(1),
                        r#type: AttestationType::KeyAttestation,
                        attestation_content_hash: Some(attestation_hash),
                        revocation: None,
                    }]),
                    ..Default::default()
                },
            )
            .await;

        context
            .db
            .histories
            .create(
                &organisation,
                TestingHistoryParams {
                    entity_id: Some(wallet_unit.id.into()),
                    entity_type: Some(one_core::model::history::HistoryEntityType::ManagedInstance),
                    action: Some(one_core::model::history::HistoryAction::KaCreated),
                    metadata: Some(HistoryMetadata::ManagedInstanceAttestation(attestation_id)),
                    ..Default::default()
                },
            )
            .await;

        attestations.push((wallet_unit.id, attestation));
    }

    let idx = rand::random::<u32>() % TEST_ELEMENTS;
    let (wallet_unit_id, attestation) = attestations[idx as usize].clone();

    // WHEN
    let resp = context
        .api
        .managed_instances
        .list(ListFilters {
            organisation_id: organisation.id,
            attestation: Some(attestation),
            ..ListFilters::new(organisation.id)
        })
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    assert_eq!(resp["totalPages"], 1);
    assert_eq!(resp["totalItems"], 1);
    let values = resp["values"].as_array().unwrap();
    assert_eq!(values.len(), 1);
    assert!(values[0]["name"].is_string());
    assert!(values[0]["id"] == wallet_unit_id.to_string());
    assert!(values[0]["createdDate"].is_string());
    assert!(values[0]["lastModified"].is_string());
    assert!(values[0]["lastIssuance"].is_string());
    assert!(values[0]["os"].is_string());
    assert!(values[0]["status"].is_string());
    assert!(values[0]["providerType"].is_string());
    assert!(values[0]["providerName"].is_string());
    assert_eq!(values[0]["role"], "WALLET");
    assert!(values[0]["walletProviderType"].is_null());
    assert!(values[0]["walletProviderName"].is_null());
    assert!(values[0]["authenticationKeyJwk"].is_object()); // JWK
}

#[tokio::test]
async fn test_list_wallet_instance_empty_success() {
    // GIVEN
    let context = TestContext::new(None).await;

    // WHEN
    let resp = context
        .api
        .managed_instances
        .list(ListFilters::new(Uuid::new_v4().into()))
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    assert_eq!(resp["totalPages"], 0);
    assert_eq!(resp["totalItems"], 0);
    let values = resp["values"].as_array().unwrap();
    assert_eq!(values.len(), 0);
}

#[tokio::test]
async fn test_list_wallet_instance_user_sub_in_response() {
    // GIVEN
    let (context, org) = TestContext::new_with_organisation(None).await;

    context
        .db
        .managed_instances
        .create(
            org.clone(),
            TestWalletInstance {
                name: Some("wallet_with_sub".to_string()),
                user_sub: Some("sub-alice".to_string()),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context
        .api
        .managed_instances
        .list(ListFilters::new(org.id))
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    let values = resp["values"].as_array().unwrap();
    assert_eq!(values.len(), 1);
    assert_eq!(values[0]["userSub"], "sub-alice");
}

#[tokio::test]
async fn test_list_wallet_instance_filter_by_user_sub() {
    // GIVEN
    let (context, org) = TestContext::new_with_organisation(None).await;

    context
        .db
        .managed_instances
        .create(
            org.clone(),
            TestWalletInstance {
                name: Some("wallet_alice".to_string()),
                user_sub: Some("sub-alice".to_string()),
                ..Default::default()
            },
        )
        .await;
    context
        .db
        .managed_instances
        .create(
            org.clone(),
            TestWalletInstance {
                name: Some("wallet_bob".to_string()),
                user_sub: Some("sub-bob".to_string()),
                ..Default::default()
            },
        )
        .await;

    // WHEN — filter by exact user_sub
    let resp = context
        .api
        .managed_instances
        .list(ListFilters {
            organisation_id: org.id,
            user_sub: Some("sub-alice".to_string()),
            ..ListFilters::new(org.id)
        })
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    assert_eq!(resp["totalItems"], 1);
    let values = resp["values"].as_array().unwrap();
    assert_eq!(values[0]["userSub"], "sub-alice");
}

#[tokio::test]
async fn test_list_wallet_instance_filter_by_user_sub_prefix() {
    // GIVEN
    let (context, org) = TestContext::new_with_organisation(None).await;

    for name in ["alice", "adam", "bob"] {
        context
            .db
            .managed_instances
            .create(
                org.clone(),
                TestWalletInstance {
                    name: Some(name.to_string()),
                    user_sub: Some(format!("sub-{name}")),
                    ..Default::default()
                },
            )
            .await;
    }

    // WHEN — filter by prefix "sub-a" should match alice and adam
    let resp = context
        .api
        .managed_instances
        .list(ListFilters {
            organisation_id: org.id,
            user_sub: Some("sub-a".to_string()),
            ..ListFilters::new(org.id)
        })
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    assert_eq!(resp["totalItems"], 2);
}

#[tokio::test]
async fn test_list_wallet_instance_org_success() {
    // GIVEN
    let (context, org) = TestContext::new_with_organisation(None).await;

    let holder_key_pair = Ecdsa.generate_key().unwrap();
    let holder_public_jwk = holder_key_pair.key.public_key_as_jwk().unwrap();
    context
        .db
        .managed_instances
        .create(
            org.clone(),
            TestWalletInstance {
                name: Some("wallet".to_string()),
                public_key: Some(holder_public_jwk),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context
        .api
        .managed_instances
        .list(ListFilters::new(Uuid::new_v4().into())) // different org
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    assert_eq!(resp["totalPages"], 0);
    assert_eq!(resp["totalItems"], 0);
    let values = resp["values"].as_array().unwrap();
    assert_eq!(values.len(), 0);
}
