use one_core::model::history::HistoryMetadata;
use one_core::model::wallet_unit::WalletUnitStatus;
use one_core::provider::key_algorithm::KeyAlgorithm;
use one_core::provider::key_algorithm::ecdsa::Ecdsa;
use one_crypto::Hasher;
use one_crypto::hasher::sha256::SHA256;
use similar_asserts::assert_eq;
use uuid::Uuid;

use crate::api_wallet_unit_tests::create_wallet_unit_attestation;
use crate::utils::api_clients::wallet_units::ListFilters;
use crate::utils::context::TestContext;
use crate::utils::db_clients::histories::TestingHistoryParams;
use crate::utils::db_clients::wallet_units::TestWalletUnit;

#[tokio::test]
async fn test_list_wallet_unit_success() {
    // GIVEN
    let (context, org) = TestContext::new_with_organisation(None).await;

    for i in 1..15 {
        let holder_key_pair = Ecdsa.generate_key().unwrap();
        let holder_public_jwk = holder_key_pair.key.public_key_as_jwk().unwrap();
        context
            .db
            .wallet_units
            .create(
                org.clone(),
                TestWalletUnit {
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
        .wallet_units
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
    assert!(values[0]["walletProviderType"].is_string());
    assert!(values[0]["walletProviderName"].is_string());
    assert!(values[0]["publicKey"].is_string());
}

#[tokio::test]
async fn test_list_wallet_unit_revoked_success() {
    // GIVEN
    let (context, org) = TestContext::new_with_organisation(None).await;

    for i in 1..10 {
        context
            .db
            .wallet_units
            .create(
                org.clone(),
                TestWalletUnit {
                    name: Some(format!("wallet_{i}")),
                    ..Default::default()
                },
            )
            .await;
    }

    for _i in 10..15 {
        context
            .db
            .wallet_units
            .create(
                org.clone(),
                TestWalletUnit {
                    status: Some(WalletUnitStatus::Revoked),
                    ..Default::default()
                },
            )
            .await;
    }

    // WHEN
    let resp = context
        .api
        .wallet_units
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
async fn test_list_wallet_unit_by_attestation_success() {
    // GIVEN
    const TEST_ELEMENTS: usize = 5;
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let mut attestations = Vec::with_capacity(TEST_ELEMENTS);

    for i in 0..TEST_ELEMENTS {
        let holder_key_pair = Ecdsa.generate_key().unwrap();
        let holder_public_jwk = holder_key_pair.key.public_key_as_jwk().unwrap();
        let attestation = create_wallet_unit_attestation(
            holder_key_pair.key.public_key_as_jwk().unwrap(),
            "http://127.0.0.1:12312".to_string(),
        )
        .await;
        let wallet_unit = context
            .db
            .wallet_units
            .create(
                organisation.clone(),
                TestWalletUnit {
                    name: Some(format!("wallet_{i}")),
                    public_key: Some(holder_public_jwk),
                    ..Default::default()
                },
            )
            .await;

        let attestation_hash = SHA256.hash_base64(attestation.as_bytes()).unwrap();
        context
            .db
            .histories
            .create_without_organisation(TestingHistoryParams {
                entity_id: Some(wallet_unit.id.into()),
                entity_type: Some(one_core::model::history::HistoryEntityType::WalletUnit),
                action: Some(one_core::model::history::HistoryAction::Updated),
                metadata: Some(HistoryMetadata::WalletUnitJWT(attestation_hash)),
                ..Default::default()
            })
            .await;

        attestations.push((wallet_unit.id, attestation));
    }

    let idx = rand::random::<usize>() % TEST_ELEMENTS;
    let (wallet_unit_id, attestation) = attestations[idx].clone();

    // WHEN
    let resp = context
        .api
        .wallet_units
        .list(ListFilters {
            organisation_id: organisation.id,
            attestation: Some(attestation),
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
    assert!(values[0]["walletProviderType"].is_string());
    assert!(values[0]["walletProviderName"].is_string());
    assert!(values[0]["publicKey"].is_string());
}

#[tokio::test]
async fn test_list_wallet_unit_empty_success() {
    // GIVEN
    let context = TestContext::new(None).await;

    // WHEN
    let resp = context
        .api
        .wallet_units
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
