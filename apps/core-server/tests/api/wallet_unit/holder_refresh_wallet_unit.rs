use one_core::model::wallet_unit::WalletUnitStatus;
use one_core::provider::key_algorithm::KeyAlgorithm;
use one_core::provider::key_algorithm::ecdsa::Ecdsa;
use one_crypto::encryption::encrypt_data;
use secrecy::SecretSlice;
use serde_json::json;
use shared_types::WalletUnitId;
use similar_asserts::assert_eq;
use uuid::Uuid;
use wiremock::http::Method;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::api_wallet_unit_tests::create_wallet_unit_attestation;
use crate::fixtures::TestingKeyParams;
use crate::utils::api_clients::wallet_units::TestHolderRefreshRequest;
use crate::utils::context::TestContext;
use crate::utils::db_clients::wallet_unit_attestations::TestWalletUnitAttestation;

#[tokio::test]
async fn holder_refresh_wallet_unit_successfully() {
    // given
    let (context, org) = TestContext::new_with_organisation(None).await;

    let mock_server = MockServer::builder().start().await;

    let holder_key_pair = Ecdsa.generate_key().unwrap();
    let attestation = create_wallet_unit_attestation(
        holder_key_pair.key.public_key_as_jwk().unwrap(),
        mock_server.uri(),
    )
    .await;

    let existing_wallet_unit_id: WalletUnitId = Uuid::new_v4().into();

    Mock::given(method(Method::POST))
        .and(path(format!(
            "/ssi/wallet-unit/v1/{existing_wallet_unit_id}/refresh"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": Uuid::new_v4(),
            "attestation": attestation,
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let internal_storage_encryption_key = SecretSlice::from(
        hex::decode("93d9182795f0d1bec61329fc2d18c4b4c1b7e65e69e20ec30a2101a9875fff7e").unwrap(), // has to match config keyStorage.INTERNAL.params.private.encryption
    );
    let holder_private_key_reference =
        encrypt_data(&holder_key_pair.private, &internal_storage_encryption_key).unwrap();

    let holder_key = context
        .db
        .keys
        .create(
            &org,
            TestingKeyParams {
                key_type: Some("ECDSA".to_string()),
                storage_type: Some("INTERNAL".to_string()),
                public_key: Some(holder_key_pair.public.clone()),
                key_reference: Some(holder_private_key_reference),
                ..Default::default()
            },
        )
        .await;

    context
        .db
        .wallet_unit_attestations
        .create(TestWalletUnitAttestation {
            wallet_unit_id: Some(existing_wallet_unit_id),
            wallet_provider_url: Some(mock_server.uri()),
            organisation: Some(org.clone()),
            key: Some(holder_key.clone()),
            ..Default::default()
        })
        .await;

    let wallet_unit_attestations = context
        .db
        .wallet_unit_attestations
        .get_by_organisation(&org.id)
        .await;
    assert!(wallet_unit_attestations.is_some());
    let history = context
        .db
        .histories
        .get_by_entity_id(&wallet_unit_attestations.unwrap().id.into())
        .await;
    assert!(history.values.is_empty());

    // when
    let resp = context
        .api
        .wallet_units
        .holder_refresh(TestHolderRefreshRequest {
            organization_id: Some(org.id),
        })
        .await;

    // then
    assert_eq!(resp.status(), 204);
    let wallet_unit_attestations = context
        .db
        .wallet_unit_attestations
        .get_by_organisation(&org.id)
        .await;
    assert!(wallet_unit_attestations.is_some());
    assert_ne!(
        wallet_unit_attestations.clone().unwrap().attestation,
        "some_invalid_attestation"
    );
    let history = context
        .db
        .histories
        .get_by_entity_id(&wallet_unit_attestations.unwrap().id.into())
        .await;
    assert!(!history.values.is_empty());
}

#[tokio::test]
async fn holder_refresh_wallet_unit_failed_when_revoked() {
    // given
    let (context, org) = TestContext::new_with_organisation(None).await;

    let mock_server = MockServer::builder().start().await;

    let holder_key_pair = Ecdsa.generate_key().unwrap();
    let existing_wallet_unit_id: WalletUnitId = Uuid::new_v4().into();

    Mock::given(method(Method::POST))
        .and(path(format!(
            "/ssi/wallet-unit/v1/{existing_wallet_unit_id}/refresh"
        )))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "code": "BR_0261",
            "message": "Error message",
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let internal_storage_encryption_key = SecretSlice::from(
        hex::decode("93d9182795f0d1bec61329fc2d18c4b4c1b7e65e69e20ec30a2101a9875fff7e").unwrap(), // has to match config keyStorage.INTERNAL.params.private.encryption
    );
    let holder_private_key_reference =
        encrypt_data(&holder_key_pair.private, &internal_storage_encryption_key).unwrap();

    let holder_key = context
        .db
        .keys
        .create(
            &org,
            TestingKeyParams {
                key_type: Some("ECDSA".to_string()),
                storage_type: Some("INTERNAL".to_string()),
                public_key: Some(holder_key_pair.public.clone()),
                key_reference: Some(holder_private_key_reference),
                ..Default::default()
            },
        )
        .await;

    context
        .db
        .wallet_unit_attestations
        .create(TestWalletUnitAttestation {
            wallet_unit_id: Some(existing_wallet_unit_id),
            wallet_provider_url: Some(mock_server.uri()),
            organisation: Some(org.clone()),
            key: Some(holder_key.clone()),
            ..Default::default()
        })
        .await;

    let wallet_unit_attestations = context
        .db
        .wallet_unit_attestations
        .get_by_organisation(&org.id)
        .await;
    assert!(wallet_unit_attestations.is_some());
    let history = context
        .db
        .histories
        .get_by_entity_id(&wallet_unit_attestations.unwrap().id.into())
        .await;
    assert!(history.values.is_empty());

    // when
    let resp = context
        .api
        .wallet_units
        .holder_refresh(TestHolderRefreshRequest {
            organization_id: Some(org.id),
        })
        .await;

    // then
    assert_eq!(resp.status(), 500);
    let wallet_unit_attestations = context
        .db
        .wallet_unit_attestations
        .get_by_organisation(&org.id)
        .await;
    assert!(wallet_unit_attestations.is_some());
    let attestation = wallet_unit_attestations.clone().unwrap();
    assert_eq!(attestation.attestation, "some_invalid_attestation");
    assert_eq!(attestation.status, WalletUnitStatus::Revoked);
    let history = context
        .db
        .histories
        .get_by_entity_id(&wallet_unit_attestations.unwrap().id.into())
        .await;
    assert!(!history.values.is_empty());
}
