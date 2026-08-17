use one_core::model::instance::{InstanceRole, InstanceStatus, WalletProviderType};
use similar_asserts::assert_eq;
use uuid::Uuid;

use crate::fixtures::TestingKeyParams;
use crate::utils::context::TestContext;
use crate::utils::db_clients::holder_wallet_instance::TestHolderWalletInstanceParams;
use crate::utils::field_match::FieldHelpers;

#[tokio::test]
async fn test_get_organisation_success() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    // WHEN
    let resp = context.api.organisations.get(&organisation.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    resp["id"].assert_eq(&organisation.id);
    assert!(resp["createdDate"].is_string());
    assert!(resp["lastModified"].is_string());
    assert!(resp.get("parentOrganisation").is_none());
}

#[tokio::test]
async fn test_get_organisation_returns_parent_organisation() {
    // GIVEN
    let (context, parent) = TestContext::new_with_organisation(None).await;
    let child = context.db.organisations.create_with_parent(parent.id).await;

    // WHEN
    let resp = context.api.organisations.get(&child.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    resp["id"].assert_eq(&child.id);
    resp["parentOrganisation"].assert_eq(&parent.id);
}

#[tokio::test]
async fn test_get_organisation_returns_wallet_instance() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let now = one_core::clock::now_utc();
    let key = context
        .db
        .keys
        .create(
            &organisation,
            TestingKeyParams {
                id: Some(Uuid::new_v4().into()),
                created_date: Some(now),
                last_modified: Some(now),
                name: Some("auth-key".to_string()),
                key_type: Some("ECDSA".to_string()),
                storage_type: Some("INTERNAL".to_string()),
                public_key: Some(vec![0; 32]),
                key_reference: Some(vec![0; 32]),
            },
        )
        .await;
    let holder_wallet_instance = context
        .db
        .holder_wallet_units
        .create(
            organisation.clone(),
            Some(key.clone()),
            TestHolderWalletInstanceParams {
                status: Some(InstanceStatus::Active),
                provider_type: Some(WalletProviderType::ProcivisOne),
                provider_name: Some("PROCIVIS_ONE".to_string()),
                provider_url: Some("https://wallet.provider".to_string()),
                provider_wallet_unit_id: Some(Uuid::new_v4().into()),
                role: Some(InstanceRole::Wallet),
                user_nonce: None,
            },
        )
        .await;

    // WHEN
    let resp = context.api.organisations.get(&organisation.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    resp["id"].assert_eq(&organisation.id);

    let wallet_instance = resp["walletInstance"].as_object().unwrap();
    assert_eq!(wallet_instance["providerUrl"], "https://wallet.provider");
    assert_eq!(wallet_instance["id"], holder_wallet_instance.id.to_string());
    assert_eq!(wallet_instance["providerName"], "PROCIVIS_ONE");
    assert_eq!(wallet_instance["authenticationKeyType"], "ECDSA");

    let configuration = resp["configuration"].as_object().unwrap();
    assert_eq!(configuration["trustedRpRequired"], false);
    assert_eq!(configuration["trustedIssuerRequired"], false);
    assert_eq!(configuration["trustedWalletProviderRequired"], false);
    assert_eq!(configuration["enforceEcosystemAsIssuer"], false);
    assert_eq!(configuration["enforceEcosystemAsHolder"], false);
    assert_eq!(configuration["enforceEcosystemAsVerifier"], false);
}

#[tokio::test]
async fn test_get_organisation_without_wallet_instance_omits_field() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    // WHEN
    let resp = context.api.organisations.get(&organisation.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    resp["id"].assert_eq(&organisation.id);
    assert!(resp.get("walletInstance").is_none());
}

#[tokio::test]
async fn get_deactivated_organisation_success() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    // WHEN
    context.db.organisations.deactivate(&organisation.id).await;
    let resp = context.api.organisations.get(&organisation.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    resp["id"].assert_eq(&organisation.id);
    assert!(resp["createdDate"].is_string());
    assert!(resp["lastModified"].is_string());
    assert!(resp["deactivatedAt"].is_string());
}

#[tokio::test]
async fn test_get_organisation_with_verifier_instance_success() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let now = one_core::clock::now_utc();
    let key = context
        .db
        .keys
        .create(
            &organisation,
            TestingKeyParams {
                id: Some(Uuid::new_v4().into()),
                created_date: Some(now),
                last_modified: Some(now),
                name: Some("auth-key".to_string()),
                key_type: Some("ECDSA".to_string()),
                storage_type: Some("INTERNAL".to_string()),
                public_key: Some(vec![0; 32]),
                key_reference: Some(vec![0; 32]),
            },
        )
        .await;
    let verifier_instance = context
        .db
        .holder_wallet_units
        .create(
            organisation.clone(),
            Some(key),
            TestHolderWalletInstanceParams {
                role: Some(InstanceRole::Verifier),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context.api.organisations.get(&organisation.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    resp["id"].assert_eq(&organisation.id);
    assert!(resp["createdDate"].is_string());
    assert!(resp["lastModified"].is_string());
    let verifier_instance_resp = resp["verifierInstance"].as_object().unwrap();
    assert_eq!(
        verifier_instance_resp["id"],
        verifier_instance.id.to_string()
    );
    assert_eq!(verifier_instance_resp["providerName"], "PROCIVIS_ONE");
    assert_eq!(
        verifier_instance_resp["providerUrl"],
        "https://wallet.provider"
    );
    assert_eq!(verifier_instance_resp["authenticationKeyType"], "ECDSA");

    let configuration = resp["configuration"].as_object().unwrap();
    assert_eq!(configuration["trustedIssuerRequired"], false);
}
