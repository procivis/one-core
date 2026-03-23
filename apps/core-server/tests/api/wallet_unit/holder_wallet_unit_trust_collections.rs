use one_core::model::trust_list_role::TrustListRoleEnum;
use one_core::model::trust_list_subscription::TrustListSubscriptionState;
use one_core::model::wallet_unit::{WalletProviderType, WalletUnitStatus};
use serde_json::json;
use similar_asserts::assert_eq;
use uuid::Uuid;
use wiremock::http::Method;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::utils::context::TestContext;
use crate::utils::db_clients::holder_wallet_unit::TestHolderWalletUnit;
use crate::utils::db_clients::trust_collections::TestTrustCollectionParams;

#[tokio::test]
async fn test_holder_wallet_unit_trust_collections() {
    // GIVEN
    let (context, org) = TestContext::new_with_organisation(None).await;

    let mock_server = MockServer::start().await;
    let wallet_unit = context
        .db
        .holder_wallet_units
        .create(
            org.clone(),
            None,
            TestHolderWalletUnit {
                status: Some(WalletUnitStatus::Unattested),
                wallet_provider_type: Some(WalletProviderType::ProcivisOne),
                wallet_provider_name: Some("PROCIVIS_ONE".to_string()),
                wallet_provider_url: Some(mock_server.uri()),
                provider_wallet_unit_id: Some(Uuid::new_v4().into()),
            },
        )
        .await;

    let collection = context
        .db
        .trust_collections
        .create(
            org,
            TestTrustCollectionParams {
                name: Some("test-collection".to_string()),
                remote_trust_collection_url: Some("https://trust.collection".parse().unwrap()),
                ..Default::default()
            },
        )
        .await;

    context
        .db
        .trust_list_subscriptions
        .create(
            "subscr",
            TrustListRoleEnum::PidProvider,
            "type",
            "reference",
            TrustListSubscriptionState::Active,
            collection.id,
        )
        .await;

    Mock::given(method(Method::GET))
        .and(path("/ssi/wallet-provider/v1/PROCIVIS_ONE"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
          "name": "PROCIVIS_ONE",
          "walletUnitAttestation": {
            "appIntegrityCheckRequired": false,
            "enabled": true,
            "required": true
          },
          "featureFlags": {
            "trustEcosystemsEnabled": true
          },
          "trustCollections": [{
             "description": [{
                 "lang": "en",
                 "value": "desc"
             }],
             "displayName": [{
                 "lang": "en",
                 "value": "name"
             }],
             "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
             "logo": "logo",
             "name": "test-collection"
          }]
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    // WHEN
    let resp = context
        .api
        .holder_wallet_units
        .holder_get_wallet_unit_trust_collections(&wallet_unit.id)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);

    let resp_json = resp.json_value().await;
    let collections = resp_json["trustCollections"].as_array().unwrap();
    assert_eq!(collections.len(), 1);
    assert_eq!(
        collections[0],
        json!({
            "id": collection.id,
            "name": "test-collection",
            "selected": true,
            "description": [{
                "lang": "en",
                "value": "desc"
            }],
            "displayName": [{
                "lang": "en",
                "value": "name"
            }],
            "logo": "logo"
        })
    );
}
