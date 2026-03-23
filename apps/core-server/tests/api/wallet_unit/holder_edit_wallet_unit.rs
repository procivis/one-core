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
async fn test_edit_wallet_unit_holder_successfully() {
    // GIVEN
    let (context, org) = TestContext::new_with_organisation(None).await;

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
                wallet_provider_url: Some("https://wallet.provider".to_string()),
                provider_wallet_unit_id: Some(Uuid::new_v4().into()),
            },
        )
        .await;

    let mock_server = MockServer::start().await;

    let collection = context
        .db
        .trust_collections
        .create(
            org,
            TestTrustCollectionParams {
                remote_trust_collection_url: Some(
                    format!("{}/collection", mock_server.uri()).parse().unwrap(),
                ),
                ..Default::default()
            },
        )
        .await;

    Mock::given(method(Method::GET))
        .and(path("/collection"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "name": "collection",
            "trustLists": [{
                "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
                "name": "list-name",
                "reference": "reference",
                "role": "PID_PROVIDER",
                "type": "LOTE_SUBSCRIBER"
            }]
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    // WHEN
    let resp = context
        .api
        .holder_wallet_units
        .holder_wallet_unit_edit(&wallet_unit.id, &[collection.id])
        .await;

    // THEN
    assert_eq!(resp.status(), 204);

    let subscriptions = context
        .db
        .trust_list_subscriptions
        .list(Default::default())
        .await;

    assert_eq!(subscriptions.len(), 1);
    let subscription = &subscriptions[0];
    assert_eq!(subscription.name, "list-name");
    assert_eq!(subscription.trust_collection_id, collection.id);

    // WHEN
    let resp = context
        .api
        .holder_wallet_units
        .holder_wallet_unit_edit(&wallet_unit.id, &[])
        .await;

    // THEN
    assert_eq!(resp.status(), 204);
    let subscriptions = context
        .db
        .trust_list_subscriptions
        .list(Default::default())
        .await;
    assert_eq!(subscriptions.len(), 0);
}
