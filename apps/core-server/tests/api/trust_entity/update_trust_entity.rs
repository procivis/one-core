use core_server::endpoint::ssi::dto::{
    PatchTrustEntityActionRestDTO, PatchTrustEntityRequestRestDTO,
};
use one_core::model::history::{HistoryAction, HistoryEntityType};
use one_core::model::trust_entity::{TrustEntityRole, TrustEntityState};
use uuid::Uuid;
use wiremock::MockServer;

use crate::utils::context::TestContext;
use crate::utils::db_clients::trust_anchors::TestingTrustAnchorParams;

#[tokio::test]
async fn test_update_trust_entity_action_withdraw_success() {
    // GIVEN
    let mock_server = MockServer::start().await;
    let (context, _, did, ..) = TestContext::new_with_did(None).await;

    let anchor = context
        .db
        .trust_anchors
        .create(TestingTrustAnchorParams {
            name: "name".to_string(),
            publisher_reference: format!("{}/ssi/trust/v1/{}", mock_server.uri(), Uuid::new_v4()),
            is_publisher: false,
            ..Default::default()
        })
        .await;

    let entity = context
        .db
        .trust_entities
        .create(
            "name",
            TrustEntityRole::Issuer,
            TrustEntityState::Active,
            anchor,
            did,
        )
        .await;

    let history_list = context
        .db
        .histories
        .get_by_entity_id(&entity.id.into())
        .await;
    let history_item_count = history_list.total_items;

    // WHEN
    let resp = context
        .api
        .trust_entities
        .update(
            entity.id,
            PatchTrustEntityRequestRestDTO {
                action: Some(PatchTrustEntityActionRestDTO::Withdraw),
                name: None,
                logo: None,
                website: None,
                terms_url: None,
                privacy_url: None,
                role: None,
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 204);

    let history_list = context
        .db
        .histories
        .get_by_entity_id(&entity.id.into())
        .await;
    assert_eq!(history_item_count + 1, history_list.total_items);

    let last = history_list.values.first().unwrap();
    assert_eq!(HistoryAction::Withdrawn, last.action);
    assert_eq!(HistoryEntityType::TrustEntity, last.entity_type);
}
