use core_server::endpoint::trust_entity::dto::TrustEntityRoleRest;
use one_core::model::trust_anchor::TrustAnchor;
use one_core::model::trust_entity::{TrustEntity, TrustEntityRole, TrustEntityState};
use serde_json::Value;

use crate::utils::api_clients::trust_entity::ListFilters;
use crate::utils::context::TestContext;
use crate::utils::db_clients::trust_anchors::TestingTrustAnchorParams;
use crate::utils::field_match::FieldHelpers;

#[tokio::test]
async fn test_list_trust_entities() {
    // GIVEN
    let (context, _, did, _) = TestContext::new_with_did(None).await;
    let ta = context
        .db
        .trust_anchors
        .create(TestingTrustAnchorParams {
            name: "name1".to_string(),
            ..Default::default()
        })
        .await;

    let ta2 = context
        .db
        .trust_anchors
        .create(TestingTrustAnchorParams {
            name: "name2".to_string(),
            ..Default::default()
        })
        .await;

    let entity1 = context
        .db
        .trust_entities
        .create(
            "e1",
            TrustEntityRole::Issuer,
            TrustEntityState::Active,
            ta.clone(),
            did.clone(),
        )
        .await;

    let entity2 = context
        .db
        .trust_entities
        .create(
            "e2",
            TrustEntityRole::Issuer,
            TrustEntityState::Active,
            ta2.clone(),
            did.clone(),
        )
        .await;

    // WHEN
    let resp = context
        .api
        .trust_entities
        .list(
            0,
            ListFilters {
                role: Some(TrustEntityRoleRest::Issuer),
                anchor_id: None,
                name: None,
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 200);

    let body = resp.json_value().await;
    assert_eq!(body["totalItems"], 2);
    let values = body["values"].as_array().unwrap();
    assert_eq!(values.len(), 2);

    let entity = values
        .iter()
        .find(|entity| entity["id"].as_str() == Some(&entity1.id.to_string()))
        .unwrap();

    compare_entity(entity, &entity1, &ta);

    let entity = values
        .iter()
        .find(|entity| entity["id"].as_str() == Some(&entity2.id.to_string()))
        .unwrap();

    compare_entity(entity, &entity2, &ta2);
}

#[tokio::test]
async fn test_list_trust_entities_filter_trust_anchor() {
    // GIVEN
    let (context, _, did, _) = TestContext::new_with_did(None).await;

    let ta = context
        .db
        .trust_anchors
        .create(TestingTrustAnchorParams {
            name: "name1".to_string(),
            ..Default::default()
        })
        .await;

    let ta2 = context
        .db
        .trust_anchors
        .create(TestingTrustAnchorParams {
            name: "name2".to_string(),
            ..Default::default()
        })
        .await;

    let entity1 = context
        .db
        .trust_entities
        .create(
            "e1",
            TrustEntityRole::Issuer,
            TrustEntityState::Active,
            ta.clone(),
            did.clone(),
        )
        .await;

    let entity2 = context
        .db
        .trust_entities
        .create(
            "e2",
            TrustEntityRole::Issuer,
            TrustEntityState::Active,
            ta.clone(),
            did.clone(),
        )
        .await;

    let _ = context
        .db
        .trust_entities
        .create(
            "e3",
            TrustEntityRole::Issuer,
            TrustEntityState::Active,
            ta2.clone(),
            did.clone(),
        )
        .await;

    // WHEN
    let resp = context
        .api
        .trust_entities
        .list(
            0,
            ListFilters {
                anchor_id: Some(ta.id),
                role: None,
                name: None,
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 200);

    let body = resp.json_value().await;
    assert_eq!(body["totalItems"], 2);
    let values = body["values"].as_array().unwrap();
    assert_eq!(values.len(), 2);

    assert!(values.iter().all(|entity| [
        entity1.id.to_string().as_str(),
        entity2.id.to_string().as_str()
    ]
    .contains(&entity["id"].as_str().unwrap())));
}

#[tokio::test]
async fn test_list_trust_entities_find_by_name() {
    // GIVEN
    let (context, _, did, _) = TestContext::new_with_did(None).await;
    let ta = context
        .db
        .trust_anchors
        .create(TestingTrustAnchorParams::default())
        .await;

    let entity1 = context
        .db
        .trust_entities
        .create(
            "ent11",
            TrustEntityRole::Issuer,
            TrustEntityState::Active,
            ta.clone(),
            did.clone(),
        )
        .await;

    let entity2 = context
        .db
        .trust_entities
        .create(
            "ent12",
            TrustEntityRole::Issuer,
            TrustEntityState::Active,
            ta.clone(),
            did.clone(),
        )
        .await;

    let _ = context
        .db
        .trust_entities
        .create(
            "ent",
            TrustEntityRole::Issuer,
            TrustEntityState::Active,
            ta.clone(),
            did.clone(),
        )
        .await;

    // WHEN
    let resp = context
        .api
        .trust_entities
        .list(
            0,
            ListFilters {
                role: Some(TrustEntityRoleRest::Issuer),
                anchor_id: None,
                name: Some("ent1".to_string()),
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 200);

    let body = resp.json_value().await;
    assert_eq!(body["totalItems"], 2);
    let values = body["values"].as_array().unwrap();
    assert_eq!(values.len(), 2);

    assert!(values.iter().all(|entity| [
        entity1.id.to_string().as_str(),
        entity2.id.to_string().as_str()
    ]
    .contains(&entity["id"].as_str().unwrap())));
}

fn compare_entity(result: &Value, entity: &TrustEntity, trust_anchor: &TrustAnchor) {
    result["name"].assert_eq(&entity.name);
    result["logo"].assert_eq(entity.logo.as_ref().unwrap());
    result["website"].assert_eq(entity.website.as_ref().unwrap());
    result["termsUrl"].assert_eq(entity.terms_url.as_ref().unwrap());
    result["privacyUrl"].assert_eq(entity.privacy_url.as_ref().unwrap());
    result["trustAnchor"]["id"].assert_eq(&trust_anchor.id.to_string());
}
