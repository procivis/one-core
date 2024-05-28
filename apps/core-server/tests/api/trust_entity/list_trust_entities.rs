use one_core::model::organisation::Organisation;
use one_core::model::trust_anchor::{TrustAnchor, TrustAnchorRole};
use one_core::model::trust_entity::{TrustEntity, TrustEntityRole};
use serde_json::Value;

use crate::utils::api_clients::trust_entity::ListFilters;
use crate::utils::context::TestContext;
use crate::utils::field_match::FieldHelpers;

#[tokio::test]
async fn test_list_trust_entities() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;
    let ta = context
        .db
        .trust_anchors
        .create(
            "name1",
            organisation.clone(),
            "SIMPLE_TRUST_LIST",
            TrustAnchorRole::Publisher,
        )
        .await;

    let ta2 = context
        .db
        .trust_anchors
        .create(
            "name2",
            organisation.clone(),
            "SIMPLE_TRUST_LIST",
            TrustAnchorRole::Publisher,
        )
        .await;

    let entity1 = context
        .db
        .trust_entities
        .create("e1id", "e1", TrustEntityRole::Issuer, ta.clone())
        .await;

    let entity2 = context
        .db
        .trust_entities
        .create("e2id", "e2", TrustEntityRole::Issuer, ta2.clone())
        .await;

    // WHEN
    let resp = context
        .api
        .trust_entities
        .list(
            0,
            ListFilters {
                organisation_id: organisation.id,
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

    compare_entity(entity, &entity1, &organisation, &ta);

    let entity = values
        .iter()
        .find(|entity| entity["id"].as_str() == Some(&entity2.id.to_string()))
        .unwrap();

    compare_entity(entity, &entity2, &organisation, &ta2);
}

#[tokio::test]
async fn test_list_trust_entities_filter_trust_anchor() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;
    let ta = context
        .db
        .trust_anchors
        .create(
            "name1",
            organisation.clone(),
            "SIMPLE_TRUST_LIST",
            TrustAnchorRole::Publisher,
        )
        .await;

    let ta2 = context
        .db
        .trust_anchors
        .create(
            "name2",
            organisation.clone(),
            "SIMPLE_TRUST_LIST",
            TrustAnchorRole::Publisher,
        )
        .await;

    let entity1 = context
        .db
        .trust_entities
        .create("e1id", "e1", TrustEntityRole::Issuer, ta.clone())
        .await;

    let entity2 = context
        .db
        .trust_entities
        .create("e2id", "e2", TrustEntityRole::Issuer, ta.clone())
        .await;

    let _ = context
        .db
        .trust_entities
        .create("e3id", "e3", TrustEntityRole::Issuer, ta2.clone())
        .await;

    // WHEN
    let resp = context
        .api
        .trust_entities
        .list(
            0,
            ListFilters {
                organisation_id: organisation.id,
                anchor_id: Some(ta.id),
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
    let (context, organisation) = TestContext::new_with_organisation().await;
    let ta = context
        .db
        .trust_anchors
        .create(
            "name1",
            organisation.clone(),
            "SIMPLE_TRUST_LIST",
            TrustAnchorRole::Publisher,
        )
        .await;

    let entity1 = context
        .db
        .trust_entities
        .create("e1id", "ent11", TrustEntityRole::Issuer, ta.clone())
        .await;

    let entity2 = context
        .db
        .trust_entities
        .create("e2id", "ent12", TrustEntityRole::Issuer, ta.clone())
        .await;

    let _ = context
        .db
        .trust_entities
        .create("e3id", "ent", TrustEntityRole::Issuer, ta.clone())
        .await;

    // WHEN
    let resp = context
        .api
        .trust_entities
        .list(
            0,
            ListFilters {
                organisation_id: organisation.id,
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

fn compare_entity(
    result: &Value,
    entity: &TrustEntity,
    organisation: &Organisation,
    trust_anchor: &TrustAnchor,
) {
    result["name"].assert_eq(&entity.name);
    result["entityId"].assert_eq(&entity.entity_id);
    result["logo"].assert_eq(entity.logo.as_ref().unwrap());
    result["website"].assert_eq(entity.website.as_ref().unwrap());
    result["termsUrl"].assert_eq(entity.terms_url.as_ref().unwrap());
    result["privacyUrl"].assert_eq(entity.privacy_url.as_ref().unwrap());
    result["organisationId"].assert_eq(&organisation.id.to_string());
    result["trustAnchorId"].assert_eq(&trust_anchor.id.to_string());
}
