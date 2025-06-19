use core_server::endpoint::trust_entity::dto::{TrustEntityRoleRest, TrustEntityTypeRest};
use one_core::model::trust_anchor::TrustAnchor;
use one_core::model::trust_entity::{
    TrustEntity, TrustEntityRole, TrustEntityState, TrustEntityType,
};
use serde_json::Value;

use crate::fixtures::TestingDidParams;
use crate::utils::api_clients::trust_entity::ListFilters;
use crate::utils::context::TestContext;
use crate::utils::db_clients::trust_anchors::TestingTrustAnchorParams;
use crate::utils::field_match::FieldHelpers;

#[tokio::test]
async fn test_list_trust_entities() {
    // GIVEN
    let (context, organisation, did, ..) = TestContext::new_with_did(None).await;
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
            TrustEntityType::Did,
            did.did.into(),
            None,
            did.organisation,
        )
        .await;

    let did2 = context
        .db
        .dids
        .create(Some(organisation.clone()), TestingDidParams::default())
        .await;
    let entity2 = context
        .db
        .trust_entities
        .create(
            "e2",
            TrustEntityRole::Issuer,
            TrustEntityState::Active,
            ta2.clone(),
            TrustEntityType::Did,
            did2.did.into(),
            None,
            did2.organisation,
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
                ..Default::default()
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
    let (context, organisation, did, ..) = TestContext::new_with_did(None).await;

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
            TrustEntityType::Did,
            did.did.into(),
            None,
            did.organisation,
        )
        .await;

    let did2 = context
        .db
        .dids
        .create(Some(organisation.clone()), TestingDidParams::default())
        .await;
    let entity2 = context
        .db
        .trust_entities
        .create(
            "e2",
            TrustEntityRole::Issuer,
            TrustEntityState::Active,
            ta.clone(),
            TrustEntityType::Did,
            did2.did.into(),
            None,
            did2.organisation,
        )
        .await;

    let did3 = context
        .db
        .dids
        .create(Some(organisation.clone()), TestingDidParams::default())
        .await;
    context
        .db
        .trust_entities
        .create(
            "e3",
            TrustEntityRole::Issuer,
            TrustEntityState::Active,
            ta2.clone(),
            TrustEntityType::Did,
            did3.did.into(),
            None,
            did3.organisation,
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
                ..Default::default()
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 200);

    let body = resp.json_value().await;
    assert_eq!(body["totalItems"], 2);
    let values = body["values"].as_array().unwrap();
    assert_eq!(values.len(), 2);

    assert!(values.iter().all(|entity| {
        [
            entity1.id.to_string().as_str(),
            entity2.id.to_string().as_str(),
        ]
        .contains(&entity["id"].as_str().unwrap())
    }));
}

#[tokio::test]
async fn test_list_trust_entities_find_by_name() {
    // GIVEN
    let (context, organisation, did, ..) = TestContext::new_with_did(None).await;
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
            TrustEntityType::Did,
            did.did.into(),
            None,
            did.organisation,
        )
        .await;

    let did2 = context
        .db
        .dids
        .create(Some(organisation.clone()), TestingDidParams::default())
        .await;
    let entity2 = context
        .db
        .trust_entities
        .create(
            "ent12",
            TrustEntityRole::Issuer,
            TrustEntityState::Active,
            ta.clone(),
            TrustEntityType::Did,
            did2.did.into(),
            None,
            did2.organisation,
        )
        .await;

    let did3 = context
        .db
        .dids
        .create(Some(organisation.clone()), TestingDidParams::default())
        .await;
    context
        .db
        .trust_entities
        .create(
            "ent",
            TrustEntityRole::Issuer,
            TrustEntityState::Active,
            ta.clone(),
            TrustEntityType::Did,
            did3.did.into(),
            None,
            did3.organisation,
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
                name: Some("ent1".to_string()),
                ..Default::default()
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 200);

    let body = resp.json_value().await;
    assert_eq!(body["totalItems"], 2);
    let values = body["values"].as_array().unwrap();
    assert_eq!(values.len(), 2);

    assert!(values.iter().all(|entity| {
        [
            entity1.id.to_string().as_str(),
            entity2.id.to_string().as_str(),
        ]
        .contains(&entity["id"].as_str().unwrap())
    }));
}

#[tokio::test]
async fn test_list_trust_entities_find_by_did_id() {
    // GIVEN
    let (context, organisation, did, ..) = TestContext::new_with_did(None).await;
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
            TrustEntityType::Did,
            did.did.into(),
            None,
            did.organisation,
        )
        .await;

    let did2 = context
        .db
        .dids
        .create(Some(organisation.clone()), TestingDidParams::default())
        .await;
    context
        .db
        .trust_entities
        .create(
            "ent12",
            TrustEntityRole::Issuer,
            TrustEntityState::Active,
            ta.clone(),
            TrustEntityType::Did,
            did2.did.into(),
            None,
            did2.organisation,
        )
        .await;

    let did3 = context
        .db
        .dids
        .create(Some(organisation.clone()), TestingDidParams::default())
        .await;
    context
        .db
        .trust_entities
        .create(
            "ent",
            TrustEntityRole::Issuer,
            TrustEntityState::Active,
            ta.clone(),
            TrustEntityType::Did,
            did3.did.into(),
            None,
            did3.organisation,
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
                did_id: Some(did.id),
                ..Default::default()
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 200);

    let body = resp.json_value().await;
    assert_eq!(body["totalItems"], 1);
    let values = body["values"].as_array().unwrap();
    assert_eq!(values.len(), 1);

    assert!(values.iter().all(|entity| {
        [entity1.id.to_string().as_str()].contains(&entity["id"].as_str().unwrap())
    }));
}

#[tokio::test]
async fn test_list_trust_entities_filter_type() {
    // GIVEN
    let (context, organisation, did, ..) = TestContext::new_with_did(None).await;

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
            TrustEntityType::Did,
            did.did.into(),
            None,
            did.organisation,
        )
        .await;

    let did2 = context
        .db
        .dids
        .create(Some(organisation.clone()), TestingDidParams::default())
        .await;
    let entity2 = context
        .db
        .trust_entities
        .create(
            "e2",
            TrustEntityRole::Issuer,
            TrustEntityState::Active,
            ta.clone(),
            TrustEntityType::Did,
            did2.did.into(),
            None,
            did2.organisation,
        )
        .await;

    let pem_certificate = "-----BEGIN CERTIFICATE-----
MIHkMIGXoAMCAQICFGplpJ84r+DSD8MnjFLdyhcQiGc8MAUGAytlcDAAMCAXDTI1
MDYxNjE1MDQxMloYDzQ3NjMwNTEzMTUwNDEyWjAAMCowBQYDK2VwAyEADPgdSzff
JD51EE4P8hvRxcwsuVAbfbn/6XozFbn4GT+jITAfMB0GA1UdDgQWBBRsnYgGqNo/
0Yrapt79gdzc258hbTAFBgMrZXADQQAGooxtr6luOPyLyhJLDTZMz75hzhbokc4Q
X2qJiGDrkN4Lr/85kRw7KHlsHq/w1aXLp0/Eg/c5aMur6qSWBjMD
-----END CERTIFICATE-----
";

    let entity3 = context
        .db
        .trust_entities
        .create(
            "e3",
            TrustEntityRole::Issuer,
            TrustEntityState::Active,
            ta2.clone(),
            TrustEntityType::CertificateAuthority,
            "CN=*.dev.procivis-one.com".to_string().into(),
            Some(pem_certificate.to_string()),
            Some(organisation.clone()),
        )
        .await;

    // WHEN
    let resp = context
        .api
        .trust_entities
        .list(
            0,
            ListFilters {
                r#type: Some(vec![TrustEntityTypeRest::Did]),
                organisation_id: Some(organisation.id),
                ..Default::default()
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 200);

    let body = resp.json_value().await;
    assert_eq!(body["totalItems"], 2);
    let values = body["values"].as_array().unwrap();
    assert_eq!(values.len(), 2);

    assert!(values.iter().all(|entity| {
        [
            entity1.id.to_string().as_str(),
            entity2.id.to_string().as_str(),
        ]
        .contains(&entity["id"].as_str().unwrap())
    }));

    // WHEN
    let resp = context
        .api
        .trust_entities
        .list(
            0,
            ListFilters {
                r#type: Some(vec![TrustEntityTypeRest::CertificateAuthority]),
                ..Default::default()
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 200);

    let body = resp.json_value().await;
    assert_eq!(body["totalItems"], 1);
    let values = body["values"].as_array().unwrap();
    assert_eq!(values.len(), 1);

    assert!(values.iter().all(|entity| {
        [entity3.id.to_string().as_str()].contains(&entity["id"].as_str().unwrap())
    }));
}

#[tokio::test]
async fn test_list_trust_entities_entity_key() {
    // GIVEN
    let (context, organisation, did, ..) = TestContext::new_with_did(None).await;

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
            TrustEntityType::Did,
            (&did.did).into(),
            None,
            did.organisation,
        )
        .await;

    let pem_certificate = "-----BEGIN CERTIFICATE-----
MIHkMIGXoAMCAQICFGplpJ84r+DSD8MnjFLdyhcQiGc8MAUGAytlcDAAMCAXDTI1
MDYxNjE1MDQxMloYDzQ3NjMwNTEzMTUwNDEyWjAAMCowBQYDK2VwAyEADPgdSzff
JD51EE4P8hvRxcwsuVAbfbn/6XozFbn4GT+jITAfMB0GA1UdDgQWBBRsnYgGqNo/
0Yrapt79gdzc258hbTAFBgMrZXADQQAGooxtr6luOPyLyhJLDTZMz75hzhbokc4Q
X2qJiGDrkN4Lr/85kRw7KHlsHq/w1aXLp0/Eg/c5aMur6qSWBjMD
-----END CERTIFICATE-----
";

    let entity2 = context
        .db
        .trust_entities
        .create(
            "e3",
            TrustEntityRole::Issuer,
            TrustEntityState::Active,
            ta2.clone(),
            TrustEntityType::CertificateAuthority,
            "CN=*.dev.procivis-one.com".to_string().into(),
            Some(pem_certificate.to_string()),
            Some(organisation),
        )
        .await;

    // WHEN
    let resp = context
        .api
        .trust_entities
        .list(
            0,
            ListFilters {
                entity_key: Some(did.did.to_string()),
                ..Default::default()
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 200);

    let body = resp.json_value().await;
    assert_eq!(body["totalItems"], 1);
    let values = body["values"].as_array().unwrap();
    assert_eq!(values.len(), 1);

    assert!(values.iter().all(|entity| {
        [entity1.id.to_string().as_str()].contains(&entity["id"].as_str().unwrap())
    }));

    // WHEN
    let resp = context
        .api
        .trust_entities
        .list(
            0,
            ListFilters {
                entity_key: Some("CN=*.dev.procivis-one.com".to_owned()),
                ..Default::default()
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 200);

    let body = resp.json_value().await;
    assert_eq!(body["totalItems"], 1);
    let values = body["values"].as_array().unwrap();
    assert_eq!(values.len(), 1);

    assert!(values.iter().all(|entity| {
        [entity2.id.to_string().as_str()].contains(&entity["id"].as_str().unwrap())
    }));
}

fn compare_entity(result: &Value, entity: &TrustEntity, trust_anchor: &TrustAnchor) {
    result["name"].assert_eq(&entity.name);
    result["logo"].assert_eq(entity.logo.as_ref().unwrap());
    result["website"].assert_eq(entity.website.as_ref().unwrap());
    result["termsUrl"].assert_eq(entity.terms_url.as_ref().unwrap());
    result["privacyUrl"].assert_eq(entity.privacy_url.as_ref().unwrap());
    result["trustAnchor"]["id"].assert_eq(&trust_anchor.id.to_string());
}
