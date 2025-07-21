use core_server::endpoint::ssi::dto::{
    PatchTrustEntityActionRestDTO, PatchTrustEntityRequestRestDTO,
};
use one_core::model::history::{HistoryAction, HistoryEntityType};
use one_core::model::trust_entity::{TrustEntityRole, TrustEntityState, TrustEntityType};
use similar_asserts::assert_eq;
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
            TrustEntityType::Did,
            did.did.into(),
            None,
            did.organisation,
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
                content: None,
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

#[tokio::test]
async fn test_update_trust_entity_removed_and_withdrawn_history_success() {
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
            TrustEntityState::Withdrawn,
            anchor,
            TrustEntityType::Did,
            did.did.into(),
            None,
            did.organisation,
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
                action: Some(PatchTrustEntityActionRestDTO::Remove),
                name: None,
                logo: None,
                website: None,
                terms_url: None,
                privacy_url: None,
                role: None,
                content: None,
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
    assert_eq!(HistoryAction::Removed, last.action);
    assert_eq!(HistoryEntityType::TrustEntity, last.entity_type);
}

#[tokio::test]
async fn test_patch_trust_entity_did() {
    // GIVEN
    let (context, _, did, ..) = TestContext::new_with_did(None).await;

    let anchor = context
        .db
        .trust_anchors
        .create(TestingTrustAnchorParams::default())
        .await;

    let entity = context
        .db
        .trust_entities
        .create(
            "trust-entity",
            TrustEntityRole::Both,
            TrustEntityState::Active,
            anchor,
            TrustEntityType::Did,
            did.did.into(),
            None,
            did.organisation,
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
                action: Some(PatchTrustEntityActionRestDTO::Remove),
                ..Default::default()
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 204);
    assert_eq!(
        context
            .db
            .trust_entities
            .get(entity.id)
            .await
            .unwrap()
            .state,
        TrustEntityState::Removed
    );

    let history_list = context
        .db
        .histories
        .get_by_entity_id(&entity.id.into())
        .await;
    assert_eq!(history_item_count + 1, history_list.total_items);

    let last = history_list.values.first().unwrap();
    assert_eq!(HistoryAction::Removed, last.action);
    assert_eq!(HistoryEntityType::TrustEntity, last.entity_type);
}

#[tokio::test]
async fn test_patch_trust_entity_duplicate_name() {
    // GIVEN
    let (context, _, did, ..) = TestContext::new_with_did(None).await;

    let anchor = context
        .db
        .trust_anchors
        .create(TestingTrustAnchorParams::default())
        .await;

    context
        .db
        .trust_entities
        .create(
            "trust-entity",
            TrustEntityRole::Both,
            TrustEntityState::Active,
            anchor.clone(),
            TrustEntityType::Did,
            did.did.clone().into(),
            None,
            did.organisation.clone(),
        )
        .await;

    let entity = context
        .db
        .trust_entities
        .create(
            "trust-entity",
            TrustEntityRole::Both,
            TrustEntityState::Withdrawn,
            anchor,
            TrustEntityType::Did,
            did.did.into(),
            None,
            did.organisation,
        )
        .await;

    // WHEN
    let resp = context
        .api
        .trust_entities
        .update(
            entity.id,
            PatchTrustEntityRequestRestDTO {
                action: Some(PatchTrustEntityActionRestDTO::Activate),
                ..Default::default()
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0120");
}

#[tokio::test]
async fn test_patch_name_trust_entity_did() {
    // GIVEN
    let (context, _, did, ..) = TestContext::new_with_did(None).await;

    let anchor = context
        .db
        .trust_anchors
        .create(TestingTrustAnchorParams::default())
        .await;

    let entity = context
        .db
        .trust_entities
        .create(
            "trust-entity",
            TrustEntityRole::Both,
            TrustEntityState::Active,
            anchor,
            TrustEntityType::Did,
            did.did.into(),
            None,
            did.organisation,
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
                name: Some("trust-entity-updated".to_string()),
                ..Default::default()
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 204);
    let trust_entity = context.db.trust_entities.get(entity.id).await.unwrap();
    assert_eq!(trust_entity.state, TrustEntityState::Active);
    assert_eq!(trust_entity.name, "trust-entity-updated");

    let history_list = context
        .db
        .histories
        .get_by_entity_id(&entity.id.into())
        .await;
    assert_eq!(history_item_count + 1, history_list.total_items);

    let last = history_list.values.first().unwrap();
    assert_eq!(HistoryAction::Updated, last.action);
    assert_eq!(HistoryEntityType::TrustEntity, last.entity_type);
}

#[tokio::test]
async fn test_patch_trust_entity_ca() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let anchor = context
        .db
        .trust_anchors
        .create(TestingTrustAnchorParams::default())
        .await;

    let old_certificate = "-----BEGIN CERTIFICATE-----
MIIBejCCASygAwIBAgIBATAFBgMrZXAwITEfMB0GA1UEAwwWKi5kZXYucHJvY2l2
aXMtb25lLmNvbTAeFw0yMzA4MTYxNjI5MTJaFw0zNTAyMTQxNjI5MTJaMCExHzAd
BgNVBAMMFiouZGV2LnByb2NpdmlzLW9uZS5jb20wKjAFBgMrZXADIQBKBEnJk+6L
yU8tcMSYIw8mvo06E2W4JVTSZRP1JavvX6OBiDCBhTAfBgNVHSMEGDAWgBRhIOt+
rsH0tbwmoV/wajKmLHX1+zAhBgNVHREEGjAYghYqLmRldi5wcm9jaXZpcy1vbmUu
Y29tMA8GA1UdDwEB/wQFAwMHBgAwHQYDVR0OBBYEFGEg636uwfS1vCahX/BqMqYs
dfX7MA8GA1UdEwEB/wQFMAMBAf8wBQYDK2VwA0EAMl/BKDftZH7zLrWi1+Dk3gMn
sX8udGN/3YhU5EntLHL9BVVxIdNYBYH/bLjhUiBGcOwndQo1M98ayauMAK2BAQ==
-----END CERTIFICATE-----
";

    let trust_entity = context
        .db
        .trust_entities
        .create(
            "trust-entity",
            TrustEntityRole::Both,
            TrustEntityState::Active,
            anchor,
            TrustEntityType::CertificateAuthority,
            "61:20:eb:7e:ae:c1:f4:b5:bc:26:a1:5f:f0:6a:32:a6:2c:75:f5:fb"
                .to_string()
                .into(),
            Some(old_certificate.to_string()),
            Some(organisation),
        )
        .await;

    let new_certificate = "-----BEGIN CERTIFICATE-----
MIIBejCCASygAwIBAgIBAjAFBgMrZXAwITEfMB0GA1UEAwwWKi5kZXYucHJvY2l2
aXMtb25lLmNvbTAeFw0yMzA4MTYxNjI5MzhaFw0zNTAyMTQxNjI5MzhaMCExHzAd
BgNVBAMMFiouZGV2LnByb2NpdmlzLW9uZS5jb20wKjAFBgMrZXADIQBKBEnJk+6L
yU8tcMSYIw8mvo06E2W4JVTSZRP1JavvX6OBiDCBhTAfBgNVHSMEGDAWgBRhIOt+
rsH0tbwmoV/wajKmLHX1+zAhBgNVHREEGjAYghYqLmRldi5wcm9jaXZpcy1vbmUu
Y29tMA8GA1UdDwEB/wQFAwMHBgAwHQYDVR0OBBYEFGEg636uwfS1vCahX/BqMqYs
dfX7MA8GA1UdEwEB/wQFMAMBAf8wBQYDK2VwA0EA52P8iAkH7ZAE5PDq/1c8CfMp
e+VBXOHS+dfr0v3s90sICgxV3E4r8gYsEv3EybBI1Z8MCfqJ+JzVXTTvai3OBg==
-----END CERTIFICATE-----
";

    let history_list = context
        .db
        .histories
        .get_by_entity_id(&trust_entity.id.into())
        .await;
    let history_item_count = history_list.total_items;

    // WHEN
    let resp = context
        .api
        .trust_entities
        .update(
            trust_entity.id,
            PatchTrustEntityRequestRestDTO {
                content: Some(new_certificate.to_string()),
                ..Default::default()
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 204);
    assert_eq!(
        context
            .db
            .trust_entities
            .get(trust_entity.id)
            .await
            .unwrap()
            .content,
        Some(new_certificate.to_string())
    );

    let history_list = context
        .db
        .histories
        .get_by_entity_id(&trust_entity.id.into())
        .await;
    assert_eq!(history_item_count + 1, history_list.total_items);

    let last = history_list.values.first().unwrap();
    assert_eq!(HistoryAction::Updated, last.action);
    assert_eq!(HistoryEntityType::TrustEntity, last.entity_type);
}

#[tokio::test]
async fn test_patch_trust_entity_remove_logo_with_empty_string() {
    // GIVEN
    let (context, _, did, ..) = TestContext::new_with_did(None).await;

    let anchor = context
        .db
        .trust_anchors
        .create(TestingTrustAnchorParams::default())
        .await;

    let entity = context
        .db
        .trust_entities
        .create(
            "trust-entity",
            TrustEntityRole::Both,
            TrustEntityState::Active,
            anchor,
            TrustEntityType::Did,
            did.did.into(),
            None,
            did.organisation,
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
                logo: Some(Some("".to_owned())),
                ..Default::default()
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 204);
    assert_eq!(
        context.db.trust_entities.get(entity.id).await.unwrap().logo,
        None
    );

    let history_list = context
        .db
        .histories
        .get_by_entity_id(&entity.id.into())
        .await;
    assert_eq!(history_item_count + 1, history_list.total_items);

    let last = history_list.values.first().unwrap();
    assert_eq!(HistoryAction::Updated, last.action);
    assert_eq!(HistoryEntityType::TrustEntity, last.entity_type);
}

#[tokio::test]
async fn test_patch_trust_entity_remove_logo_with_none() {
    // GIVEN
    let (context, _, did, ..) = TestContext::new_with_did(None).await;

    let anchor = context
        .db
        .trust_anchors
        .create(TestingTrustAnchorParams::default())
        .await;

    let entity = context
        .db
        .trust_entities
        .create(
            "trust-entity",
            TrustEntityRole::Both,
            TrustEntityState::Active,
            anchor,
            TrustEntityType::Did,
            did.did.into(),
            None,
            did.organisation,
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
                logo: Some(None),
                ..Default::default()
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 204);
    assert_eq!(
        context.db.trust_entities.get(entity.id).await.unwrap().logo,
        None
    );

    let history_list = context
        .db
        .histories
        .get_by_entity_id(&entity.id.into())
        .await;
    assert_eq!(history_item_count + 1, history_list.total_items);

    let last = history_list.values.first().unwrap();
    assert_eq!(HistoryAction::Updated, last.action);
    assert_eq!(HistoryEntityType::TrustEntity, last.entity_type);
}

#[tokio::test]
async fn test_fail_to_patch_trust_entity_with_did_type() {
    // GIVEN
    let (context, _, did, ..) = TestContext::new_with_did(None).await;

    let anchor = context
        .db
        .trust_anchors
        .create(TestingTrustAnchorParams::default())
        .await;

    let trust_entity = context
        .db
        .trust_entities
        .create(
            "trust-entity",
            TrustEntityRole::Both,
            TrustEntityState::Active,
            anchor,
            TrustEntityType::Did,
            did.did.into(),
            None,
            did.organisation,
        )
        .await;

    let new_certificate = "-----BEGIN CERTIFICATE-----
MIIBJjCB2aADAgECAhRRuHXSvqb79YtzP1X+T7/qXoScNzAFBgMrZXAwITEfMB0G
A1UEAwwWKi5kZXYucHJvY2l2aXMtb25lLmNvbTAgFw0yNTA2MTcwODUzMTRaGA8y
Mjk5MDQwMjA4NTMxNFowITEfMB0GA1UEAwwWKi5kZXYucHJvY2l2aXMtb25lLmNv
bTAqMAUGAytlcAMhAAz4HUs33yQ+dRBOD/Ib0cXMLLlQG325/+l6MxW5+Bk/oyEw
HzAdBgNVHQ4EFgQUbJ2IBqjaP9GK2qbe/YHc3NufIW0wBQYDK2VwA0EAwUd5OSgX
RBeqkrL90DIItpyca7H3LtR16K6yjKFT+lgYV2kkWbegrpQdKa1bvHWLCYh23sdN
dCxE50eAQeDCDQ==
-----END CERTIFICATE-----
";

    // WHEN
    let resp = context
        .api
        .trust_entities
        .update(
            trust_entity.id,
            PatchTrustEntityRequestRestDTO {
                content: Some(new_certificate.to_string()),
                ..Default::default()
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!("BR_0230", resp.error_code().await);
}

#[tokio::test]
async fn test_fail_to_patch_trust_entity_with_not_matching_entity_key() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let anchor = context
        .db
        .trust_anchors
        .create(TestingTrustAnchorParams::default())
        .await;

    let old_certificate = "-----BEGIN CERTIFICATE-----
MIIBejCCASygAwIBAgIBATAFBgMrZXAwITEfMB0GA1UEAwwWKi5kZXYucHJvY2l2
aXMtb25lLmNvbTAeFw0yMzA4MTYxNjI5MTJaFw0zNTAyMTQxNjI5MTJaMCExHzAd
BgNVBAMMFiouZGV2LnByb2NpdmlzLW9uZS5jb20wKjAFBgMrZXADIQBKBEnJk+6L
yU8tcMSYIw8mvo06E2W4JVTSZRP1JavvX6OBiDCBhTAfBgNVHSMEGDAWgBRhIOt+
rsH0tbwmoV/wajKmLHX1+zAhBgNVHREEGjAYghYqLmRldi5wcm9jaXZpcy1vbmUu
Y29tMA8GA1UdDwEB/wQFAwMHBgAwHQYDVR0OBBYEFGEg636uwfS1vCahX/BqMqYs
dfX7MA8GA1UdEwEB/wQFMAMBAf8wBQYDK2VwA0EAMl/BKDftZH7zLrWi1+Dk3gMn
sX8udGN/3YhU5EntLHL9BVVxIdNYBYH/bLjhUiBGcOwndQo1M98ayauMAK2BAQ==
-----END CERTIFICATE-----
";

    let trust_entity = context
        .db
        .trust_entities
        .create(
            "trust-entity",
            TrustEntityRole::Both,
            TrustEntityState::Active,
            anchor,
            TrustEntityType::CertificateAuthority,
            "some_other_entity_key".to_string().into(),
            Some(old_certificate.to_string()),
            Some(organisation),
        )
        .await;

    let new_certificate = "-----BEGIN CERTIFICATE-----
MIIBejCCASygAwIBAgIBAjAFBgMrZXAwITEfMB0GA1UEAwwWKi5kZXYucHJvY2l2
aXMtb25lLmNvbTAeFw0yMzA4MTYxNjI5MzhaFw0zNTAyMTQxNjI5MzhaMCExHzAd
BgNVBAMMFiouZGV2LnByb2NpdmlzLW9uZS5jb20wKjAFBgMrZXADIQBKBEnJk+6L
yU8tcMSYIw8mvo06E2W4JVTSZRP1JavvX6OBiDCBhTAfBgNVHSMEGDAWgBRhIOt+
rsH0tbwmoV/wajKmLHX1+zAhBgNVHREEGjAYghYqLmRldi5wcm9jaXZpcy1vbmUu
Y29tMA8GA1UdDwEB/wQFAwMHBgAwHQYDVR0OBBYEFGEg636uwfS1vCahX/BqMqYs
dfX7MA8GA1UdEwEB/wQFMAMBAf8wBQYDK2VwA0EA52P8iAkH7ZAE5PDq/1c8CfMp
e+VBXOHS+dfr0v3s90sICgxV3E4r8gYsEv3EybBI1Z8MCfqJ+JzVXTTvai3OBg==
-----END CERTIFICATE-----
";

    // WHEN
    let resp = context
        .api
        .trust_entities
        .update(
            trust_entity.id,
            PatchTrustEntityRequestRestDTO {
                content: Some(new_certificate.to_string()),
                ..Default::default()
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!("BR_0231", resp.error_code().await);
}
