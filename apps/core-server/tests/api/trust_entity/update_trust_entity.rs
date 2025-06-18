use core_server::endpoint::ssi::dto::{
    PatchTrustEntityActionRestDTO, PatchTrustEntityRequestRestDTO,
};
use one_core::model::history::{HistoryAction, HistoryEntityType};
use one_core::model::trust_entity::{TrustEntityRole, TrustEntityState, TrustEntityType};
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
async fn test_patch_trust_entity_ca() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let anchor = context
        .db
        .trust_anchors
        .create(TestingTrustAnchorParams::default())
        .await;

    let old_certificate = "-----BEGIN CERTIFICATE-----
MIIBJjCB2aADAgECAhRzWkNCwN3ySyHodhYOzXij/kB1XDAFBgMrZXAwITEfMB0G
A1UEAwwWKi5kZXYucHJvY2l2aXMtb25lLmNvbTAgFw0yNTA2MTcwODUyNTdaGA80
NzYzMDUxNDA4NTI1N1owITEfMB0GA1UEAwwWKi5kZXYucHJvY2l2aXMtb25lLmNv
bTAqMAUGAytlcAMhAAz4HUs33yQ+dRBOD/Ib0cXMLLlQG325/+l6MxW5+Bk/oyEw
HzAdBgNVHQ4EFgQUbJ2IBqjaP9GK2qbe/YHc3NufIW0wBQYDK2VwA0EAsAaCzr02
rpezgIUbslWYL837hwBg08vTFJjBsY0O/D6QTozuYYCSUooMc2izJqcJ9Ga76LS3
JupK8gddPJ2WCw==
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
            "CN=*.dev.procivis-one.com".to_string().into(),
            Some(old_certificate.to_string()),
            Some(organisation),
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
MIIBJjCB2aADAgECAhRzWkNCwN3ySyHodhYOzXij/kB1XDAFBgMrZXAwITEfMB0G
A1UEAwwWKi5kZXYucHJvY2l2aXMtb25lLmNvbTAgFw0yNTA2MTcwODUyNTdaGA80
NzYzMDUxNDA4NTI1N1owITEfMB0GA1UEAwwWKi5kZXYucHJvY2l2aXMtb25lLmNv
bTAqMAUGAytlcAMhAAz4HUs33yQ+dRBOD/Ib0cXMLLlQG325/+l6MxW5+Bk/oyEw
HzAdBgNVHQ4EFgQUbJ2IBqjaP9GK2qbe/YHc3NufIW0wBQYDK2VwA0EAsAaCzr02
rpezgIUbslWYL837hwBg08vTFJjBsY0O/D6QTozuYYCSUooMc2izJqcJ9Ga76LS3
JupK8gddPJ2WCw==
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
    assert_eq!("BR_0231", resp.error_code().await);
}
