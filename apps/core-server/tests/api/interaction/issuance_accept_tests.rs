use serde_json::json;
use uuid::Uuid;

use one_core::model::{
    credential::CredentialStateEnum,
    credential_schema::WalletStorageTypeEnum,
    did::{DidType, KeyRole, RelatedKey},
};

use crate::{
    fixtures::{TestingCredentialParams, TestingDidParams},
    utils::{
        context::TestContext,
        db_clients::{credential_schemas::TestingCreateSchemaParams, keys::es256_testing_params},
    },
};

#[tokio::test]
async fn test_issuance_accept_procivis_temp() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;
    let did = context
        .db
        .dids
        .create(&organisation, Default::default())
        .await;
    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, "NONE", Default::default())
        .await;
    let interaction = context
        .db
        .interactions
        .create(None, &context.server_mock.uri(), "".as_bytes())
        .await;
    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Pending,
            &did,
            "PROCIVIS_TEMPORARY",
            TestingCredentialParams {
                interaction: Some(interaction.to_owned()),
                ..Default::default()
            },
        )
        .await;
    let key = context
        .db
        .keys
        .create(&organisation, es256_testing_params())
        .await;
    let holder_did = context
        .db
        .dids
        .create(
            &organisation,
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::Authentication,
                    key,
                }]),
                ..Default::default()
            },
        )
        .await;
    context
        .server_mock
        .ssi_submit(credential.id, holder_did.did)
        .await;

    // WHEN
    let resp = context
        .api
        .interactions
        .issuance_accept(interaction.id, holder_did.id, None)
        .await;

    // THEN
    assert_eq!(resp.status(), 204);

    let credential = context.db.credentials.get(&credential.id).await;
    assert_eq!(holder_did.id, credential.holder_did.unwrap().id);

    let states = credential.state.unwrap();
    assert_eq!(2, states.len());
    assert_eq!(CredentialStateEnum::Accepted, states[0].state);
}

#[tokio::test]
async fn test_issuance_accept_procivis_temp_with_key_id() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;
    let did = context
        .db
        .dids
        .create(&organisation, Default::default())
        .await;
    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, "NONE", Default::default())
        .await;
    let interaction = context
        .db
        .interactions
        .create(None, &context.server_mock.uri(), "".as_bytes())
        .await;
    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Pending,
            &did,
            "PROCIVIS_TEMPORARY",
            TestingCredentialParams {
                interaction: Some(interaction.to_owned()),
                ..Default::default()
            },
        )
        .await;
    let key = context
        .db
        .keys
        .create(&organisation, es256_testing_params())
        .await;
    let holder_did = context
        .db
        .dids
        .create(
            &organisation,
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::Authentication,
                    key: key.clone(),
                }]),
                ..Default::default()
            },
        )
        .await;
    context
        .server_mock
        .ssi_submit(credential.id, holder_did.did)
        .await;

    // WHEN
    let resp = context
        .api
        .interactions
        .issuance_accept(interaction.id, holder_did.id, Some(key.id))
        .await;

    // THEN
    assert_eq!(resp.status(), 204);

    let credential = context.db.credentials.get(&credential.id).await;
    assert_eq!(holder_did.id, credential.holder_did.unwrap().id);
    assert_eq!(key.id, credential.key.unwrap().id);

    let states = credential.state.unwrap();
    assert_eq!(2, states.len());
    assert_eq!(CredentialStateEnum::Accepted, states[0].state);
}

#[tokio::test]
async fn test_fail_issuance_accept_procivis_temp_unknown_did() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;
    let did = context
        .db
        .dids
        .create(&organisation, Default::default())
        .await;
    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, "NONE", Default::default())
        .await;
    let interaction = context
        .db
        .interactions
        .create(None, &context.server_mock.uri(), "".as_bytes())
        .await;
    context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Pending,
            &did,
            "PROCIVIS_TEMPORARY",
            TestingCredentialParams {
                interaction: Some(interaction.to_owned()),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context
        .api
        .interactions
        .issuance_accept(interaction.id, Uuid::new_v4(), None)
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    let body = resp.json_value().await;
    assert_eq!(body["code"], "BR_0024");
}

#[tokio::test]
async fn test_fail_issuance_accept_procivis_temp_unknown_key() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;
    let did = context
        .db
        .dids
        .create(&organisation, Default::default())
        .await;
    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, "NONE", Default::default())
        .await;
    let interaction = context
        .db
        .interactions
        .create(None, &context.server_mock.uri(), "".as_bytes())
        .await;
    context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Pending,
            &did,
            "PROCIVIS_TEMPORARY",
            TestingCredentialParams {
                interaction: Some(interaction.to_owned()),
                ..Default::default()
            },
        )
        .await;
    let key = context
        .db
        .keys
        .create(&organisation, es256_testing_params())
        .await;
    let holder_did = context
        .db
        .dids
        .create(
            &organisation,
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::Authentication,
                    key: key.clone(),
                }]),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context
        .api
        .interactions
        .issuance_accept(interaction.id, holder_did.id, Some(Uuid::new_v4().into()))
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    let body = resp.json_value().await;
    assert_eq!(body["code"], "BR_0037");
}

#[tokio::test]
async fn test_fail_issuance_accept_procivis_temp_wrong_key_role() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;
    let did = context
        .db
        .dids
        .create(&organisation, Default::default())
        .await;
    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, "NONE", Default::default())
        .await;
    let interaction = context
        .db
        .interactions
        .create(None, &context.server_mock.uri(), "".as_bytes())
        .await;
    context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Pending,
            &did,
            "PROCIVIS_TEMPORARY",
            TestingCredentialParams {
                interaction: Some(interaction.to_owned()),
                ..Default::default()
            },
        )
        .await;
    let key = context
        .db
        .keys
        .create(&organisation, es256_testing_params())
        .await;
    let holder_did = context
        .db
        .dids
        .create(
            &organisation,
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::AssertionMethod,
                    key: key.clone(),
                }]),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context
        .api
        .interactions
        .issuance_accept(interaction.id, holder_did.id, Some(key.id))
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    let body = resp.json_value().await;
    assert_eq!(body["code"], "BR_0096");
}

#[tokio::test]
async fn test_fail_issuance_accept_procivis_temp_no_key_with_auth_role() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;
    let did = context
        .db
        .dids
        .create(&organisation, Default::default())
        .await;
    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, "NONE", Default::default())
        .await;
    let interaction = context
        .db
        .interactions
        .create(None, &context.server_mock.uri(), "".as_bytes())
        .await;
    context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Pending,
            &did,
            "PROCIVIS_TEMPORARY",
            TestingCredentialParams {
                interaction: Some(interaction.to_owned()),
                ..Default::default()
            },
        )
        .await;
    let key = context
        .db
        .keys
        .create(&organisation, es256_testing_params())
        .await;
    let holder_did = context
        .db
        .dids
        .create(
            &organisation,
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::AssertionMethod,
                    key: key.clone(),
                }]),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context
        .api
        .interactions
        .issuance_accept(interaction.id, holder_did.id, None)
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    let body = resp.json_value().await;
    assert_eq!(body["code"], "BR_0096");
}

#[tokio::test]
async fn test_fail_issuance_accept_procivis_temp_wallet_storage_type_not_met() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;
    let did = context
        .db
        .dids
        .create(&organisation, Default::default())
        .await;
    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test",
            &organisation,
            "NONE",
            TestingCreateSchemaParams {
                wallet_storage_type: Some(WalletStorageTypeEnum::Hardware),
                ..Default::default()
            },
        )
        .await;
    let interaction = context
        .db
        .interactions
        .create(None, &context.server_mock.uri(), "".as_bytes())
        .await;
    context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Pending,
            &did,
            "PROCIVIS_TEMPORARY",
            TestingCredentialParams {
                interaction: Some(interaction.to_owned()),
                ..Default::default()
            },
        )
        .await;
    let key = context
        .db
        .keys
        .create(&organisation, es256_testing_params())
        .await;
    let holder_did = context
        .db
        .dids
        .create(
            &organisation,
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::Authentication,
                    key: key.clone(),
                }]),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context
        .api
        .interactions
        .issuance_accept(interaction.id, holder_did.id, Some(key.id))
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    let body = resp.json_value().await;
    assert_eq!(body["code"], "BR_0097");
}

#[tokio::test]
async fn test_issuance_accept_openid4vc() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;
    let issuer_did = context
        .db
        .dids
        .create(
            &organisation,
            TestingDidParams {
                did_type: Some(DidType::Remote),
                ..Default::default()
            },
        )
        .await;
    let key = context
        .db
        .keys
        .create(&organisation, es256_testing_params())
        .await;
    let holder_did = context
        .db
        .dids
        .create(
            &organisation,
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::Authentication,
                    key,
                }]),
                ..Default::default()
            },
        )
        .await;

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, "NONE", Default::default())
        .await;

    let interaction_data = serde_json::to_vec(&json!({
        "issuer_url": "http://127.0.0.1",
        "credential_endpoint": format!("{}/credential", context.server_mock.uri()),
        "access_token": "123",
        "access_token_expires_at": null,
    }))
    .unwrap();
    let interaction = context
        .db
        .interactions
        .create(None, &context.server_mock.uri(), &interaction_data)
        .await;

    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Pending,
            &issuer_did,
            "OPENID4VC",
            TestingCredentialParams {
                interaction: Some(interaction.to_owned()),
                ..Default::default()
            },
        )
        .await;

    context.server_mock.credential_endpoint().await;

    // WHEN
    let resp = context
        .api
        .interactions
        .issuance_accept(interaction.id, holder_did.id, None)
        .await;

    // THEN
    assert_eq!(resp.status(), 204);

    let credential = context.db.credentials.get(&credential.id).await;
    assert_eq!(holder_did.id, credential.holder_did.unwrap().id);

    let states = credential.state.unwrap();
    assert_eq!(2, states.len());
    assert_eq!(CredentialStateEnum::Accepted, states[0].state);
}

#[tokio::test]
async fn test_issuance_accept_openid4vc_with_key_id() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;
    let issuer_did = context
        .db
        .dids
        .create(
            &organisation,
            TestingDidParams {
                did_type: Some(DidType::Remote),
                ..Default::default()
            },
        )
        .await;
    let key = context
        .db
        .keys
        .create(&organisation, es256_testing_params())
        .await;
    let holder_did = context
        .db
        .dids
        .create(
            &organisation,
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::Authentication,
                    key: key.clone(),
                }]),
                ..Default::default()
            },
        )
        .await;

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, "NONE", Default::default())
        .await;

    let interaction_data = serde_json::to_vec(&json!({
        "issuer_url": "http://127.0.0.1",
        "credential_endpoint": format!("{}/credential", context.server_mock.uri()),
        "access_token": "123",
        "access_token_expires_at": null,
    }))
    .unwrap();
    let interaction = context
        .db
        .interactions
        .create(None, &context.server_mock.uri(), &interaction_data)
        .await;

    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Pending,
            &issuer_did,
            "OPENID4VC",
            TestingCredentialParams {
                interaction: Some(interaction.to_owned()),
                ..Default::default()
            },
        )
        .await;

    context.server_mock.credential_endpoint().await;

    // WHEN
    let resp = context
        .api
        .interactions
        .issuance_accept(interaction.id, holder_did.id, Some(key.id))
        .await;

    assert_eq!(resp.status(), 204);

    let credential = context.db.credentials.get(&credential.id).await;
    assert_eq!(holder_did.id, credential.holder_did.unwrap().id);
    assert_eq!(key.id, credential.key.unwrap().id);

    let states = credential.state.unwrap();
    assert_eq!(2, states.len());
    assert_eq!(CredentialStateEnum::Accepted, states[0].state);
}

#[tokio::test]
async fn test_fail_issuance_accept_openid4vc_unknown_did() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;
    let issuer_did = context
        .db
        .dids
        .create(
            &organisation,
            TestingDidParams {
                did_type: Some(DidType::Remote),
                ..Default::default()
            },
        )
        .await;

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, "NONE", Default::default())
        .await;

    let interaction_data = serde_json::to_vec(&json!({
        "issuer_url": "http://127.0.0.1",
        "credential_endpoint": format!("{}/credential", context.server_mock.uri()),
        "access_token": "123",
        "access_token_expires_at": null,
    }))
    .unwrap();
    let interaction = context
        .db
        .interactions
        .create(None, &context.server_mock.uri(), &interaction_data)
        .await;

    context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Pending,
            &issuer_did,
            "OPENID4VC",
            TestingCredentialParams {
                interaction: Some(interaction.to_owned()),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context
        .api
        .interactions
        .issuance_accept(interaction.id, Uuid::new_v4(), None)
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    let body = resp.json_value().await;
    assert_eq!(body["code"], "BR_0024");
}

#[tokio::test]
async fn test_fail_issuance_accept_openid4vc_unknown_key() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;
    let issuer_did = context
        .db
        .dids
        .create(
            &organisation,
            TestingDidParams {
                did_type: Some(DidType::Remote),
                ..Default::default()
            },
        )
        .await;
    let key = context
        .db
        .keys
        .create(&organisation, es256_testing_params())
        .await;
    let holder_did = context
        .db
        .dids
        .create(
            &organisation,
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::Authentication,
                    key,
                }]),
                ..Default::default()
            },
        )
        .await;

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, "NONE", Default::default())
        .await;

    let interaction_data = serde_json::to_vec(&json!({
        "issuer_url": "http://127.0.0.1",
        "credential_endpoint": format!("{}/credential", context.server_mock.uri()),
        "access_token": "123",
        "access_token_expires_at": null,
    }))
    .unwrap();
    let interaction = context
        .db
        .interactions
        .create(None, &context.server_mock.uri(), &interaction_data)
        .await;

    context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Pending,
            &issuer_did,
            "OPENID4VC",
            TestingCredentialParams {
                interaction: Some(interaction.to_owned()),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context
        .api
        .interactions
        .issuance_accept(interaction.id, holder_did.id, Some(Uuid::new_v4().into()))
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    let body = resp.json_value().await;
    assert_eq!(body["code"], "BR_0037");
}

#[tokio::test]
async fn test_fail_issuance_accept_openid4vc_wrong_key_role() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;
    let issuer_did = context
        .db
        .dids
        .create(
            &organisation,
            TestingDidParams {
                did_type: Some(DidType::Remote),
                ..Default::default()
            },
        )
        .await;
    let key = context
        .db
        .keys
        .create(&organisation, es256_testing_params())
        .await;
    let holder_did = context
        .db
        .dids
        .create(
            &organisation,
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::AssertionMethod,
                    key: key.clone(),
                }]),
                ..Default::default()
            },
        )
        .await;

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, "NONE", Default::default())
        .await;

    let interaction_data = serde_json::to_vec(&json!({
        "issuer_url": "http://127.0.0.1",
        "credential_endpoint": format!("{}/credential", context.server_mock.uri()),
        "access_token": "123",
        "access_token_expires_at": null,
    }))
    .unwrap();
    let interaction = context
        .db
        .interactions
        .create(None, &context.server_mock.uri(), &interaction_data)
        .await;

    context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Pending,
            &issuer_did,
            "OPENID4VC",
            TestingCredentialParams {
                interaction: Some(interaction.to_owned()),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context
        .api
        .interactions
        .issuance_accept(interaction.id, holder_did.id, Some(key.id))
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    let body = resp.json_value().await;
    assert_eq!(body["code"], "BR_0096");
}

#[tokio::test]
async fn test_fail_issuance_accept_openid4vc_no_key_with_auth_role() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;
    let issuer_did = context
        .db
        .dids
        .create(
            &organisation,
            TestingDidParams {
                did_type: Some(DidType::Remote),
                ..Default::default()
            },
        )
        .await;
    let key = context
        .db
        .keys
        .create(&organisation, es256_testing_params())
        .await;
    let holder_did = context
        .db
        .dids
        .create(
            &organisation,
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::AssertionMethod,
                    key: key.clone(),
                }]),
                ..Default::default()
            },
        )
        .await;

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, "NONE", Default::default())
        .await;

    let interaction_data = serde_json::to_vec(&json!({
        "issuer_url": "http://127.0.0.1",
        "credential_endpoint": format!("{}/credential", context.server_mock.uri()),
        "access_token": "123",
        "access_token_expires_at": null,
    }))
    .unwrap();
    let interaction = context
        .db
        .interactions
        .create(None, &context.server_mock.uri(), &interaction_data)
        .await;

    context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Pending,
            &issuer_did,
            "OPENID4VC",
            TestingCredentialParams {
                interaction: Some(interaction.to_owned()),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context
        .api
        .interactions
        .issuance_accept(interaction.id, holder_did.id, None)
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    let body = resp.json_value().await;
    assert_eq!(body["code"], "BR_0096");
}

#[tokio::test]
async fn test_fail_issuance_accept_openid4vc_wallet_storage_type_not_met() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;
    let issuer_did = context
        .db
        .dids
        .create(
            &organisation,
            TestingDidParams {
                did_type: Some(DidType::Remote),
                ..Default::default()
            },
        )
        .await;
    let key = context
        .db
        .keys
        .create(&organisation, es256_testing_params())
        .await;
    let holder_did = context
        .db
        .dids
        .create(
            &organisation,
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::Authentication,
                    key: key.clone(),
                }]),
                ..Default::default()
            },
        )
        .await;

    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test",
            &organisation,
            "NONE",
            TestingCreateSchemaParams {
                wallet_storage_type: Some(WalletStorageTypeEnum::Hardware),
                ..Default::default()
            },
        )
        .await;

    let interaction_data = serde_json::to_vec(&json!({
        "issuer_url": "http://127.0.0.1",
        "credential_endpoint": format!("{}/credential", context.server_mock.uri()),
        "access_token": "123",
        "access_token_expires_at": null,
    }))
    .unwrap();
    let interaction = context
        .db
        .interactions
        .create(None, &context.server_mock.uri(), &interaction_data)
        .await;

    context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Pending,
            &issuer_did,
            "OPENID4VC",
            TestingCredentialParams {
                interaction: Some(interaction.to_owned()),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context
        .api
        .interactions
        .issuance_accept(interaction.id, holder_did.id, Some(key.id))
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    let body = resp.json_value().await;
    assert_eq!(body["code"], "BR_0097");
}
