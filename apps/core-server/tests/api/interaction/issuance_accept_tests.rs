use one_core::model::credential::CredentialStateEnum;
use one_core::model::credential_schema::WalletStorageTypeEnum;
use one_core::model::did::{DidType, KeyRole, RelatedKey};
use serde_json::json;
use uuid::Uuid;

use crate::fixtures::{TestingCredentialParams, TestingDidParams};
use crate::utils::context::TestContext;
use crate::utils::db_clients::credential_schemas::TestingCreateSchemaParams;
use crate::utils::db_clients::keys::es256_testing_params;

static RANDOM_DOCUMENT: &str = "eyJhbGciOiJFRERTQSIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE3MDEyNTk2MzcsImV4cCI6MTc2NDMzMTYzNywibmJmIjoxNzAxMjU5NTc3LCJpc3MiOiJkaWQ6a2V5Ono2TWt2M0hMNTJYSk5oNHJkdG5QS1BSbmRHd1U4bkF1VnBFN3lGRmllNVNOeFprWCIsInN1YiI6ImRkMmZmMDE2LTVmYmUtNDNiMC1hMmJhLTNiMDIzZWNjNTRmYiIsImp0aSI6IjNjNDgwYjUxLTI0ZDQtNGM3OS05MDViLTI3MTQ4YjYyY2RlNiIsInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIiwiaHR0cHM6Ly93M2lkLm9yZy92Yy9zdGF0dXMtbGlzdC8yMDIxL3YxIl0sInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiXSwiY3JlZGVudGlhbFN1YmplY3QiOnsic3RyaW5nIjoic3RyaW5nIn0sImNyZWRlbnRpYWxTdGF0dXMiOnsiaWQiOiJodHRwOi8vMC4wLjAuMDozMDAwL3NzaS9yZXZvY2F0aW9uL3YxL2xpc3QvOGJmNmRjOGYtMjI4Zi00MTVjLTgzZjItOTVkODUxYzE5MjdiIzAiLCJ0eXBlIjoiU3RhdHVzTGlzdDIwMjFFbnRyeSIsInN0YXR1c1B1cnBvc2UiOiJyZXZvY2F0aW9uIiwic3RhdHVzTGlzdENyZWRlbnRpYWwiOiJodHRwOi8vMC4wLjAuMDozMDAwL3NzaS9yZXZvY2F0aW9uL3YxL2xpc3QvOGJmNmRjOGYtMjI4Zi00MTVjLTgzZjItOTVkODUxYzE5MjdiIiwic3RhdHVzTGlzdEluZGV4IjoiMCJ9fX0.JUe1lljvJAXMMLr9mKOKLMFJ1XQr_GzL0i8JTOvt1_uNwVgQzMFQPqMUZ-sQg2JtWogDHLaUsjW64yFyc7ExCg";

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
        "credential_endpoint": format!("{}/ssi/oidc-issuer/v1/{}/credential", context.server_mock.uri(), credential_schema.id),
        "access_token": "123",
        "access_token_expires_at": null,
        "token_endpoint": format!("{}/ssi/oidc-issuer/v1/{}/token", context.server_mock.uri(), credential_schema.id),
        "grants":{
            "urn:ietf:params:oauth:grant-type:pre-authorized_code":{
                "pre-authorized_code":"76f2355d-c9cb-4db6-8779-2f3b81062f8e"
            }
        },
    }))
    .unwrap();

    let interaction = context
        .db
        .interactions
        .create(
            None,
            &context.server_mock.uri(),
            &interaction_data,
            &organisation,
        )
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

    context
        .server_mock
        .ssi_credential_endpoint(credential_schema.id, "123", RANDOM_DOCUMENT, "JWT")
        .await;

    context
        .server_mock
        .token_endpoint(credential_schema.schema_id, "123")
        .await;

    // WHEN
    let resp = context
        .api
        .interactions
        .issuance_accept(interaction.id, holder_did.id, None, None)
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
        "credential_endpoint": format!("{}/ssi/oidc-issuer/v1/{}/credential", context.server_mock.uri(), credential_schema.id),
        "access_token": "123",
        "access_token_expires_at": null,
        "token_endpoint": format!("{}/ssi/oidc-issuer/v1/{}/token", context.server_mock.uri(), credential_schema.id),
        "grants":{
            "urn:ietf:params:oauth:grant-type:pre-authorized_code":{
                "pre-authorized_code":"76f2355d-c9cb-4db6-8779-2f3b81062f8e"
            }
        },
    }))
    .unwrap();
    let interaction = context
        .db
        .interactions
        .create(
            None,
            &context.server_mock.uri(),
            &interaction_data,
            &organisation,
        )
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

    context
        .server_mock
        .token_endpoint(credential_schema.schema_id, "123")
        .await;

    context
        .server_mock
        .ssi_credential_endpoint(credential_schema.id, "123", "eyJhbGciOiJFRERTQSIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE3MDEyNTk2MzcsImV4cCI6MTc2NDMzMTYzNywibmJmIjoxNzAxMjU5NTc3LCJpc3MiOiJkaWQ6a2V5Ono2TWt2M0hMNTJYSk5oNHJkdG5QS1BSbmRHd1U4bkF1VnBFN3lGRmllNVNOeFprWCIsInN1YiI6ImRkMmZmMDE2LTVmYmUtNDNiMC1hMmJhLTNiMDIzZWNjNTRmYiIsImp0aSI6IjNjNDgwYjUxLTI0ZDQtNGM3OS05MDViLTI3MTQ4YjYyY2RlNiIsInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIiwiaHR0cHM6Ly93M2lkLm9yZy92Yy9zdGF0dXMtbGlzdC8yMDIxL3YxIl0sInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiXSwiY3JlZGVudGlhbFN1YmplY3QiOnsic3RyaW5nIjoic3RyaW5nIn0sImNyZWRlbnRpYWxTdGF0dXMiOnsiaWQiOiJodHRwOi8vMC4wLjAuMDozMDAwL3NzaS9yZXZvY2F0aW9uL3YxL2xpc3QvOGJmNmRjOGYtMjI4Zi00MTVjLTgzZjItOTVkODUxYzE5MjdiIzAiLCJ0eXBlIjoiU3RhdHVzTGlzdDIwMjFFbnRyeSIsInN0YXR1c1B1cnBvc2UiOiJyZXZvY2F0aW9uIiwic3RhdHVzTGlzdENyZWRlbnRpYWwiOiJodHRwOi8vMC4wLjAuMDozMDAwL3NzaS9yZXZvY2F0aW9uL3YxL2xpc3QvOGJmNmRjOGYtMjI4Zi00MTVjLTgzZjItOTVkODUxYzE5MjdiIiwic3RhdHVzTGlzdEluZGV4IjoiMCJ9fX0.JUe1lljvJAXMMLr9mKOKLMFJ1XQr_GzL0i8JTOvt1_uNwVgQzMFQPqMUZ-sQg2JtWogDHLaUsjW64yFyc7ExCg", "JWT")
        .await;

    // WHEN
    let resp = context
        .api
        .interactions
        .issuance_accept(interaction.id, holder_did.id, Some(key.id), None)
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
        "credential_endpoint": format!("{}/ssi/oidc-issuer/v1/{}/credential", context.server_mock.uri(), credential_schema.id),
        "access_token": "123",
        "access_token_expires_at": null,
        "token_endpoint": format!("{}/ssi/oidc-issuer/v1/{}/token", context.server_mock.uri(), credential_schema.id),
        "grants":{
            "urn:ietf:params:oauth:grant-type:pre-authorized_code":{
                "pre-authorized_code":"76f2355d-c9cb-4db6-8779-2f3b81062f8e"
            }
        },
    }))
    .unwrap();
    let interaction = context
        .db
        .interactions
        .create(
            None,
            &context.server_mock.uri(),
            &interaction_data,
            &organisation,
        )
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
        .issuance_accept(interaction.id, Uuid::new_v4(), None, None)
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!("BR_0024", resp.error_code().await);
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
        "credential_endpoint": format!("{}/ssi/oidc-issuer/v1/{}/credential", context.server_mock.uri(), credential_schema.id),
        "access_token": "123",
        "access_token_expires_at": null,
        "token_endpoint": format!("{}/ssi/oidc-issuer/v1/{}/token", context.server_mock.uri(), credential_schema.id),
        "grants":{
            "urn:ietf:params:oauth:grant-type:pre-authorized_code":{
                "pre-authorized_code":"76f2355d-c9cb-4db6-8779-2f3b81062f8e"
            }
        },
    }))
    .unwrap();
    let interaction = context
        .db
        .interactions
        .create(
            None,
            &context.server_mock.uri(),
            &interaction_data,
            &organisation,
        )
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
        .issuance_accept(
            interaction.id,
            holder_did.id,
            Some(Uuid::new_v4().into()),
            None,
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!("BR_0037", resp.error_code().await);
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
        .create(
            None,
            &context.server_mock.uri(),
            &interaction_data,
            &organisation,
        )
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
        .issuance_accept(interaction.id, holder_did.id, Some(key.id), None)
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!("BR_0096", resp.error_code().await);
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
        .create(
            None,
            &context.server_mock.uri(),
            &interaction_data,
            &organisation,
        )
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
        .issuance_accept(interaction.id, holder_did.id, None, None)
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!("BR_0096", resp.error_code().await);
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
        .create(
            None,
            &context.server_mock.uri(),
            &interaction_data,
            &organisation,
        )
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
        .issuance_accept(interaction.id, holder_did.id, Some(key.id), None)
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!("BR_0097", resp.error_code().await);
}

#[tokio::test]
async fn test_issuance_accept_openid4vc_with_tx_code() {
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
        "credential_endpoint": format!("{}/ssi/oidc-issuer/v1/{}/credential", context.server_mock.uri(), credential_schema.id),
        "access_token": "123",
        "access_token_expires_at": null,
        "token_endpoint": format!("{}/ssi/oidc-issuer/v1/{}/token", context.server_mock.uri(), credential_schema.id),
        "grants":{
            "urn:ietf:params:oauth:grant-type:pre-authorized_code":{
                "pre-authorized_code":"76f2355d-c9cb-4db6-8779-2f3b81062f8e",
                "tx_code":{"input_mode":"numeric","length":5,"description":"code"}
            }
        },
    }))
    .unwrap();

    let interaction = context
        .db
        .interactions
        .create(
            None,
            &context.server_mock.uri(),
            &interaction_data,
            &organisation,
        )
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

    context
        .server_mock
        .ssi_credential_endpoint(credential_schema.id, "123", RANDOM_DOCUMENT, "JWT")
        .await;

    let tx_code = "45454";

    context
        .server_mock
        .token_endpoint_tx_code(credential_schema.schema_id, "123", tx_code)
        .await;

    // WHEN
    let resp = context
        .api
        .interactions
        .issuance_accept(interaction.id, holder_did.id, None, Some(tx_code))
        .await;

    // THEN
    assert_eq!(resp.status(), 204);

    let credential = context.db.credentials.get(&credential.id).await;
    assert_eq!(holder_did.id, credential.holder_did.unwrap().id);

    let states = credential.state.unwrap();
    assert_eq!(2, states.len());
    assert_eq!(CredentialStateEnum::Accepted, states[0].state);
}
