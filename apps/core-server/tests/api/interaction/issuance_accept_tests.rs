use std::str::FromStr;

use one_core::model::claim_schema::ClaimSchema;
use one_core::model::credential::CredentialStateEnum;
use one_core::model::credential_schema::{CredentialSchemaClaim, WalletStorageTypeEnum};
use one_core::model::did::{DidType, KeyRole, RelatedKey};
use serde_json::json;
use shared_types::DidValue;
use time::macros::datetime;
use uuid::Uuid;

use crate::fixtures::{
    encrypted_token, TestingCredentialParams, TestingDidParams, TestingKeyParams,
};
use crate::utils::context::TestContext;
use crate::utils::db_clients::credential_schemas::TestingCreateSchemaParams;
use crate::utils::db_clients::keys::es256_testing_params;

static RANDOM_DOCUMENT: &str = "eyJhbGciOiJFRERTQSIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE3MDEyNTk2MzcsImV4cCI6MTc2NDMzMTYzNywibmJmIjoxNzAxMjU5NTc3LCJpc3MiOiJkaWQ6a2V5Ono2TWt2M0hMNTJYSk5oNHJkdG5QS1BSbmRHd1U4bkF1VnBFN3lGRmllNVNOeFprWCIsInN1YiI6ImRkMmZmMDE2LTVmYmUtNDNiMC1hMmJhLTNiMDIzZWNjNTRmYiIsImp0aSI6IjNjNDgwYjUxLTI0ZDQtNGM3OS05MDViLTI3MTQ4YjYyY2RlNiIsInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIiwiaHR0cHM6Ly93M2lkLm9yZy92Yy9zdGF0dXMtbGlzdC8yMDIxL3YxIl0sInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiXSwiY3JlZGVudGlhbFN1YmplY3QiOnsic3RyaW5nIjoic3RyaW5nIn0sImNyZWRlbnRpYWxTdGF0dXMiOnsiaWQiOiJodHRwOi8vMC4wLjAuMDozMDAwL3NzaS9yZXZvY2F0aW9uL3YxL2xpc3QvOGJmNmRjOGYtMjI4Zi00MTVjLTgzZjItOTVkODUxYzE5MjdiIzAiLCJ0eXBlIjoiU3RhdHVzTGlzdDIwMjFFbnRyeSIsInN0YXR1c1B1cnBvc2UiOiJyZXZvY2F0aW9uIiwic3RhdHVzTGlzdENyZWRlbnRpYWwiOiJodHRwOi8vMC4wLjAuMDozMDAwL3NzaS9yZXZvY2F0aW9uL3YxL2xpc3QvOGJmNmRjOGYtMjI4Zi00MTVjLTgzZjItOTVkODUxYzE5MjdiIiwic3RhdHVzTGlzdEluZGV4IjoiMCJ9fX0.JUe1lljvJAXMMLr9mKOKLMFJ1XQr_GzL0i8JTOvt1_uNwVgQzMFQPqMUZ-sQg2JtWogDHLaUsjW64yFyc7ExCg";
static DOCUMENT_INVALID_SIG: &str = "eyJhbGciOiJFRERTQSIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE3MDEyNTk2MzcsImV4cCI6MTc2NDMzMTYzNywibmJmIjoxNzAxMjU5NTc3LCJpc3MiOiJkaWQ6a2V5Ono2TWt2M0hMNTJYSk5oNHJkdG5QS1BSbmRHd1U4bkF1VnBFN3lGRmllNVNOeFprWCIsInN1YiI6ImRkMmZmMDE2LTVmYmUtNDNiMC1hMmJhLTNiMDIzZWNjNTRmYiIsImp0aSI6IjNjNDgwYjUxLTI0ZDQtNGM3OS05MDViLTI3MTQ4YjYyY2RlNiIsInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIiwiaHR0cHM6Ly93M2lkLm9yZy92Yy9zdGF0dXMtbGlzdC8yMDIxL3YxIl0sInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiXSwiY3JlZGVudGlhbFN1YmplY3QiOnsic3RyaW5nIjoic3RyaW5nIn0sImNyZWRlbnRpYWxTdGF0dXMiOnsiaWQiOiJodHRwOi8vMC4wLjAuMDozMDAwL3NzaS9yZXZvY2F0aW9uL3YxL2xpc3QvOGJmNmRjOGYtMjI4Zi00MTVjLTgzZjItOTVkODUxYzE5MjdiIzAiLCJ0eXBlIjoiU3RhdHVzTGlzdDIwMjFFbnRyeSIsInN0YXR1c1B1cnBvc2UiOiJyZXZvY2F0aW9uIiwic3RhdHVzTGlzdENyZWRlbnRpYWwiOiJodHRwOi8vMC4wLjAuMDozMDAwL3NzaS9yZXZvY2F0aW9uL3YxL2xpc3QvOGJmNmRjOGYtMjI4Zi00MTVjLTgzZjItOTVkODUxYzE5MjdiIiwic3RhdHVzTGlzdEluZGV4IjoiMCJ9fX0.JUe1lljvJAXMMLr9mKOKLMFJ1XQr_GzL0i8JTOvt1_uNwVgQzMFQPqMUZ-sQg2JtWogDHLaUsjW64yFyc7ExCw";

#[tokio::test]
async fn test_issuance_accept_openid4vc() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let issuer_did = context
        .db
        .dids
        .create(
            &organisation,
            TestingDidParams {
                did_type: Some(DidType::Remote),
                did: Some(
                    "did:key:z6Mkv3HL52XJNh4rdtnPKPRndGwU8nAuVpE7yFFie5SNxZkX"
                        .parse()
                        .unwrap(),
                ),
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
                did: Some(
                    DidValue::from_str("did:key:zDnaeY6V3KGKLzgK3C2hbb4zMpeVKbrtWhEP4WXUyTAbshioQ")
                        .unwrap(),
                ),
                ..Default::default()
            },
        )
        .await;

    let schema_id = Uuid::new_v4();

    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test",
            &organisation,
            "NONE",
            TestingCreateSchemaParams {
                claim_schemas: Some(vec![CredentialSchemaClaim {
                    schema: ClaimSchema {
                        id: schema_id.into(),
                        key: "string".to_string(),
                        data_type: "STRING".to_string(),
                        created_date: datetime!(2024-10-20 12:00 +1),
                        last_modified: datetime!(2024-10-20 12:00 +1),
                        array: false,
                    },
                    required: true,
                }]),
                ..Default::default()
            },
        )
        .await;

    let interaction_data = serde_json::to_vec(&json!({
        "issuer_url": "http://127.0.0.1",
        "credential_endpoint": format!("{}/ssi/oidc-issuer/v1/{}/credential", context.server_mock.uri(), credential_schema.id),
        "access_token": encrypted_token("123"),
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
        .ssi_credential_endpoint(credential_schema.id, "123", RANDOM_DOCUMENT, "JWT", 1)
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

    assert_eq!(CredentialStateEnum::Accepted, credential.state);
}

#[tokio::test]
async fn test_issuance_accept_openid4vc_issuer_did_mismatch() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
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
                did: Some(
                    DidValue::from_str("did:key:zDnaeY6V3KGKLzgK3C2hbb4zMpeVKbrtWhEP4WXUyTAbshioQ")
                        .unwrap(),
                ),
                ..Default::default()
            },
        )
        .await;

    let schema_id = Uuid::new_v4();

    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test",
            &organisation,
            "NONE",
            TestingCreateSchemaParams {
                claim_schemas: Some(vec![CredentialSchemaClaim {
                    schema: ClaimSchema {
                        id: schema_id.into(),
                        key: "string".to_string(),
                        data_type: "STRING".to_string(),
                        created_date: datetime!(2024-10-20 12:00 +1),
                        last_modified: datetime!(2024-10-20 12:00 +1),
                        array: false,
                    },
                    required: true,
                }]),
                ..Default::default()
            },
        )
        .await;

    let interaction_data = serde_json::to_vec(&json!({
        "issuer_url": "http://127.0.0.1",
        "credential_endpoint": format!("{}/ssi/oidc-issuer/v1/{}/credential", context.server_mock.uri(), credential_schema.id),
        "access_token": encrypted_token("123"),
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

    context
        .server_mock
        .ssi_credential_endpoint(credential_schema.id, "123", RANDOM_DOCUMENT, "JWT", 1)
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
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0173")
}

#[tokio::test]
async fn test_issuance_accept_openid4vc_issuer_invalid_signature() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let issuer_did = context
        .db
        .dids
        .create(
            &organisation,
            TestingDidParams {
                did_type: Some(DidType::Remote),
                did: Some(
                    "did:key:z6Mkv3HL52XJNh4rdtnPKPRndGwU8nAuVpE7yFFie5SNxZkX"
                        .parse()
                        .unwrap(),
                ),
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
                did: Some(
                    DidValue::from_str("did:key:zDnaeY6V3KGKLzgK3C2hbb4zMpeVKbrtWhEP4WXUyTAbshioQ")
                        .unwrap(),
                ),
                ..Default::default()
            },
        )
        .await;

    let schema_id = Uuid::new_v4();

    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test",
            &organisation,
            "NONE",
            TestingCreateSchemaParams {
                claim_schemas: Some(vec![CredentialSchemaClaim {
                    schema: ClaimSchema {
                        id: schema_id.into(),
                        key: "string".to_string(),
                        data_type: "STRING".to_string(),
                        created_date: datetime!(2024-10-20 12:00 +1),
                        last_modified: datetime!(2024-10-20 12:00 +1),
                        array: false,
                    },
                    required: true,
                }]),
                ..Default::default()
            },
        )
        .await;

    let interaction_data = serde_json::to_vec(&json!({
        "issuer_url": "http://127.0.0.1",
        "credential_endpoint": format!("{}/ssi/oidc-issuer/v1/{}/credential", context.server_mock.uri(), credential_schema.id),
        "access_token": encrypted_token("123"),
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

    context
        .server_mock
        .ssi_credential_endpoint(credential_schema.id, "123", DOCUMENT_INVALID_SIG, "JWT", 1)
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
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0173")
}

#[tokio::test]
async fn test_issuance_accept_openid4vc_with_key_id() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let issuer_did = context
        .db
        .dids
        .create(
            &organisation,
            TestingDidParams {
                did_type: Some(DidType::Remote),
                did: Some(
                    "did:key:z6Mkv3HL52XJNh4rdtnPKPRndGwU8nAuVpE7yFFie5SNxZkX"
                        .parse()
                        .unwrap(),
                ),
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
                did: Some(
                    DidValue::from_str("did:key:zDnaeY6V3KGKLzgK3C2hbb4zMpeVKbrtWhEP4WXUyTAbshioQ")
                        .unwrap(),
                ),
                ..Default::default()
            },
        )
        .await;

    let schema_id = Uuid::new_v4();

    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test",
            &organisation,
            "NONE",
            TestingCreateSchemaParams {
                claim_schemas: Some(vec![CredentialSchemaClaim {
                    schema: ClaimSchema {
                        id: schema_id.into(),
                        key: "string".to_string(),
                        data_type: "STRING".to_string(),
                        created_date: datetime!(2024-10-20 12:00 +1),
                        last_modified: datetime!(2024-10-20 12:00 +1),
                        array: false,
                    },
                    required: true,
                }]),
                ..Default::default()
            },
        )
        .await;

    let interaction_data = serde_json::to_vec(&json!({
        "issuer_url": "http://127.0.0.1",
        "credential_endpoint": format!("{}/ssi/oidc-issuer/v1/{}/credential", context.server_mock.uri(), credential_schema.id),
        "access_token": encrypted_token("123"),
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
        .ssi_credential_endpoint(credential_schema.id, "123", "eyJhbGciOiJFRERTQSIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE3MDEyNTk2MzcsImV4cCI6MTc2NDMzMTYzNywibmJmIjoxNzAxMjU5NTc3LCJpc3MiOiJkaWQ6a2V5Ono2TWt2M0hMNTJYSk5oNHJkdG5QS1BSbmRHd1U4bkF1VnBFN3lGRmllNVNOeFprWCIsInN1YiI6ImRkMmZmMDE2LTVmYmUtNDNiMC1hMmJhLTNiMDIzZWNjNTRmYiIsImp0aSI6IjNjNDgwYjUxLTI0ZDQtNGM3OS05MDViLTI3MTQ4YjYyY2RlNiIsInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIiwiaHR0cHM6Ly93M2lkLm9yZy92Yy9zdGF0dXMtbGlzdC8yMDIxL3YxIl0sInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiXSwiY3JlZGVudGlhbFN1YmplY3QiOnsic3RyaW5nIjoic3RyaW5nIn0sImNyZWRlbnRpYWxTdGF0dXMiOnsiaWQiOiJodHRwOi8vMC4wLjAuMDozMDAwL3NzaS9yZXZvY2F0aW9uL3YxL2xpc3QvOGJmNmRjOGYtMjI4Zi00MTVjLTgzZjItOTVkODUxYzE5MjdiIzAiLCJ0eXBlIjoiU3RhdHVzTGlzdDIwMjFFbnRyeSIsInN0YXR1c1B1cnBvc2UiOiJyZXZvY2F0aW9uIiwic3RhdHVzTGlzdENyZWRlbnRpYWwiOiJodHRwOi8vMC4wLjAuMDozMDAwL3NzaS9yZXZvY2F0aW9uL3YxL2xpc3QvOGJmNmRjOGYtMjI4Zi00MTVjLTgzZjItOTVkODUxYzE5MjdiIiwic3RhdHVzTGlzdEluZGV4IjoiMCJ9fX0.JUe1lljvJAXMMLr9mKOKLMFJ1XQr_GzL0i8JTOvt1_uNwVgQzMFQPqMUZ-sQg2JtWogDHLaUsjW64yFyc7ExCg", "JWT", 1)
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

    assert_eq!(CredentialStateEnum::Accepted, credential.state);
}

#[tokio::test]
async fn test_fail_issuance_accept_openid4vc_unknown_did() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
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
        "access_token": encrypted_token("123"),
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
    let (context, organisation) = TestContext::new_with_organisation(None).await;
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
        "access_token": encrypted_token("123"),
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
    let (context, organisation) = TestContext::new_with_organisation(None).await;
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
        "access_token": encrypted_token("123"),
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
async fn test_fail_issuance_accept_openid4vc_wrong_key_security() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let issuer_did = context
        .db
        .dids
        .create(
            &organisation,
            TestingDidParams {
                did_type: Some(DidType::Remote),
                did: Some(
                    "did:key:z6Mkv3HL52XJNh4rdtnPKPRndGwU8nAuVpE7yFFie5SNxZkX"
                        .parse()
                        .unwrap(),
                ),
                ..Default::default()
            },
        )
        .await;
    let key = context
        .db
        .keys
        .create(
            &organisation,
            TestingKeyParams {
                ..es256_testing_params()
            },
        )
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
                did: Some(
                    DidValue::from_str("did:key:zDnaeY6V3KGKLzgK3C2hbb4zMpeVKbrtWhEP4WXUyTAbshioQ")
                        .unwrap(),
                ),
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
                wallet_storage_type: Some(WalletStorageTypeEnum::RemoteSecureElement),
                ..Default::default()
            },
        )
        .await;

    let interaction_data = serde_json::to_vec(&json!({
        "issuer_url": "http://127.0.0.1",
        "credential_endpoint": format!("{}/credential", context.server_mock.uri()),
        "access_token": encrypted_token("123"),
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
async fn test_fail_issuance_accept_openid4vc_no_key_with_auth_role() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
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
        "access_token": encrypted_token("123"),
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
    let (context, organisation) = TestContext::new_with_organisation(None).await;
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
                did: Some(
                    DidValue::from_str("did:key:zDnaeY6V3KGKLzgK3C2hbb4zMpeVKbrtWhEP4WXUyTAbshioQ")
                        .unwrap(),
                ),
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
        "access_token": encrypted_token("123"),
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
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let issuer_did = context
        .db
        .dids
        .create(
            &organisation,
            TestingDidParams {
                did_type: Some(DidType::Remote),
                did: Some(
                    "did:key:z6Mkv3HL52XJNh4rdtnPKPRndGwU8nAuVpE7yFFie5SNxZkX"
                        .parse()
                        .unwrap(),
                ),
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
                did: Some(
                    DidValue::from_str("did:key:zDnaeY6V3KGKLzgK3C2hbb4zMpeVKbrtWhEP4WXUyTAbshioQ")
                        .unwrap(),
                ),
                ..Default::default()
            },
        )
        .await;

    let schema_id = Uuid::new_v4();

    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test",
            &organisation,
            "NONE",
            TestingCreateSchemaParams {
                claim_schemas: Some(vec![CredentialSchemaClaim {
                    schema: ClaimSchema {
                        id: schema_id.into(),
                        key: "string".to_string(),
                        data_type: "STRING".to_string(),
                        created_date: datetime!(2024-10-20 12:00 +1),
                        last_modified: datetime!(2024-10-20 12:00 +1),
                        array: false,
                    },
                    required: true,
                }]),
                ..Default::default()
            },
        )
        .await;

    let interaction_data = serde_json::to_vec(&json!({
        "issuer_url": "http://127.0.0.1",
        "credential_endpoint": format!("{}/ssi/oidc-issuer/v1/{}/credential", context.server_mock.uri(), credential_schema.id),
        "access_token": encrypted_token("123"),
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
        .ssi_credential_endpoint(credential_schema.id, "123", RANDOM_DOCUMENT, "JWT", 1)
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

    assert_eq!(CredentialStateEnum::Accepted, credential.state);
}

#[tokio::test]
async fn test_issuance_accept_openid4vc_update_from_vc() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let issuer_did = context
        .db
        .dids
        .create(
            &organisation,
            TestingDidParams {
                did_type: Some(DidType::Remote),
                did: Some(
                    "did:key:z6Mkv3HL52XJNh4rdtnPKPRndGwU8nAuVpE7yFFie5SNxZkX"
                        .parse()
                        .unwrap(),
                ),
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
                did: Some(
                    DidValue::from_str("did:key:zDnaeY6V3KGKLzgK3C2hbb4zMpeVKbrtWhEP4WXUyTAbshioQ")
                        .unwrap(),
                ),
                ..Default::default()
            },
        )
        .await;

    let schema_id = Uuid::new_v4();

    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test",
            &organisation,
            "NONE",
            TestingCreateSchemaParams {
                claim_schemas: Some(vec![CredentialSchemaClaim {
                    schema: ClaimSchema {
                        id: schema_id.into(),
                        key: "string".to_string(),
                        data_type: "STRING".to_string(),
                        created_date: datetime!(2024-10-20 12:00 +1),
                        last_modified: datetime!(2024-10-20 12:00 +1),
                        array: false,
                    },
                    required: true,
                }]),
                ..Default::default()
            },
        )
        .await;

    let interaction_data = serde_json::to_vec(&json!({
        "issuer_url": "http://127.0.0.1",
        "credential_endpoint": format!("{}/ssi/oidc-issuer/v1/{}/credential", context.server_mock.uri(), credential_schema.id),
        "access_token": encrypted_token("123"),
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
                claims_data: Some(vec![(schema_id, "string", "")]),
                ..Default::default()
            },
        )
        .await;

    context
        .server_mock
        .ssi_credential_endpoint(credential_schema.id, "123", RANDOM_DOCUMENT, "JWT", 1)
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
    let claims = credential.claims.unwrap();

    let claim = claims.iter().find(|claim| claim.path == "string").unwrap();

    assert_eq!(claim.value, "string");
    assert_eq!(claim.schema.as_ref().unwrap().key, "string");
}

#[tokio::test]
async fn test_issuance_accept_openid4vc_update_from_vc_complex() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let issuer_did = context
        .db
        .dids
        .create(
            &organisation,
            TestingDidParams {
                did_type: Some(DidType::Remote),
                did: Some(
                    "did:key:z6MkmbnkXaAsQrxgo9uGVrKSsm5w6jezSr52MwV7RayDWjxL"
                        .parse()
                        .unwrap(),
                ),
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
                did: Some(
                    DidValue::from_str("did:key:z6MkviStFZjsFT9KP8R8vaXZJj5i4ouvmHxh7CpGrptzfMHD")
                        .unwrap(),
                ),
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
                format: Some("JSON_LD_CLASSIC".to_string()),
                claim_schemas: Some(vec![
                    CredentialSchemaClaim {
                        schema: ClaimSchema {
                            id: Uuid::new_v4().into(),
                            key: "first name".to_string(),
                            data_type: "STRING".to_string(),
                            created_date: datetime!(2024-10-20 12:00 +1),
                            last_modified: datetime!(2024-10-20 12:00 +1),
                            array: false,
                        },
                        required: true,
                    },
                    CredentialSchemaClaim {
                        schema: ClaimSchema {
                            id: Uuid::new_v4().into(),
                            key: "last name".to_string(),
                            data_type: "STRING".to_string(),
                            created_date: datetime!(2024-10-20 12:00 +1),
                            last_modified: datetime!(2024-10-20 12:00 +1),
                            array: false,
                        },
                        required: true,
                    },
                    CredentialSchemaClaim {
                        schema: ClaimSchema {
                            id: Uuid::new_v4().into(),
                            key: "address".to_string(),
                            data_type: "OBJECT".to_string(),
                            created_date: datetime!(2024-10-20 12:00 +1),
                            last_modified: datetime!(2024-10-20 12:00 +1),
                            array: false,
                        },
                        required: true,
                    },
                    CredentialSchemaClaim {
                        schema: ClaimSchema {
                            id: Uuid::new_v4().into(),
                            key: "address/postal code".to_string(),
                            data_type: "STRING".to_string(),
                            created_date: datetime!(2024-10-20 12:00 +1),
                            last_modified: datetime!(2024-10-20 12:00 +1),
                            array: false,
                        },
                        required: true,
                    },
                    CredentialSchemaClaim {
                        schema: ClaimSchema {
                            id: Uuid::new_v4().into(),
                            key: "address/street".to_string(),
                            data_type: "STRING".to_string(),
                            created_date: datetime!(2024-10-20 12:00 +1),
                            last_modified: datetime!(2024-10-20 12:00 +1),
                            array: false,
                        },
                        required: true,
                    },
                ]),
                ..Default::default()
            },
        )
        .await;

    let interaction_data = serde_json::to_vec(&json!({
        "issuer_url": "http://127.0.0.1",
        "credential_endpoint": format!("{}/ssi/oidc-issuer/v1/{}/credential", context.server_mock.uri(), credential_schema.id),
        "access_token": encrypted_token("123"),
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
                claims_data: Some(vec![
                    (
                        credential_schema.claim_schemas.as_ref().unwrap()[0]
                            .schema
                            .id
                            .into(),
                        "first name",
                        "John",
                    ),
                    (
                        credential_schema.claim_schemas.as_ref().unwrap()[1]
                            .schema
                            .id
                            .into(),
                        "last name",
                        "Doe",
                    ),
                    (
                        credential_schema.claim_schemas.as_ref().unwrap()[3]
                            .schema
                            .id
                            .into(),
                        "address/postal code",
                        "1234",
                    ),
                    (
                        credential_schema.claim_schemas.as_ref().unwrap()[4]
                            .schema
                            .id
                            .into(),
                        "address/street",
                        "Via Torino",
                    ),
                ]),
                ..Default::default()
            },
        )
        .await;

    context
        .server_mock
        .ssi_credential_endpoint(credential_schema.id, "123", complex_document(), "JWT", 1)
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
    let claims = credential.claims.unwrap();

    let claim = claims
        .iter()
        .find(|claim| claim.path == "first name")
        .unwrap();
    assert_eq!(claim.value, "John");
    assert_eq!(claim.schema.as_ref().unwrap().key, "first name");

    let claim = claims
        .iter()
        .find(|claim| claim.path == "last name")
        .unwrap();
    assert_eq!(claim.value, "Doe");
    assert_eq!(claim.schema.as_ref().unwrap().key, "last name");

    let claim = claims
        .iter()
        .find(|claim| claim.path == "address/postal code")
        .unwrap();
    assert_eq!(claim.value, "1234");
    assert_eq!(claim.schema.as_ref().unwrap().key, "address/postal code");

    let claim = claims
        .iter()
        .find(|claim| claim.path == "address/street")
        .unwrap();
    assert_eq!(claim.value, "Via Torino");
    assert_eq!(claim.schema.as_ref().unwrap().key, "address/street");
}

fn complex_document() -> &'static str {
    r#"{
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                {
                    "ProcivisOneSchema2024": {
                        "@context": {
                            "@protected": true,
                            "id": "@id",
                            "type": "@type",
                            "metadata": {
                                "@id": "http://0.0.0.0:3000/ssi/context/v1/88f2e231-cead-4034-b28e-c02c29e8eb3f#metadata",
                                "@type": "@json"
                            }
                        },
                        "@id": "http://0.0.0.0:3000/ssi/context/v1/88f2e231-cead-4034-b28e-c02c29e8eb3f#ProcivisOneSchema2024"
                    },
                    "SimpleTest": "http://0.0.0.0:3000/ssi/context/v1/88f2e231-cead-4034-b28e-c02c29e8eb3f#SimpleTest",
                    "last name": "http://0.0.0.0:3000/ssi/context/v1/88f2e231-cead-4034-b28e-c02c29e8eb3f#last%20name",
                    "first name": "http://0.0.0.0:3000/ssi/context/v1/88f2e231-cead-4034-b28e-c02c29e8eb3f#first%20name",
                    "address": {
                        "@context": {
                            "@protected": true,
                            "id": "@id",
                            "type": "@type",
                            "postal code": "http://0.0.0.0:3000/ssi/context/v1/88f2e231-cead-4034-b28e-c02c29e8eb3f#postal%20code",
                            "street": "http://0.0.0.0:3000/ssi/context/v1/88f2e231-cead-4034-b28e-c02c29e8eb3f#street"
                        },
                        "@id": "http://0.0.0.0:3000/ssi/context/v1/88f2e231-cead-4034-b28e-c02c29e8eb3f#address"
                    }
                }
            ],
            "type": [
                "VerifiableCredential",
                "SimpleTest"
            ],
            "issuer": "did:key:z6MkmbnkXaAsQrxgo9uGVrKSsm5w6jezSr52MwV7RayDWjxL",
            "validFrom": "2025-03-10T22:13:36.652829Z",
            "validUntil": "2027-03-10T22:13:36.652829Z",
            "credentialSubject": {
                "id": "did:key:z6MkviStFZjsFT9KP8R8vaXZJj5i4ouvmHxh7CpGrptzfMHD",
                "first name": "John",
                "last name": "Doe",
                "address": {
                    "postal code": "1234",
                    "street": "Via Torino"
                }
            },
            "proof": {
                "type": "DataIntegrityProof",
                "created": "2025-03-10T22:13:36.653229Z",
                "cryptosuite": "eddsa-rdfc-2022",
                "verificationMethod": "did:key:z6MkmbnkXaAsQrxgo9uGVrKSsm5w6jezSr52MwV7RayDWjxL#z6MkmbnkXaAsQrxgo9uGVrKSsm5w6jezSr52MwV7RayDWjxL",
                "proofPurpose": "assertionMethod",
                "proofValue": "z3VzJfDiE21cCnhVufh6C9uGHibe7gsn5v2D4DN8w9FZaSTUMqq8wPEtiaCEPKkpSxXAvpjvPj5QMKZJCLtpZGBf7"
            },
            "credentialSchema": {
                "id": "http://0.0.0.0:3000/ssi/schema/v1/88f2e231-cead-4034-b28e-c02c29e8eb3f",
                "type": "ProcivisOneSchema2024"
            }
        }"#
}
