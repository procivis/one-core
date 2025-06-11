use one_core::model::credential::{Credential, CredentialStateEnum};
use one_core::model::credential_schema::CredentialSchema;
use one_core::model::did::{DidType, KeyRole, RelatedKey};
use one_core::model::identifier::IdentifierType;
use one_core::provider::issuance_protocol::openid4vci_draft13::model::OpenID4VCINotificationEvent;
use one_crypto::Hasher;
use one_crypto::hasher::sha256::SHA256;
use serde_json::json;
use time::OffsetDateTime;
use time::macros::format_description;
use uuid::Uuid;

use crate::fixtures::{TestingCredentialParams, TestingDidParams, TestingIdentifierParams};
use crate::utils::context::TestContext;
use crate::utils::db_clients::keys::eddsa_testing_params;

#[tokio::test]
async fn test_post_notification_credential_accepted() {
    let (context, credential, credential_schema) = setup_accepted_credential().await;

    let resp = context
        .api
        .ssi
        .openid4vci_notification(
            credential_schema.id,
            "notification",
            OpenID4VCINotificationEvent::CredentialAccepted,
        )
        .await;

    assert_eq!(204, resp.status());

    let credential = context.db.credentials.get(&credential.id).await;
    assert_eq!(credential.state, CredentialStateEnum::Accepted);
}

#[tokio::test]
async fn test_post_notification_credential_failure() {
    let (context, credential, credential_schema) = setup_accepted_credential().await;

    let resp = context
        .api
        .ssi
        .openid4vci_notification(
            credential_schema.id,
            "notification",
            OpenID4VCINotificationEvent::CredentialFailure,
        )
        .await;

    assert_eq!(204, resp.status());

    let credential = context.db.credentials.get(&credential.id).await;
    assert_eq!(credential.state, CredentialStateEnum::Error);
}

#[tokio::test]
async fn test_post_notification_credential_deleted() {
    let (context, credential, credential_schema) = setup_accepted_credential().await;

    let resp = context
        .api
        .ssi
        .openid4vci_notification(
            credential_schema.id,
            "notification",
            OpenID4VCINotificationEvent::CredentialDeleted,
        )
        .await;

    assert_eq!(204, resp.status());

    let credential = context.db.credentials.get(&credential.id).await;
    assert_eq!(credential.state, CredentialStateEnum::Rejected);
}

async fn setup_accepted_credential() -> (TestContext, Credential, CredentialSchema) {
    let interaction_id = Uuid::new_v4();
    let access_token = format!("{interaction_id}.test");

    let context = TestContext::new_with_token(&access_token, None).await;

    let organisation = context.db.organisations.create().await;

    let key = context
        .db
        .keys
        .create(&organisation, eddsa_testing_params())
        .await;

    let issuer_did = context
        .db
        .dids
        .create(
            Some(organisation.clone()),
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::AssertionMethod,
                    key: key.clone(),
                }]),
                ..Default::default()
            },
        )
        .await;
    let issuer_identifier = context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                did: Some(issuer_did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(issuer_did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;

    let str_claim_id = Uuid::new_v4();
    let new_claim_schemas: Vec<(Uuid, &str, bool, &str, bool)> = vec![
        (Uuid::new_v4(), "root", true, "OBJECT", false),
        (str_claim_id, "root/str", true, "STRING", false),
    ];

    let credential_schema = context
        .db
        .credential_schemas
        .create_with_claims(
            &Uuid::new_v4(),
            "schema-1",
            &organisation,
            "NONE",
            &new_claim_schemas,
            "MDOC",
            "schema-id",
        )
        .await;

    let date_format =
        format_description!("[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond]Z");
    let data = serde_json::to_vec(&json!({
        "pre_authorized_code_used": true,
        "access_token_hash": SHA256.hash(access_token.as_bytes()).unwrap(),
        "access_token_expires_at": (OffsetDateTime::now_utc() + time::Duration::seconds(20)).format(&date_format).unwrap(),
        "notification_id": "notification"
    })).unwrap();

    let base_url = &context.config.app.core_base_url;
    let interaction = context
        .db
        .interactions
        .create(Some(interaction_id), base_url, &data, &organisation)
        .await;

    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &issuer_identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                interaction: Some(interaction),
                key: Some(key),
                claims_data: Some(vec![(str_claim_id, "root/str", "str-value")]),
                ..Default::default()
            },
        )
        .await;

    (context, credential, credential_schema)
}
