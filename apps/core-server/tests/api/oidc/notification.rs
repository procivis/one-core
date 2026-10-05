use std::collections::HashMap;

use assert2::let_assert;
use one_core::error::ErrorCode;
use one_core::model::certificate::CertificateRole;
use one_core::model::credential::{
    Credential, CredentialFilterValue, CredentialStateEnum, CredentialType,
};
use one_core::model::credential_schema::CredentialSchema;
use one_core::model::credential_schema_format::CredentialSchemaFormat;
use one_core::model::did::{KeyRole, RelatedKey};
use one_core::model::history::{HistoryAction, HistoryMetadata};
use one_core::model::identifier::IdentifierType;
use one_core::model::interaction::InteractionType;
use one_core::model::list_filter::ListFilterValue;
use one_core::model::revocation_list::{RevocationListPurpose, StatusListCredentialFormat};
use one_crypto::Hasher;
use one_crypto::hasher::sha256::SHA256;
use serde_json::json;
use shared_types::{CredentialId, CredentialSchemaFormatId};
use similar_asserts::assert_eq;
use standardized_types::openid4vci::NotificationEvent;
use time::macros::format_description;
use uuid::Uuid;

use crate::fixtures::interaction::{IssuerInteractionDataParams, dummy_issuer_interaction_data};
use crate::fixtures::{
    ClaimData, TestingCredentialParams, TestingDidParams, TestingIdentifierParams,
};
use crate::utils::context::TestContext;
use crate::utils::db_clients::certificates::TestingCertificateParams;
use crate::utils::db_clients::interactions::TestingInteractionParams;
use crate::utils::db_clients::keys::eddsa_testing_params;
use crate::utils::db_clients::revocation_lists::TestingRevocationListParams;

#[tokio::test]
async fn test_post_notification_credential_accepted() {
    let (context, credential, credential_schema) = setup_accepted_credential().await;

    let resp = context
        .api
        .ssi
        .openid4vci_notification(
            credential_schema.id,
            "notification",
            NotificationEvent::CredentialAccepted,
        )
        .await;

    assert_eq!(204, resp.status());

    let credential = context.db.credentials.get(&credential.common().id).await;
    assert_eq!(credential.common().state, CredentialStateEnum::Accepted);
}

#[rstest::rstest]
#[case(None, "Wallet reported credential_failure")]
#[case(Some(""), "Wallet reported credential_failure")]
#[case(
    Some("Could not store credential"),
    "Wallet reported credential_failure: Could not store credential"
)]
#[tokio::test]
async fn test_post_notification_credential_failure(
    #[case] description: Option<&str>,
    #[case] expected_message: &str,
) {
    let (context, credential, credential_schema) = setup_accepted_credential().await;

    let resp = context
        .api
        .client
        .post(
            &format!(
                "/ssi/openid4vci/final-1.0/{}/notification",
                credential_schema.id
            ),
            json!({
                "notification_id": "notification",
                "event": "credential_failure",
                "event_description": description,
            }),
        )
        .await;

    assert_eq!(204, resp.status());

    let credential = context.db.credentials.get(&credential.common().id).await;
    assert_eq!(credential.common().state, CredentialStateEnum::Error);
    assert_error_history(&context, credential.common().id, expected_message).await;

    // Retrying the same notification must not create duplicate error events.
    let resp = context
        .api
        .ssi
        .openid4vci_notification(
            credential_schema.id,
            "notification",
            NotificationEvent::CredentialFailure,
        )
        .await;
    assert_eq!(204, resp.status());
    assert_error_history(&context, credential.common().id, expected_message).await;
}

async fn assert_error_history(context: &TestContext, credential_id: CredentialId, message: &str) {
    let history = context
        .db
        .histories
        .get_by_entity_id(&credential_id.into())
        .await;
    let errors: Vec<_> = history
        .values
        .into_iter()
        .filter(|entry| entry.action == HistoryAction::Errored)
        .collect();
    let_assert!([entry] = errors.as_slice());
    let_assert!(Some(HistoryMetadata::ErrorMetadata(error)) = &entry.metadata);
    assert_eq!(error.error_code, ErrorCode::BR_0048);
    assert_eq!(error.message, message);
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
            NotificationEvent::CredentialDeleted,
        )
        .await;

    assert_eq!(204, resp.status());

    let credential = context.db.credentials.get(&credential.common().id).await;
    assert_eq!(credential.common().state, CredentialStateEnum::Rejected);
}

struct MultiFormatBatch {
    context: TestContext,
    credential_schema: CredentialSchema,
    parent: Credential,
    sd_jwt_vc_format: CredentialSchemaFormat,
    mdoc_format: CredentialSchemaFormat,
}

/// Accepted BATCH_PARENT with one accepted batch item per issued format.
/// Notification ids: `n-sd-jwt-vc` and `n-mdoc`.
async fn setup_multi_format_batch(issued_formats: &[&str]) -> MultiFormatBatch {
    let interaction_id = Uuid::new_v4().into();
    let access_token = format!("{interaction_id}.test");
    let context = TestContext::new_with_token(&access_token, None).await;
    let organisation = context.db.organisations.create().await;
    let key = context
        .db
        .keys
        .create(&organisation, eddsa_testing_params())
        .await;
    let did = context
        .db
        .dids
        .create(
            organisation.clone(),
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::AssertionMethod,
                    key,
                    reference: "1".into(),
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
                did: Some(did),
                r#type: Some(IdentifierType::Did),
                ..Default::default()
            },
        )
        .await;

    let credential_schema_id = context
        .db
        .credential_schemas
        .create_with_multiformat("schema-1", &organisation, None)
        .await
        .unwrap();
    let credential_schema = context
        .db
        .credential_schemas
        .get(&credential_schema_id)
        .await;
    let formats = credential_schema.formats.as_ref().await.unwrap().to_owned();
    let format_by_name = |name: &str| {
        formats
            .iter()
            .find(|format| format.format.to_string() == name)
            .unwrap()
            .clone()
    };
    let sd_jwt_vc_format = format_by_name("SD_JWT_VC");
    let mdoc_format = format_by_name("MDOC");

    let interaction = context
        .db
        .interactions
        .create(
            &organisation,
            InteractionType::Issuance,
            TestingInteractionParams {
                id: Some(interaction_id),
                data: Some(dummy_issuer_interaction_data(
                    &access_token,
                    IssuerInteractionDataParams {
                        notification_ids: HashMap::from([
                            (sd_jwt_vc_format.id, "n-sd-jwt-vc".to_string()),
                            (mdoc_format.id, "n-mdoc".to_string()),
                        ]),
                        ..Default::default()
                    },
                )),
                ..Default::default()
            },
        )
        .await;

    let parent = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &issuer_identifier,
            "OPENID4VCI_FINAL1",
            TestingCredentialParams {
                interaction: Some(interaction),
                r#type: Some(CredentialType::BatchParent),
                ..Default::default()
            },
        )
        .await;

    for format in issued_formats {
        context
            .db
            .credentials
            .create(
                &credential_schema,
                CredentialStateEnum::Accepted,
                &issuer_identifier,
                "OPENID4VCI_FINAL1",
                TestingCredentialParams {
                    r#type: Some(CredentialType::BatchItem),
                    parent_id: Some(parent.common().id),
                    format: Some(format_by_name(format)),
                    ..Default::default()
                },
            )
            .await;
    }

    MultiFormatBatch {
        context,
        credential_schema,
        parent,
        sd_jwt_vc_format,
        mdoc_format,
    }
}

async fn batch_item_states(
    context: &TestContext,
    parent: &Credential,
) -> HashMap<CredentialSchemaFormatId, Vec<CredentialStateEnum>> {
    let mut states: HashMap<_, Vec<_>> = HashMap::new();
    for item in context
        .db
        .credentials
        .list(CredentialFilterValue::ParentCredential(parent.common().id).condition())
        .await
    {
        states
            .entry(item.format().unwrap().id())
            .or_default()
            .push(item.common().state);
    }
    states
}

#[rstest::rstest]
#[case(NotificationEvent::CredentialAccepted, CredentialStateEnum::Accepted)]
#[case(NotificationEvent::CredentialDeleted, CredentialStateEnum::Rejected)]
#[case(NotificationEvent::CredentialFailure, CredentialStateEnum::Error)]
#[tokio::test]
async fn test_post_notification_for_one_format_keeps_other_format(
    #[case] event: NotificationEvent,
    #[case] expected_state: CredentialStateEnum,
) {
    let MultiFormatBatch {
        context,
        credential_schema,
        parent,
        sd_jwt_vc_format,
        mdoc_format,
    } = setup_multi_format_batch(&["SD_JWT_VC", "MDOC"]).await;

    let resp = context
        .api
        .ssi
        .openid4vci_notification(credential_schema.id, "n-sd-jwt-vc", event)
        .await;
    assert_eq!(204, resp.status());

    let states = batch_item_states(&context, &parent).await;
    assert_eq!(states[&sd_jwt_vc_format.id], [expected_state]);
    assert_eq!(states[&mdoc_format.id], [CredentialStateEnum::Accepted]);
    let parent = context.db.credentials.get(&parent.common().id).await;
    assert_eq!(parent.common().state, CredentialStateEnum::Accepted);

    // Report the outcome for the remaining format, then retry it.
    for _ in 0..2 {
        let resp = context
            .api
            .ssi
            .openid4vci_notification(credential_schema.id, "n-mdoc", event)
            .await;
        assert_eq!(204, resp.status());
    }

    let states = batch_item_states(&context, &parent).await;
    assert_eq!(states[&mdoc_format.id], [expected_state]);
    let parent = context.db.credentials.get(&parent.common().id).await;
    assert_eq!(parent.common().state, expected_state);
    if event == NotificationEvent::CredentialFailure {
        assert_error_history(
            &context,
            parent.common().id,
            "Wallet reported credential_failure",
        )
        .await;
        let items = context
            .db
            .credentials
            .list(CredentialFilterValue::ParentCredential(parent.common().id).condition())
            .await;
        for item in items {
            assert_error_history(
                &context,
                item.common().id,
                "Wallet reported credential_failure",
            )
            .await;
        }
    }
}

#[rstest::rstest]
#[case(NotificationEvent::CredentialAccepted)]
#[case(NotificationEvent::CredentialDeleted)]
#[case(NotificationEvent::CredentialFailure)]
#[tokio::test]
async fn test_post_notification_rejects_format_without_items(
    #[case] event: NotificationEvent,
    #[values(false, true)] has_other_format: bool,
) {
    let MultiFormatBatch {
        context,
        credential_schema,
        parent,
        sd_jwt_vc_format,
        mdoc_format,
    } = setup_multi_format_batch(if has_other_format {
        &["SD_JWT_VC"]
    } else {
        &[]
    })
    .await;

    let resp = context
        .api
        .ssi
        .openid4vci_notification(credential_schema.id, "n-mdoc", event)
        .await;
    assert_eq!(400, resp.status());
    assert_eq!(
        resp.json_value().await["error"],
        "invalid_notification_request"
    );

    let states = batch_item_states(&context, &parent).await;
    assert!(!states.contains_key(&mdoc_format.id));
    assert_eq!(states.len(), usize::from(has_other_format));
    if has_other_format {
        assert_eq!(
            states[&sd_jwt_vc_format.id],
            [CredentialStateEnum::Accepted]
        );
    }
    let parent = context.db.credentials.get(&parent.common().id).await;
    assert_eq!(parent.common().state, CredentialStateEnum::Accepted);
    let history = context
        .db
        .histories
        .get_by_entity_id(&parent.common().id.into())
        .await;
    assert!(history.values.is_empty());
}

#[tokio::test]
async fn test_post_notification_unknown_notification_id() {
    let MultiFormatBatch {
        context,
        credential_schema,
        ..
    } = setup_multi_format_batch(&["SD_JWT_VC"]).await;

    let resp = context
        .api
        .ssi
        .openid4vci_notification(
            credential_schema.id,
            "unknown",
            NotificationEvent::CredentialDeleted,
        )
        .await;
    assert_eq!(400, resp.status());
}

async fn setup_accepted_credential() -> (TestContext, Credential, CredentialSchema) {
    let interaction_id = Uuid::new_v4().into();
    let access_token = format!("{interaction_id}.test");

    let context = TestContext::new_with_token(&access_token, None).await;

    let organisation = context.db.organisations.create().await;

    let key = context
        .db
        .keys
        .create(&organisation, eddsa_testing_params())
        .await;

    let issuer_identifier = context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                r#type: Some(IdentifierType::Certificate),
                ..Default::default()
            },
        )
        .await;

    let pem = r#"-----BEGIN CERTIFICATE-----
MIIDhzCCAyygAwIBAgIUahQKX8KQ86zDl0g9Wy3kW6oxFOQwCgYIKoZIzj0EAwIw
YjELMAkGA1UEBhMCQ0gxDzANBgNVBAcMBlp1cmljaDERMA8GA1UECgwIUHJvY2l2
aXMxETAPBgNVBAsMCFByb2NpdmlzMRwwGgYDVQQDDBNjYS5kZXYubWRsLXBsdXMu
Y29tMB4XDTI0MDUxNDA5MDAwMFoXDTI4MDIyOTAwMDAwMFowVTELMAkGA1UEBhMC
Q0gxDzANBgNVBAcMBlp1cmljaDEUMBIGA1UECgwLUHJvY2l2aXMgQUcxHzAdBgNV
BAMMFnRlc3QuZXMyNTYucHJvY2l2aXMuY2gwOTATBgcqhkjOPQIBBggqhkjOPQMB
BwMiAAJx38tO0JCdq3ZecMSW6a+BAAzllydQxVOQ+KDjnwLXJ6OCAeswggHnMA4G
A1UdDwEB/wQEAwIHgDAVBgNVHSUBAf8ECzAJBgcogYxdBQECMAwGA1UdEwEB/wQC
MAAwHwYDVR0jBBgwFoAU7RqwneJgRVAAO9paNDIamL4tt8UwWgYDVR0fBFMwUTBP
oE2gS4ZJaHR0cHM6Ly9jYS5kZXYubWRsLXBsdXMuY29tL2NybC80MENEMjI1NDdG
MzgzNEM1MjZDNUMyMkUxQTI2QzdFMjAzMzI0NjY4LzCByAYIKwYBBQUHAQEEgbsw
gbgwWgYIKwYBBQUHMAKGTmh0dHA6Ly9jYS5kZXYubWRsLXBsdXMuY29tL2lzc3Vl
ci80MENEMjI1NDdGMzgzNEM1MjZDNUMyMkUxQTI2QzdFMjAzMzI0NjY4LmRlcjBa
BggrBgEFBQcwAYZOaHR0cDovL2NhLmRldi5tZGwtcGx1cy5jb20vb2NzcC80MENE
MjI1NDdGMzgzNEM1MjZDNUMyMkUxQTI2QzdFMjAzMzI0NjY4L2NlcnQvMCYGA1Ud
EgQfMB2GG2h0dHBzOi8vY2EuZGV2Lm1kbC1wbHVzLmNvbTAhBgNVHREEGjAYghZ0
ZXN0LmVzMjU2LnByb2NpdmlzLmNoMB0GA1UdDgQWBBTGxO0mgPbDCn3/AoQxNFem
Fp40RTAKBggqhkjOPQQDAgNJADBGAiEAiRmxICo5Gxa4dlcK0qeyGDqyBOA9s/EI
1V1b4KfIsl0CIQCHu0eIGECUJIffrjmSc7P6YnQfxgocBUko7nra5E0Lhg==
-----END CERTIFICATE-----
"#;
    let certificate = context
        .db
        .certificates
        .create(
            issuer_identifier.id,
            organisation.clone(),
            TestingCertificateParams {
                key: Some(key.clone()),
                roles: Some(vec![CertificateRole::AssertionMethod]),
                chain: Some(pem.to_string()),
                ..Default::default()
            },
        )
        .await;

    let root_claim_id = Uuid::new_v4();
    let str_claim_id = Uuid::new_v4();
    let new_claim_schemas: Vec<(Uuid, &str, bool, &str, bool)> = vec![
        (root_claim_id, "root", true, "OBJECT", false),
        (str_claim_id, "root/str", true, "STRING", false),
    ];

    let credential_schema = context
        .db
        .credential_schemas
        .create_with_claims(
            &Uuid::new_v4(),
            "schema-1",
            &organisation,
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
        "access_token_expires_at": (one_core::clock::now_utc() + time::Duration::seconds(20)).format(&date_format).unwrap(),
        "notification_id": "notification"
    })).unwrap();

    let interaction = context
        .db
        .interactions
        .create(
            &organisation,
            InteractionType::Issuance,
            TestingInteractionParams {
                id: Some(interaction_id),
                data: Some(data),
                ..Default::default()
            },
        )
        .await;

    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &issuer_identifier,
            "OPENID4VCI_FINAL1",
            TestingCredentialParams {
                interaction: Some(interaction),
                issuer_certificate: Some(certificate.clone()),
                key: Some(key),
                claims_data: Some(vec![
                    ClaimData {
                        schema_id: root_claim_id.into(),
                        path: "root".to_string(),
                        value: None,
                        selectively_disclosable: false,
                    },
                    ClaimData {
                        schema_id: str_claim_id.into(),
                        path: "root/str".to_string(),
                        value: Some("str-value".to_string()),
                        selectively_disclosable: false,
                    },
                ]),
                ..Default::default()
            },
        )
        .await;

    let revocation_list = context
        .db
        .revocation_lists
        .create(
            issuer_identifier,
            Some(TestingRevocationListParams {
                issuer_certificate: Some(certificate),
                purpose: Some(RevocationListPurpose::Revocation),
                format: Some(StatusListCredentialFormat::Cwt),
                r#type: Some("MDOC_TOKENSTATUSLIST".into()),
                ..Default::default()
            }),
        )
        .await;

    context
        .db
        .revocation_lists
        .create_credential_entry(revocation_list.id, credential.common().id, 0)
        .await;

    (context, credential, credential_schema)
}
