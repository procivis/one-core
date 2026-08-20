use one_core::model::certificate::CertificateRole;
use one_core::model::credential::{Credential, CredentialStateEnum};
use one_core::model::credential_schema::CredentialSchema;
use one_core::model::identifier::IdentifierType;
use one_core::model::interaction::InteractionType;
use one_core::model::revocation_list::{RevocationListPurpose, StatusListCredentialFormat};
use one_crypto::Hasher;
use one_crypto::hasher::sha256::SHA256;
use serde_json::json;
use similar_asserts::assert_eq;
use standardized_types::openid4vci::NotificationEvent;
use time::macros::format_description;
use uuid::Uuid;

use crate::fixtures::{ClaimData, TestingCredentialParams, TestingIdentifierParams};
use crate::utils::context::TestContext;
use crate::utils::db_clients::certificates::TestingCertificateParams;
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
            NotificationEvent::CredentialFailure,
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
            NotificationEvent::CredentialDeleted,
        )
        .await;

    assert_eq!(204, resp.status());

    let credential = context.db.credentials.get(&credential.id).await;
    assert_eq!(credential.state, CredentialStateEnum::Rejected);
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
            Some(interaction_id),
            &data,
            &organisation,
            InteractionType::Issuance,
            None,
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
        .create_credential_entry(revocation_list.id, credential.id, 0)
        .await;

    (context, credential, credential_schema)
}
