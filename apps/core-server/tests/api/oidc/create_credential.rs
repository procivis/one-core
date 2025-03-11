use std::str::FromStr;

use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
use one_core::model::credential::CredentialStateEnum;
use one_core::model::did::{Did, KeyRole, RelatedKey};
use one_core::model::interaction::InteractionId;
use one_core::model::key::Key;
use one_core::model::organisation::Organisation;
use one_core::model::revocation_list::{
    RevocationListPurpose, RevocationListRelations, StatusListType,
};
use one_core::model::validity_credential::ValidityCredentialType;
use one_crypto::hasher::sha256::SHA256;
use one_crypto::Hasher;
use serde_json::json;
use shared_types::{CredentialId, DidValue};
use time::macros::format_description;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::fixtures::{TestingCredentialParams, TestingDidParams};
use crate::utils::context::TestContext;
use crate::utils::db_clients::keys::eddsa_testing_params;

#[tokio::test]
async fn test_post_issuer_credential() {
    test_post_issuer_credential_with("NONE", None).await;
}

#[tokio::test]
async fn test_post_issuer_credential_with_bitstring_revocation_method() {
    test_post_issuer_credential_with("BITSTRINGSTATUSLIST", None).await;
}

#[tokio::test]
async fn test_post_issuer_credential_with_bitstring_revocation_method_and_existing_token_status_list(
) {
    let params = issuer_setup().await;
    params
        .context
        .db
        .revocation_lists
        .create(
            &params.issuer_did,
            RevocationListPurpose::Revocation,
            None,
            Some(StatusListType::TokenStatusList),
        )
        .await;

    let issuer_did_id = params.issuer_did.id;
    let (context, _) = test_post_issuer_credential_with("BITSTRINGSTATUSLIST", Some(params)).await;

    assert_eq!(
        context
            .db
            .revocation_lists
            .get_revocation_by_issuer_did_id(
                &issuer_did_id,
                RevocationListPurpose::Revocation,
                StatusListType::BitstringStatusList,
                &RevocationListRelations::default()
            )
            .await
            .unwrap()
            .r#type,
        StatusListType::BitstringStatusList
    );
    assert_eq!(
        context
            .db
            .revocation_lists
            .get_revocation_by_issuer_did_id(
                &issuer_did_id,
                RevocationListPurpose::Suspension,
                StatusListType::BitstringStatusList,
                &RevocationListRelations::default()
            )
            .await
            .unwrap()
            .r#type,
        StatusListType::BitstringStatusList
    );
    assert_eq!(
        context
            .db
            .revocation_lists
            .get_revocation_by_issuer_did_id(
                &issuer_did_id,
                RevocationListPurpose::Revocation,
                StatusListType::TokenStatusList,
                &RevocationListRelations::default()
            )
            .await
            .unwrap()
            .r#type,
        StatusListType::TokenStatusList
    );
}

#[tokio::test]
async fn test_post_issuer_credential_with_lvvc_revocation_method() {
    let (context, credential_id) = test_post_issuer_credential_with("LVVC", None).await;

    let lvvcs = context
        .db
        .validity_credentials
        .get_all_by_credential_id(credential_id, ValidityCredentialType::Lvvc)
        .await;

    assert_eq!(1, lvvcs.len());
    assert_eq!(credential_id, lvvcs[0].linked_credential_id);
}

struct TestPostIssuerCredentialParams {
    interaction_id: InteractionId,
    access_token: String,
    context: TestContext,
    organisation: Organisation,
    key: Key,
    issuer_did: Did,
}

async fn issuer_setup() -> TestPostIssuerCredentialParams {
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
            &organisation,
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::AssertionMethod,
                    key: key.clone(),
                }]),
                did: Some(
                    DidValue::from_str("did:key:z6MkuJnXWiLNmV3SooQ72iDYmUE1sz5HTCXWhKNhDZuqk4Rj")
                        .unwrap(),
                ),
                ..Default::default()
            },
        )
        .await;
    TestPostIssuerCredentialParams {
        interaction_id,
        access_token,
        context,
        organisation,
        key,
        issuer_did,
    }
}

async fn test_post_issuer_credential_with(
    revocation_method: &str,
    context: Option<TestPostIssuerCredentialParams>,
) -> (TestContext, CredentialId) {
    let TestPostIssuerCredentialParams {
        interaction_id,
        access_token,
        organisation,
        context,
        key,
        issuer_did,
    } = match context {
        None => issuer_setup().await,
        Some(context) => context,
    };

    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "schema-1",
            &organisation,
            revocation_method,
            Default::default(),
        )
        .await;

    let date_format =
        format_description!("[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond]Z");
    let data = serde_json::to_vec(&json!({
        "pre_authorized_code_used": true,
        "access_token_hash": SHA256.hash(access_token.as_bytes()).unwrap(),
        "access_token_expires_at": (OffsetDateTime::now_utc() + time::Duration::seconds(20)).format(&date_format).unwrap(),
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
            CredentialStateEnum::Offered,
            &issuer_did,
            "OPENID4VC",
            TestingCredentialParams {
                interaction: Some(interaction),
                key: Some(key),
                ..Default::default()
            },
        )
        .await;

    let jwt = [
        r#"{"alg":"EDDSA","typ":"JWT","kid":"did:key:20927216-8144-474C-B249-0C048D2BFD51"}"#,
        r#"{"aud":"test"}"#,
        "MissingSignature",
    ]
    .map(|s| Base64UrlSafeNoPadding::encode_to_string(s).unwrap())
    .join(".");

    let resp = context
        .api
        .ssi
        .issuer_create_credential(credential_schema.id, "jwt_vc_json", &jwt)
        .await;

    assert_eq!(200, resp.status());

    (context, credential.id)
}

#[tokio::test]
async fn test_post_issuer_credential_mdoc() {
    let interaction_id = Uuid::new_v4();
    let access_token = format!("{interaction_id}.test");

    let context = TestContext::new_with_token(&access_token, None).await;

    let organisation = context.db.organisations.create().await;

    let key = context
        .db
        .keys
        .create(&organisation, eddsa_testing_params())
        .await;

    let did = "did:mdl:certificate:MIIDYTCCAwegAwIBAgIUOfrQW7V3t1Df5wF54HMja4jXSiowCgYIKoZIzj0EAwIwYjELMAkGA1UEBhMCQ0gxDzANBgNVBAcMBlp1cmljaDERMA8GA1UECgwIUHJvY2l2aXMxETAPBgNVBAsMCFByb2NpdmlzMRwwGgYDVQQDDBNjYS5kZXYubWRsLXBsdXMuY29tMB4XDTI0MDUxNDA3MjcwMFoXDTI0MDgxMjAwMDAwMFowSjELMAkGA1UEBhMCQ0gxDzANBgNVBAcMBlp1cmljaDEUMBIGA1UECgwLUHJvY2l2aXMgQUcxFDASBgNVBAMMC3Byb2NpdmlzLmNoMCowBQYDK2VwAyEA3LOKxB5ik9WikgQmqNFtmuvNC0FMFFVXr6ATVoL-kT6jggHgMIIB3DAOBgNVHQ8BAf8EBAMCB4AwFQYDVR0lAQH_BAswCQYHKIGMXQUBAjAMBgNVHRMBAf8EAjAAMB8GA1UdIwQYMBaAFO0asJ3iYEVQADvaWjQyGpi-LbfFMFoGA1UdHwRTMFEwT6BNoEuGSWh0dHBzOi8vY2EuZGV2Lm1kbC1wbHVzLmNvbS9jcmwvNDBDRDIyNTQ3RjM4MzRDNTI2QzVDMjJFMUEyNkM3RTIwMzMyNDY2OC8wgcgGCCsGAQUFBwEBBIG7MIG4MFoGCCsGAQUFBzAChk5odHRwOi8vY2EuZGV2Lm1kbC1wbHVzLmNvbS9pc3N1ZXIvNDBDRDIyNTQ3RjM4MzRDNTI2QzVDMjJFMUEyNkM3RTIwMzMyNDY2OC5kZXIwWgYIKwYBBQUHMAGGTmh0dHA6Ly9jYS5kZXYubWRsLXBsdXMuY29tL29jc3AvNDBDRDIyNTQ3RjM4MzRDNTI2QzVDMjJFMUEyNkM3RTIwMzMyNDY2OC9jZXJ0LzAmBgNVHRIEHzAdhhtodHRwczovL2NhLmRldi5tZGwtcGx1cy5jb20wFgYDVR0RBA8wDYILcHJvY2l2aXMuY2gwHQYDVR0OBBYEFKz7jJBlcj4WlpOgMzjKwilDZ_ogMAoGCCqGSM49BAMCA0gAMEUCIDj2w5vOQacNAfIdHmfqlsn0nBpBlbBdC784VT0lqA1FAiEAtCGKf9Pd6dOyz6ke30fFb-YfKaOmbDngZ3dlZIh4dvg";
    let issuer_did = context
        .db
        .dids
        .create(
            &organisation,
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::AssertionMethod,
                    key: key.clone(),
                }]),
                did: Some(did.parse().unwrap()),
                ..Default::default()
            },
        )
        .await;

    let str_claim_id = Uuid::new_v4();
    let num_claim_id = Uuid::new_v4();
    let bool_claim_id = Uuid::new_v4();
    let new_claim_schemas: Vec<(Uuid, &str, bool, &str, bool)> = vec![
        (Uuid::new_v4(), "root", true, "OBJECT", false),
        (str_claim_id, "root/str", true, "STRING", false),
        (num_claim_id, "root/num", true, "NUMBER", false),
        (bool_claim_id, "root/bool", true, "BOOLEAN", false),
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
            CredentialStateEnum::Offered,
            &issuer_did,
            "OPENID4VC",
            TestingCredentialParams {
                interaction: Some(interaction),
                key: Some(key),
                claims_data: Some(vec![
                    (str_claim_id, "root/str", "str-value"),
                    (num_claim_id, "root/num", "12"),
                    (bool_claim_id, "root/bool", "false"),
                ]),
                ..Default::default()
            },
        )
        .await;

    let jwt = [
        r#"{"alg":"EDDSA","typ":"JWT","kid":"did:key:z6MkuJnXWiLNmV3SooQ72iDYmUE1sz5HTCXWhKNhDZuqk4Rj"}"#,
        r#"{"aud":"test"}"#,
        "MissingSignature",
    ]
    .map(|s| Base64UrlSafeNoPadding::encode_to_string(s).unwrap())
    .join(".");

    let resp = context
        .api
        .ssi
        .issuer_create_credential_mdoc(credential_schema.id, &credential_schema.schema_id, &jwt)
        .await;

    assert_eq!(200, resp.status());

    let credentials = context
        .db
        .validity_credentials
        .get_all_by_credential_id(credential.id, ValidityCredentialType::Mdoc)
        .await;
    assert_eq!(credential.id, credentials[0].linked_credential_id);
}
