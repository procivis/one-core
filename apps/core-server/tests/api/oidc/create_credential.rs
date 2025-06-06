use std::str::FromStr;

use one_core::model::credential::CredentialStateEnum;
use one_core::model::did::{DidType, KeyRole, RelatedKey};
use one_core::model::identifier::{Identifier, IdentifierType};
use one_core::model::interaction::InteractionId;
use one_core::model::key::Key;
use one_core::model::organisation::Organisation;
use one_core::model::revocation_list::{
    RevocationListPurpose, RevocationListRelations, StatusListType,
};
use one_core::model::validity_credential::ValidityCredentialType;
use one_crypto::Hasher;
use one_crypto::hasher::sha256::SHA256;
use serde_json::json;
use shared_types::{CredentialId, DidValue};
use time::OffsetDateTime;
use time::macros::format_description;
use uuid::Uuid;

use crate::api_oidc_tests::common::proof_jwt;
use crate::fixtures::{TestingCredentialParams, TestingDidParams, TestingIdentifierParams};
use crate::utils::context::TestContext;
use crate::utils::db_clients::credential_schemas::TestingCreateSchemaParams;
use crate::utils::db_clients::keys::eddsa_testing_params;

#[tokio::test]
async fn test_post_issuer_credential() {
    let params = PostCredentialTestParams {
        use_kid_in_proof: true,
        ..Default::default()
    };
    test_post_issuer_credential_with(params, None).await;
}

#[tokio::test]
async fn test_post_issuer_credential_sd_jwt_vc() {
    let params = PostCredentialTestParams {
        schema_id: Some("some-vct-value".to_string()),
        credential_format: Some("SD_JWT_VC".to_string()),
        format: Some("vc+sd-jwt"),
        ..Default::default()
    };
    test_post_issuer_credential_with(params, None).await;
}

#[tokio::test]
async fn test_post_issuer_credential_sd_jwt_vc_invalid_format() {
    let params = PostCredentialTestParams {
        schema_id: Some("some-vct-value".to_string()),
        credential_format: Some("SD_JWT_VC".to_string()),
        expect_failure: true,
        ..Default::default()
    };
    test_post_issuer_credential_with(params, None).await;
}

#[tokio::test]
async fn test_post_issuer_credential_jwk_proof() {
    test_post_issuer_credential_with(Default::default(), None).await;
}

#[tokio::test]
async fn test_post_issuer_credential_with_nonce() {
    let nonce = "pop_nonce1234";
    let params = PostCredentialTestParams {
        use_kid_in_proof: true,
        pop_nonce: Some(nonce),
        interaction_nonce: Some(nonce),
        ..Default::default()
    };
    test_post_issuer_credential_with(params, None).await;
}

#[tokio::test]
async fn test_post_issuer_credential_fail_missing_nonce() {
    let nonce = "pop_nonce1234";
    let params = PostCredentialTestParams {
        interaction_nonce: Some(nonce),
        expect_failure: true, // no nonce in proof
        ..Default::default()
    };
    test_post_issuer_credential_with(params, None).await;
}

#[tokio::test]
async fn test_post_issuer_credential_nonce_not_required() {
    let nonce = "pop_nonce1234";
    let params = PostCredentialTestParams {
        // Nonce is present but not asked for --> success
        // Simply adding additional unexpected claims to the proof jwt should not make the verification fail
        pop_nonce: Some(nonce),
        ..Default::default()
    };
    test_post_issuer_credential_with(params, None).await;
}

#[tokio::test]
async fn test_post_issuer_credential_jwk_proof_with_nonce() {
    let nonce = "pop_nonce1234";
    let params = PostCredentialTestParams {
        pop_nonce: Some(nonce),
        interaction_nonce: Some(nonce),
        ..Default::default()
    };
    test_post_issuer_credential_with(params, None).await;
}

#[tokio::test]
async fn test_post_issuer_credential_with_bitstring_revocation_method() {
    let params = PostCredentialTestParams {
        revocation_method: Some("BITSTRINGSTATUSLIST"),
        use_kid_in_proof: true,
        ..Default::default()
    };
    test_post_issuer_credential_with(params, None).await;
}

#[tokio::test]
async fn test_post_issuer_credential_with_bitstring_revocation_method_and_existing_token_status_list()
 {
    let issuer_setup = issuer_setup().await;
    issuer_setup
        .context
        .db
        .revocation_lists
        .create(
            issuer_setup.issuer_identifier.clone(),
            RevocationListPurpose::Revocation,
            None,
            Some(StatusListType::TokenStatusList),
        )
        .await;

    let issuer_identifier_id = issuer_setup.issuer_identifier.id;
    let params = PostCredentialTestParams {
        revocation_method: Some("BITSTRINGSTATUSLIST"),
        use_kid_in_proof: true,
        ..Default::default()
    };
    let (context, _) = test_post_issuer_credential_with(params, Some(issuer_setup)).await;

    assert_eq!(
        context
            .db
            .revocation_lists
            .get_revocation_by_issuer_identifier_id(
                issuer_identifier_id,
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
            .get_revocation_by_issuer_identifier_id(
                issuer_identifier_id,
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
            .get_revocation_by_issuer_identifier_id(
                issuer_identifier_id,
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
    let params = PostCredentialTestParams {
        revocation_method: Some("LVVC"),
        use_kid_in_proof: true,
        ..Default::default()
    };
    let (context, credential_id) = test_post_issuer_credential_with(params, None).await;

    let lvvcs = context
        .db
        .validity_credentials
        .get_all_by_credential_id(credential_id, ValidityCredentialType::Lvvc)
        .await;

    assert_eq!(1, lvvcs.len());
    assert_eq!(credential_id, lvvcs[0].linked_credential_id);
}

struct TestIssuerSetup {
    interaction_id: InteractionId,
    access_token: String,
    context: TestContext,
    organisation: Organisation,
    key: Key,
    issuer_identifier: Identifier,
}

async fn issuer_setup() -> TestIssuerSetup {
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
                did: Some(
                    DidValue::from_str("did:key:z6MkuJnXWiLNmV3SooQ72iDYmUE1sz5HTCXWhKNhDZuqk4Rj")
                        .unwrap(),
                ),
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
    TestIssuerSetup {
        interaction_id,
        access_token,
        context,
        organisation,
        key,
        issuer_identifier,
    }
}

#[derive(Default)]
struct PostCredentialTestParams<'a> {
    revocation_method: Option<&'a str>,
    use_kid_in_proof: bool,
    interaction_nonce: Option<&'a str>,
    pop_nonce: Option<&'a str>,
    expect_failure: bool,
    schema_id: Option<String>,
    credential_format: Option<String>,
    format: Option<&'a str>,
}

async fn test_post_issuer_credential_with(
    test_params: PostCredentialTestParams<'_>,
    context: Option<TestIssuerSetup>,
) -> (TestContext, CredentialId) {
    let TestIssuerSetup {
        interaction_id,
        access_token,
        organisation,
        context,
        key,
        issuer_identifier,
        ..
    } = match context {
        None => issuer_setup().await,
        Some(context) => context,
    };

    let PostCredentialTestParams {
        revocation_method,
        use_kid_in_proof,
        interaction_nonce,
        pop_nonce,
        expect_failure,
        schema_id,
        credential_format,
        format,
    } = test_params;

    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "schema-1",
            &organisation,
            revocation_method.unwrap_or("NONE"),
            TestingCreateSchemaParams {
                format: credential_format,
                schema_id: schema_id.clone(),
                ..Default::default()
            },
        )
        .await;

    let date_format =
        format_description!("[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond]Z");
    let mut interaction_data = json!({
        "pre_authorized_code_used": true,
        "access_token_hash": SHA256.hash(access_token.as_bytes()).unwrap(),
        "access_token_expires_at": (OffsetDateTime::now_utc() + time::Duration::seconds(20)).format(&date_format).unwrap(),
    });

    if let Some(interaction_nonce) = interaction_nonce {
        interaction_data["nonce"] = interaction_nonce.into();
    }

    let base_url = &context.config.app.core_base_url;
    let interaction = context
        .db
        .interactions
        .create(
            Some(interaction_id),
            base_url,
            &serde_json::to_vec(&interaction_data).unwrap(),
            &organisation,
        )
        .await;

    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Offered,
            &issuer_identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                interaction: Some(interaction),
                key: Some(key),
                ..Default::default()
            },
        )
        .await;

    let jwt = proof_jwt(use_kid_in_proof, pop_nonce).await;
    let resp = context
        .api
        .ssi
        .issuer_create_credential(
            credential_schema.id,
            format.unwrap_or("jwt_vc_json"),
            &jwt,
            schema_id.as_deref(),
        )
        .await;

    if expect_failure {
        assert_eq!(400, resp.status());
    } else {
        assert_eq!(200, resp.status());
        let credential_history = context
            .db
            .histories
            .get_by_entity_id(&credential.id.into())
            .await;
        let credential = context.db.credentials.get(&credential.id).await;
        assert_eq!(
            credential_history
                .values
                .first()
                .as_ref()
                .unwrap()
                .target
                .as_ref()
                .unwrap(),
            &credential.holder_identifier.unwrap().id.to_string()
        );
    }

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
            Some(organisation.clone()),
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
            &issuer_identifier,
            "OPENID4VCI_DRAFT13",
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

    let jwt = proof_jwt(true, None).await;
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
