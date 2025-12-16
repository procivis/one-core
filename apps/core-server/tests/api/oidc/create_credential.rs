use std::ops::Add;
use std::str::FromStr;

use futures::future::join_all;
use one_core::model::certificate::{Certificate, CertificateState};
use one_core::model::credential::CredentialStateEnum;
use one_core::model::did::{DidType, KeyRole, RelatedKey};
use one_core::model::identifier::{Identifier, IdentifierType};
use one_core::model::interaction::{InteractionId, InteractionType};
use one_core::model::key::Key;
use one_core::model::organisation::Organisation;
use one_core::model::revocation_list::{
    RevocationListPurpose, RevocationListRelations, StatusListType,
};
use one_core::model::validity_credential::ValidityCredentialType;
use one_core::provider::key_algorithm::KeyAlgorithm;
use one_core::provider::key_algorithm::eddsa::Eddsa;
use one_crypto::Hasher;
use one_crypto::hasher::sha256::SHA256;
use serde_json::json;
use shared_types::{CredentialId, DidValue};
use similar_asserts::assert_eq;
use time::macros::format_description;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::api_oidc_tests::common::{proof_jwt, proof_jwt_for};
use crate::fixtures::{
    ClaimData, TestingCredentialParams, TestingDidParams, TestingIdentifierParams,
};
use crate::utils::api_clients::Client;
use crate::utils::context::TestContext;
use crate::utils::db_clients::certificates::TestingCertificateParams;
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
async fn test_post_issuer_credential_in_parallel() {
    let params = PostCredentialTestParams {
        use_kid_in_proof: true,
        schema_id: Some("some-schema-id".to_string()),
        ..Default::default()
    };
    let TestIssuerSetup {
        interaction_id,
        access_token,
        organisation,
        context,
        key,
        issuer_identifier,
        ..
    } = issuer_setup(None).await;

    let PostCredentialTestParams {
        revocation_method,
        use_kid_in_proof,
        schema_id,
        credential_format,
        ..
    } = params;

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
                key_storage_security: None,
                ..Default::default()
            },
        )
        .await;

    let date_format =
        format_description!("[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond]Z");
    let interaction_data = json!({
        "pre_authorized_code_used": true,
        "access_token_hash": SHA256.hash(access_token.as_bytes()).unwrap(),
        "access_token_expires_at": (OffsetDateTime::now_utc() + time::Duration::seconds(20)).format(&date_format).unwrap(),
    });

    let interaction = context
        .db
        .interactions
        .create(
            Some(interaction_id),
            &serde_json::to_vec(&interaction_data).unwrap(),
            &organisation,
            InteractionType::Issuance,
        )
        .await;

    context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Offered,
            &issuer_identifier,
            "OPENID4VCI_FINAL1",
            TestingCredentialParams {
                interaction: Some(interaction),
                key: Some(key),
                ..Default::default()
            },
        )
        .await;

    let value = context
        .api
        .ssi
        .generate_nonce("OPENID4VCI_FINAL1")
        .await
        .json_value()
        .await;
    let nonce = value["c_nonce"].as_str().unwrap();
    let jwt = proof_jwt(use_kid_in_proof, Some(nonce)).await;
    let mut multiple_attempts = vec![];
    let num_credentials = 10;
    for _ in 0..num_credentials {
        multiple_attempts.push(context.api.ssi.issuer_create_credential_vci_final(
            credential_schema.id,
            schema_id.as_ref().unwrap(),
            &jwt,
        ));
    }
    let results = join_all(multiple_attempts).await;
    // one attempt must succeed
    let num_successful = results.iter().filter(|resp| resp.status() == 200).count();
    assert_eq!(num_successful, 1);
    // one attempt must fail
    let num_failed = results.iter().filter(|resp| resp.status() == 400).count();
    assert_eq!(num_failed, num_credentials - 1);
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
async fn test_post_issuer_credential_with_bitstring_in_parallel() {
    let TestIssuerSetup {
        organisation,
        context,
        key,
        issuer_identifier,
        ..
    } = issuer_setup(None).await;

    let schema_id = "schema-id".to_string();
    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "schema-1",
            &organisation,
            "BITSTRINGSTATUSLIST",
            TestingCreateSchemaParams {
                schema_id: Some(schema_id.clone()),
                ..Default::default()
            },
        )
        .await;

    let date_format =
        format_description!("[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond]Z");

    let mut issuances = vec![];
    const NUM_CREDENTIALS: usize = 10;
    for _ in 0..NUM_CREDENTIALS {
        let schema_id = schema_id.clone();
        let interaction_id = Uuid::new_v4();
        let access_token = format!("{interaction_id}.test");
        let interaction_data = json!({
            "pre_authorized_code_used": true,
            "access_token_hash": SHA256.hash(access_token.as_bytes()).unwrap(),
            "access_token_expires_at": (OffsetDateTime::now_utc() + time::Duration::seconds(20)).format(&date_format).unwrap(),
        });

        let interaction = context
            .db
            .interactions
            .create(
                Some(interaction_id),
                &serde_json::to_vec(&interaction_data).unwrap(),
                &organisation,
                InteractionType::Issuance,
            )
            .await;

        context
            .db
            .credentials
            .create(
                &credential_schema,
                CredentialStateEnum::Offered,
                &issuer_identifier,
                "OPENID4VCI_FINAL1",
                TestingCredentialParams {
                    interaction: Some(interaction),
                    key: Some(key.clone()),
                    ..Default::default()
                },
            )
            .await;

        let value = context
            .api
            .ssi
            .generate_nonce("OPENID4VCI_FINAL1")
            .await
            .json_value()
            .await;
        let nonce = value["c_nonce"].as_str().unwrap();
        let key = Eddsa.generate_key().unwrap();
        let jwt = proof_jwt_for(&key.key, "EdDSA".to_string(), None, Some(nonce)).await;
        let api = Client::new(context.api.base_url.clone(), access_token);

        issuances.push(async move {
            api.ssi
                .issuer_create_credential_vci_final(credential_schema.id, &schema_id, &jwt)
                .await
        });
    }

    let responses = join_all(issuances).await;
    for response in responses {
        assert_eq!(200, response.status());
    }

    let list = context
        .db
        .revocation_lists
        .get_revocation_by_issuer_identifier_id(
            issuer_identifier.id,
            RevocationListPurpose::Revocation,
            StatusListType::BitstringStatusList,
            &Default::default(),
        )
        .await
        .unwrap();

    let entries = context.db.revocation_lists.get_entries(list.id).await;
    assert_eq!(entries.len(), NUM_CREDENTIALS);
}

#[tokio::test]
async fn test_post_issuer_credential_with_tokenstatuslist_in_parallel() {
    let TestIssuerSetup {
        organisation,
        context,
        key,
        issuer_identifier,
        ..
    } = issuer_setup(None).await;

    let schema_id = "schema-id".to_string();
    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "schema-1",
            &organisation,
            "TOKENSTATUSLIST",
            TestingCreateSchemaParams {
                format: Some("SD_JWT_VC".to_string()),
                schema_id: Some(schema_id.clone()),
                ..Default::default()
            },
        )
        .await;

    let date_format =
        format_description!("[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond]Z");

    let mut issuances = vec![];
    const NUM_CREDENTIALS: usize = 10;
    for _ in 0..NUM_CREDENTIALS {
        let schema_id = schema_id.clone();
        let interaction_id = Uuid::new_v4();
        let access_token = format!("{interaction_id}.test");
        let interaction_data = json!({
            "pre_authorized_code_used": true,
            "access_token_hash": SHA256.hash(access_token.as_bytes()).unwrap(),
            "access_token_expires_at": (OffsetDateTime::now_utc() + time::Duration::seconds(20)).format(&date_format).unwrap(),
        });

        let interaction = context
            .db
            .interactions
            .create(
                Some(interaction_id),
                &serde_json::to_vec(&interaction_data).unwrap(),
                &organisation,
                InteractionType::Issuance,
            )
            .await;

        context
            .db
            .credentials
            .create(
                &credential_schema,
                CredentialStateEnum::Offered,
                &issuer_identifier,
                "OPENID4VCI_FINAL1",
                TestingCredentialParams {
                    interaction: Some(interaction),
                    key: Some(key.clone()),
                    ..Default::default()
                },
            )
            .await;

        let value = context
            .api
            .ssi
            .generate_nonce("OPENID4VCI_FINAL1")
            .await
            .json_value()
            .await;
        let nonce = value["c_nonce"].as_str().unwrap();
        let key = Eddsa.generate_key().unwrap();
        let jwt = proof_jwt_for(&key.key, "EdDSA".to_string(), None, Some(nonce)).await;
        let api = Client::new(context.api.base_url.clone(), access_token);

        issuances.push(async move {
            api.ssi
                .issuer_create_credential_vci_final(credential_schema.id, &schema_id, &jwt)
                .await
        });
    }

    let responses = join_all(issuances).await;
    for response in responses {
        assert_eq!(200, response.status());
    }

    let list = context
        .db
        .revocation_lists
        .get_revocation_by_issuer_identifier_id(
            issuer_identifier.id,
            RevocationListPurpose::RevocationAndSuspension,
            StatusListType::TokenStatusList,
            &Default::default(),
        )
        .await
        .unwrap();

    let entries = context.db.revocation_lists.get_entries(list.id).await;
    assert_eq!(entries.len(), NUM_CREDENTIALS);
}

#[tokio::test]
async fn test_post_issuer_credential_with_bitstring_revocation_method_and_existing_token_status_list()
 {
    let issuer_setup = issuer_setup(None).await;
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
async fn test_post_issuer_credential_with_disabled_issuer_key_storage() {
    let disabled_key_storage = Some(
        indoc::indoc! {"
        keyStorage:
            INTERNAL:
                enabled: false
        "}
        .to_string(),
    );
    let issuer_setup = issuer_setup(disabled_key_storage).await;
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
    test_post_issuer_credential_with(PostCredentialTestParams::default(), Some(issuer_setup)).await;
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

async fn issuer_setup(additional_config: Option<String>) -> TestIssuerSetup {
    let interaction_id = Uuid::new_v4();
    let access_token = format!("{interaction_id}.test");
    let context = TestContext::new_with_token(&access_token, additional_config).await;

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
                    reference: "1".to_string(),
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
        None => issuer_setup(None).await,
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

    let interaction = context
        .db
        .interactions
        .create(
            Some(interaction_id),
            &serde_json::to_vec(&interaction_data).unwrap(),
            &organisation,
            InteractionType::Issuance,
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
        assert!(credential.issuance_date.is_some());
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

    let identifier_id = Uuid::new_v4().into();
    let now = OffsetDateTime::now_utc();

    let certificate_model = Certificate {
        id: Uuid::new_v4().into(),
        identifier_id,
        organisation_id: Some(organisation.id),
        created_date: now,
        last_modified: now,
        expiry_date: now.add(Duration::minutes(10)),
        name: "test cert".to_string(),
        chain: r#"-----BEGIN CERTIFICATE-----
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
"#
        .to_string(),
        fingerprint: "fingerprint".to_string(),
        state: CertificateState::Active,
        key: Some(key.clone()),
    };

    let issuer_identifier = context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                id: Some(identifier_id),
                r#type: Some(IdentifierType::Certificate),
                certificates: Some(vec![certificate_model.clone()]),
                ..Default::default()
            },
        )
        .await;

    let _issuer_certificate = context
        .db
        .certificates
        .create(
            issuer_identifier.id,
            TestingCertificateParams::from(certificate_model),
        )
        .await;

    let root_claim_id = Uuid::new_v4();
    let str_claim_id = Uuid::new_v4();
    let num_claim_id = Uuid::new_v4();
    let bool_claim_id = Uuid::new_v4();
    let new_claim_schemas: Vec<(Uuid, &str, bool, &str, bool)> = vec![
        (root_claim_id, "root", true, "OBJECT", false),
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

    let interaction = context
        .db
        .interactions
        .create(
            Some(interaction_id),
            &data,
            &organisation,
            InteractionType::Issuance,
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
                    ClaimData {
                        schema_id: num_claim_id.into(),
                        path: "root/num".to_string(),
                        value: Some("12".to_string()),
                        selectively_disclosable: false,
                    },
                    ClaimData {
                        schema_id: bool_claim_id.into(),
                        path: "root/bool".to_string(),
                        value: Some("false".to_string()),
                        selectively_disclosable: false,
                    },
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
