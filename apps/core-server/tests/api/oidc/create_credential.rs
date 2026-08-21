use std::ops::Add;
use std::str::FromStr;

use ct_codecs::{Base64UrlSafeNoPadding, Decoder};
use futures::future::join_all;
use maplit::hashmap;
use one_core::model::certificate::{Certificate, CertificateState};
use one_core::model::credential::{CredentialStateEnum, CredentialType, UpdateCredentialRequest};
use one_core::model::credential_schema::CredentialSchema;
use one_core::model::did::{DidType, KeyRole, RelatedKey};
use one_core::model::identifier::{Identifier, IdentifierType};
use one_core::model::interaction::InteractionType;
use one_core::model::key::Key;
use one_core::model::organisation::Organisation;
use one_core::model::revocation_list::RevocationListPurpose;
use one_core::proto::jwt::Jwt;
use one_core::provider::key_algorithm::KeyAlgorithm;
use one_core::provider::key_algorithm::eddsa::Eddsa;
use one_crypto::Hasher;
use one_crypto::hasher::sha256::SHA256;
use serde_json::json;
use shared_types::{CredentialFormat, CredentialId, DidValue, InteractionId};
use similar_asserts::assert_eq;
use time::format_description::well_known::Rfc3339;
use time::macros::format_description;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::api_oidc_tests::common::{proof_jwt, proof_jwt_for};
use crate::fixtures::interaction::{IssuerInteractionDataParams, dummy_issuer_interaction_data};
use crate::fixtures::{
    ClaimData, TestingCredentialParams, TestingDidParams, TestingIdentifierParams,
};
use crate::utils::api_clients::Client;
use crate::utils::context::TestContext;
use crate::utils::db_clients::certificates::TestingCertificateParams;
use crate::utils::db_clients::credential_schemas::TestingCreateSchemaParams;
use crate::utils::db_clients::interactions::TestingInteractionParams;
use crate::utils::db_clients::keys::eddsa_testing_params;
use crate::utils::db_clients::revocation_lists::TestingRevocationListParams;
use crate::utils::field_match::FieldHelpers;

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
        credential_format: Some("SD_JWT_VC".into()),
        ..Default::default()
    };
    test_post_issuer_credential_with(params, None).await;
}

#[tokio::test]
async fn test_post_issuer_credential_jwk_proof() {
    let params = PostCredentialTestParams {
        credential_format: Some("SD_JWT_VC".into()),
        use_kid_in_proof: false,
        ..Default::default()
    };
    test_post_issuer_credential_with(params, None).await;
}

#[tokio::test]
async fn test_post_issuer_credential_in_parallel() {
    let params = PostCredentialTestParams {
        use_kid_in_proof: true,
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
        use_kid_in_proof,
        credential_format,
        ..
    } = params;

    let schema_id = "test_schema_id".to_string();
    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "schema-1",
            &organisation,
            TestingCreateSchemaParams {
                format: credential_format,
                schema_id: Some(schema_id.clone()),
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
        "access_token_expires_at": (one_core::clock::now_utc() + time::Duration::seconds(20)).format(&date_format).unwrap(),
    });

    let interaction = context
        .db
        .interactions
        .create(
            &organisation,
            InteractionType::Issuance,
            TestingInteractionParams {
                id: Some(interaction_id),
                data: Some(serde_json::to_vec(&interaction_data).unwrap()),
                ..Default::default()
            },
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
        multiple_attempts.push(context.api.ssi.issuer_create_credential(
            credential_schema.id,
            &schema_id,
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
    let params = PostCredentialTestParams {
        expect_failure: true,
        nonce_mode: NonceMode::Missing,
        ..Default::default()
    };
    test_post_issuer_credential_with(params, None).await;
}

#[tokio::test]
async fn test_post_issuer_credential_fail_invalid_nonce() {
    let params = PostCredentialTestParams {
        expect_failure: true,
        nonce_mode: NonceMode::Invalid,
        ..Default::default()
    };
    test_post_issuer_credential_with(params, None).await;
}

#[tokio::test]
async fn test_post_issuer_credential_fail_expired_access_token() {
    let params = PostCredentialTestParams {
        expect_failure: true,
        access_token_expired: true,
        ..Default::default()
    };
    test_post_issuer_credential_with(params, None).await;
}

#[tokio::test]
async fn test_post_issuer_credential_fails_when_credential_expired() {
    // an issuer-side credential (the batch parent, for a batch/MDOC schema, or the credential
    // itself otherwise) that has already expired must not be usable to issue a (further)
    // credential from - `create_credential` rejects it upfront instead of minting a new batch
    // item under an already-expired parent
    let TestIssuerSetup {
        interaction_id,
        access_token,
        organisation,
        context,
        key,
        issuer_identifier,
        ..
    } = issuer_setup(None).await;

    let schema_id = "test-schema-id".to_string();
    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "schema-1",
            &organisation,
            TestingCreateSchemaParams {
                schema_id: Some(schema_id.clone()),
                ..Default::default()
            },
        )
        .await;

    let interaction_data =
        dummy_issuer_interaction_data(&access_token, IssuerInteractionDataParams::default());
    let interaction = context
        .db
        .interactions
        .create(
            &organisation,
            InteractionType::Issuance,
            TestingInteractionParams {
                id: Some(interaction_id),
                data: Some(interaction_data),
                ..Default::default()
            },
        )
        .await;

    let credential = context
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
                expires_at: Some(one_core::clock::now_utc() - Duration::seconds(1)),
                ..Default::default()
            },
        )
        .await;

    let nonce = context
        .api
        .ssi
        .generate_nonce("OPENID4VCI_FINAL1")
        .await
        .json_value()
        .await["c_nonce"]
        .as_str()
        .unwrap()
        .to_string();
    let jwt = proof_jwt(true, Some(&nonce)).await;

    // WHEN
    let resp = context
        .api
        .ssi
        .issuer_create_credential(credential_schema.id, &schema_id, &jwt)
        .await;

    // THEN
    // `InvalidCredentialState` (BR_0002) isn't one of the variants this endpoint maps to 400/404,
    // so it currently falls through to the generic 500 handler - asserting the exact status here
    // so this test breaks loudly if that mapping ever changes
    assert_eq!(400, resp.status());

    // no *issuance* happened, but the expiry check itself eagerly transitions the stale
    // credential to `Expired` as a side effect of being caught by the check
    let credential = context.db.credentials.get(&credential.id).await;
    assert_eq!(CredentialStateEnum::Expired, credential.state);
    assert!(credential.issuance_date.is_none());
}

#[tokio::test]
async fn test_post_issuer_credential_fails_when_credential_expiring() {
    // an issuer-side credential (the batch parent, for a batch/MDOC schema, or the credential
    // itself otherwise) that has been flagged `EXPIRING` must not be usable to issue a (further)
    // credential from - `create_credential` rejects it upfront, mirroring the `Expired` guard
    // covered above, but without the state-mutating side effect of the expiry check (EXPIRING
    // is a pure pre-existing flag, not something this endpoint transitions into)
    let TestIssuerSetup {
        interaction_id,
        access_token,
        organisation,
        context,
        key,
        issuer_identifier,
        ..
    } = issuer_setup(None).await;

    let schema_id = "test-schema-id".to_string();
    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "schema-1",
            &organisation,
            TestingCreateSchemaParams {
                schema_id: Some(schema_id.clone()),
                ..Default::default()
            },
        )
        .await;

    let interaction_data =
        dummy_issuer_interaction_data(&access_token, IssuerInteractionDataParams::default());
    let interaction = context
        .db
        .interactions
        .create(
            &organisation,
            InteractionType::Issuance,
            TestingInteractionParams {
                id: Some(interaction_id),
                data: Some(interaction_data),
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
                key: Some(key),
                r#type: Some(CredentialType::BatchParent),
                ..Default::default()
            },
        )
        .await;

    context
        .db
        .credentials
        .update(
            credential.id,
            UpdateCredentialRequest {
                state: Some(CredentialStateEnum::Expiring),
                ..Default::default()
            },
        )
        .await;

    let nonce = context
        .api
        .ssi
        .generate_nonce("OPENID4VCI_FINAL1")
        .await
        .json_value()
        .await["c_nonce"]
        .as_str()
        .unwrap()
        .to_string();
    let jwt = proof_jwt(true, Some(&nonce)).await;

    // WHEN
    let resp = context
        .api
        .ssi
        .issuer_create_credential(credential_schema.id, &schema_id, &jwt)
        .await;

    // THEN
    assert_eq!(400, resp.status());

    let resp = resp.json_value().await;
    assert!(
        resp["error_description"]
            .as_str()
            .is_some_and(|desc| desc.contains("BR_0002")),
        "expected error_description to carry the BR code, got: {resp}"
    );

    let credential = context.db.credentials.get(&credential.id).await;
    assert_eq!(CredentialStateEnum::Expiring, credential.state);
}

#[tokio::test]
async fn test_post_issuer_credential_sets_expires_at_from_schema() {
    let issuer_setup = issuer_setup(None).await;
    let credential_schema = issuer_setup
        .context
        .db
        .credential_schemas
        .create(
            "schema-1",
            &issuer_setup.organisation,
            TestingCreateSchemaParams {
                schema_id: Some("test-schema-id".to_string()),
                expiration: Some(Duration::days(10)),
                ..Default::default()
            },
        )
        .await;

    let params = PostCredentialTestParams {
        use_kid_in_proof: true,
        credential_schema: Some(credential_schema),
        ..Default::default()
    };
    // `expires_at` is fixed relative to the credential's creation (not its later issuance), so
    // bracket the fixture call with real timestamps rather than asserting exact equality - the
    // fixture's own `created_date` is a fixed dummy value, not real wall-clock time
    let before = one_core::clock::now_utc();
    let (context, credential_id) =
        test_post_issuer_credential_with(params, Some(issuer_setup)).await;
    let after = one_core::clock::now_utc();

    let credential = context.db.credentials.get(&credential_id).await;
    let expires_at = credential.expires_at.unwrap();
    assert!(expires_at >= before + Duration::days(10));
    assert!(expires_at <= after + Duration::days(10));
}

#[tokio::test]
async fn test_post_issuer_credential_embeds_expires_at_in_formatted_credential() {
    let TestIssuerSetup {
        interaction_id,
        access_token,
        organisation,
        context,
        key,
        issuer_identifier,
    } = issuer_setup(None).await;

    let schema_id = "test-schema-id".to_string();
    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "schema-1",
            &organisation,
            TestingCreateSchemaParams {
                schema_id: Some(schema_id.clone()),
                expiration: Some(Duration::days(10)),
                ..Default::default()
            },
        )
        .await;

    let interaction_data =
        dummy_issuer_interaction_data(&access_token, IssuerInteractionDataParams::default());
    let interaction = context
        .db
        .interactions
        .create(
            &organisation,
            InteractionType::Issuance,
            TestingInteractionParams {
                id: Some(interaction_id),
                data: Some(interaction_data),
                ..Default::default()
            },
        )
        .await;

    let credential = context
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
                expires_at: credential_schema
                    .expiration
                    .map(|expiration| one_core::clock::now_utc() + expiration),
                ..Default::default()
            },
        )
        .await;

    let nonce = context
        .api
        .ssi
        .generate_nonce("OPENID4VCI_FINAL1")
        .await
        .json_value()
        .await["c_nonce"]
        .as_str()
        .unwrap()
        .to_string();
    let jwt = proof_jwt(true, Some(&nonce)).await;

    let resp = context
        .api
        .ssi
        .issuer_create_credential(credential_schema.id, &schema_id, &jwt)
        .await;
    assert_eq!(200, resp.status());
    let resp_body = resp.json_value().await;

    let updated_credential = context.db.credentials.get(&credential.id).await;
    let expires_at = updated_credential.expires_at.unwrap();

    let response_jwt = resp_body["credentials"][0]["credential"]
        .as_str()
        .unwrap()
        .to_string();

    let blob = context
        .db
        .blobs
        .get(&updated_credential.credential_blob_id.unwrap())
        .await
        .unwrap();
    let stored_jwt = String::from_utf8(blob.value).unwrap();

    assert_eq!(
        response_jwt, stored_jwt,
        "the credential returned over the wire must match the one persisted to the blob"
    );

    for jwt in [&stored_jwt, &response_jwt] {
        let payload_b64 = jwt.split('.').nth(1).unwrap();
        let payload: serde_json::Value = serde_json::from_slice(
            &Base64UrlSafeNoPadding::decode_to_vec(payload_b64, None).unwrap(),
        )
        .unwrap();

        assert_eq!(
            payload["exp"].as_i64().unwrap(),
            expires_at.unix_timestamp()
        );

        // the embedded VCDM 1.1 `expirationDate` (`vcdm.expiration_date`) must also reflect the
        // credential's real expiry, not just the outer JWT `exp` claim (`vcdm.valid_until`)
        let vc_expiration_date = payload["vc"]["expirationDate"].as_str().unwrap();
        assert_eq!(
            OffsetDateTime::parse(vc_expiration_date, &Rfc3339).unwrap(),
            expires_at
        );
    }
}

#[tokio::test]
async fn test_post_issuer_credential_no_schema_expiration_means_no_expiry() {
    let TestIssuerSetup {
        interaction_id,
        access_token,
        organisation,
        context,
        key,
        issuer_identifier,
    } = issuer_setup(None).await;

    let schema_id = "test-schema-id".to_string();
    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "schema-1",
            &organisation,
            TestingCreateSchemaParams {
                schema_id: Some(schema_id.clone()),
                expiration: None,
                ..Default::default()
            },
        )
        .await;

    let interaction_data =
        dummy_issuer_interaction_data(&access_token, IssuerInteractionDataParams::default());
    let interaction = context
        .db
        .interactions
        .create(
            &organisation,
            InteractionType::Issuance,
            TestingInteractionParams {
                id: Some(interaction_id),
                data: Some(interaction_data),
                ..Default::default()
            },
        )
        .await;

    let credential = context
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
                expires_at: credential_schema
                    .expiration
                    .map(|expiration| one_core::clock::now_utc() + expiration),
                ..Default::default()
            },
        )
        .await;

    let nonce = context
        .api
        .ssi
        .generate_nonce("OPENID4VCI_FINAL1")
        .await
        .json_value()
        .await["c_nonce"]
        .as_str()
        .unwrap()
        .to_string();
    let jwt = proof_jwt(true, Some(&nonce)).await;

    let resp = context
        .api
        .ssi
        .issuer_create_credential(credential_schema.id, &schema_id, &jwt)
        .await;
    assert_eq!(200, resp.status());
    let resp_body = resp.json_value().await;

    let updated_credential = context.db.credentials.get(&credential.id).await;
    assert_eq!(updated_credential.expires_at, None);

    // the serialized credential must not carry an `exp` claim, nor an embedded
    // `expirationDate`, when the schema has no configured expiration
    let response_jwt = resp_body["credentials"][0]["credential"].as_str().unwrap();
    let payload_b64 = response_jwt.split('.').nth(1).unwrap();
    let payload: serde_json::Value =
        serde_json::from_slice(&Base64UrlSafeNoPadding::decode_to_vec(payload_b64, None).unwrap())
            .unwrap();

    assert!(payload.get("exp").is_none());
    assert!(payload["vc"].get("expirationDate").is_none());
}

#[tokio::test]
async fn test_post_issuer_credential_with_bitstring_revocation_method() {
    let params = PostCredentialTestParams {
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
            TestingCreateSchemaParams {
                schema_id: Some(schema_id.clone()),
                ..Default::default()
            },
        )
        .await;

    let mut issuances = vec![];
    const NUM_CREDENTIALS: usize = 10;
    for _ in 0..NUM_CREDENTIALS {
        let schema_id = schema_id.clone();
        let interaction_id: InteractionId = Uuid::new_v4().into();
        let access_token = format!("{interaction_id}.test");
        let interaction_data = dummy_issuer_interaction_data(
            access_token.as_str(),
            IssuerInteractionDataParams::default(),
        );

        let interaction = context
            .db
            .interactions
            .create(
                &organisation,
                InteractionType::Issuance,
                TestingInteractionParams {
                    id: Some(interaction_id),
                    data: Some(interaction_data),
                    ..Default::default()
                },
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
        let multibase = key.key.public_key_as_multibase().unwrap();
        let holder_key_id = format!("did:key:{multibase}#{multibase}");
        let jwt = proof_jwt_for(
            &key.key,
            "EdDSA".to_string(),
            Some(&holder_key_id),
            Some(nonce),
        )
        .await;
        let api = Client::new(context.api.base_url.clone(), access_token);

        issuances.push(async move {
            api.ssi
                .issuer_create_credential(credential_schema.id, &schema_id, &jwt)
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
            &"BITSTRINGSTATUSLIST".into(),
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
            TestingCreateSchemaParams {
                format: Some("SD_JWT_VC".into()),
                schema_id: Some(schema_id.clone()),
                ..Default::default()
            },
        )
        .await;

    let mut issuances = vec![];
    const NUM_CREDENTIALS: usize = 10;
    for _ in 0..NUM_CREDENTIALS {
        let schema_id = schema_id.clone();
        let interaction_id: InteractionId = Uuid::new_v4().into();
        let access_token = format!("{interaction_id}.test");
        let interaction_data =
            dummy_issuer_interaction_data(&access_token, IssuerInteractionDataParams::default());

        let interaction = context
            .db
            .interactions
            .create(
                &organisation,
                InteractionType::Issuance,
                TestingInteractionParams {
                    id: Some(interaction_id),
                    data: Some(interaction_data),
                    ..Default::default()
                },
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
                .issuer_create_credential(credential_schema.id, &schema_id, &jwt)
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
            &"TOKENSTATUSLIST".into(),
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
            Some(TestingRevocationListParams {
                r#type: Some("TOKENSTATUSLIST".into()),
                ..Default::default()
            }),
        )
        .await;

    let issuer_identifier_id = issuer_setup.issuer_identifier.id;
    let params = PostCredentialTestParams {
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
                &"BITSTRINGSTATUSLIST".into(),
            )
            .await
            .unwrap()
            .r#type
            .as_ref(),
        "BITSTRINGSTATUSLIST"
    );
    assert_eq!(
        context
            .db
            .revocation_lists
            .get_revocation_by_issuer_identifier_id(
                issuer_identifier_id,
                RevocationListPurpose::Suspension,
                &"BITSTRINGSTATUSLIST".into(),
            )
            .await
            .unwrap()
            .r#type
            .as_ref(),
        "BITSTRINGSTATUSLIST"
    );
    assert_eq!(
        context
            .db
            .revocation_lists
            .get_revocation_by_issuer_identifier_id(
                issuer_identifier_id,
                RevocationListPurpose::Revocation,
                &"TOKENSTATUSLIST".into(),
            )
            .await
            .unwrap()
            .r#type
            .as_ref(),
        "TOKENSTATUSLIST"
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
            Some(TestingRevocationListParams {
                r#type: Some("TOKENSTATUSLIST".into()),
                ..Default::default()
            }),
        )
        .await;

    let params = PostCredentialTestParams {
        use_kid_in_proof: true,
        ..Default::default()
    };
    test_post_issuer_credential_with(params, Some(issuer_setup)).await;
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
    let interaction_id = Uuid::new_v4().into();
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
            organisation.clone(),
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
enum NonceMode {
    #[default]
    Valid,
    Invalid,
    Missing,
}

#[derive(Default)]
struct PostCredentialTestParams {
    use_kid_in_proof: bool,
    nonce_mode: NonceMode,
    expect_failure: bool,
    access_token_expired: bool,
    credential_format: Option<CredentialFormat>,
    credential_schema: Option<CredentialSchema>,
}

async fn test_post_issuer_credential_with(
    test_params: PostCredentialTestParams,
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
        use_kid_in_proof,
        nonce_mode,
        expect_failure,
        credential_format,
        access_token_expired,
        credential_schema,
    } = test_params;

    let schema_id = "test-schema-id".to_string();
    let credential_schema = match credential_schema {
        None => {
            context
                .db
                .credential_schemas
                .create(
                    "schema-1",
                    &organisation,
                    TestingCreateSchemaParams {
                        format: credential_format,
                        schema_id: Some(schema_id.clone()),
                        ..Default::default()
                    },
                )
                .await
        }
        Some(schema) => schema,
    };

    let interaction_data = dummy_issuer_interaction_data(
        &access_token,
        IssuerInteractionDataParams {
            access_token_expired,
        },
    );
    let interaction = context
        .db
        .interactions
        .create(
            &organisation,
            InteractionType::Issuance,
            TestingInteractionParams {
                id: Some(interaction_id),
                data: Some(interaction_data),
                ..Default::default()
            },
        )
        .await;

    let credential = context
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
                // production credentials get `expires_at` computed once at creation time
                // (`from_create_request`), well before they're ever offered - mirror that here
                // since this fixture creates the row directly in the `Offered` state
                expires_at: credential_schema
                    .expiration
                    .map(|expiration| one_core::clock::now_utc() + expiration),
                ..Default::default()
            },
        )
        .await;

    let nonce = match nonce_mode {
        NonceMode::Valid => Some(
            context
                .api
                .ssi
                .generate_nonce("OPENID4VCI_FINAL1")
                .await
                .json_value()
                .await["c_nonce"]
                .as_str()
                .unwrap()
                .to_string(),
        ),
        NonceMode::Invalid => Some("invalid-nonce".to_string()),
        NonceMode::Missing => None,
    };

    let jwt = proof_jwt(use_kid_in_proof, nonce.as_deref()).await;
    let resp = context
        .api
        .ssi
        .issuer_create_credential(credential_schema.id, &schema_id, &jwt)
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
            &credential.holder_identifier.unwrap().id().to_string()
        );
    }

    (context, credential.id)
}

#[tokio::test]
async fn test_post_issuer_credential_mdoc() {
    let interaction_id = Uuid::new_v4().into();
    let access_token = format!("{interaction_id}.test");

    let context = TestContext::new_with_token(&access_token, None).await;

    let organisation = context.db.organisations.create().await;

    let key = context
        .db
        .keys
        .create(&organisation, eddsa_testing_params())
        .await;

    let identifier_id = Uuid::new_v4().into();
    let now = one_core::clock::now_utc();

    let fingerprint =
        "b97935d875d0f9adff52f4a547db4ffc533ecc6372cba6cbe657ff53ad65248d".to_string();
    let certificate_model = Certificate {
        id: Uuid::new_v4().into(),
        identifier_id,
        organisation: organisation.clone().into(),
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
        fingerprint: fingerprint.clone(),
        state: CertificateState::Active,
        roles: vec![],
        key: Some(key.clone().into()),
        deleted_at: None,
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
            organisation.clone(),
            TestingCertificateParams::from(certificate_model).await,
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
            &new_claim_schemas,
            "MDOC",
            "schema-id",
        )
        .await;

    let interaction_data =
        dummy_issuer_interaction_data(&access_token, IssuerInteractionDataParams::default());
    let interaction = context
        .db
        .interactions
        .create(
            &organisation,
            InteractionType::Issuance,
            TestingInteractionParams {
                id: Some(interaction_id),
                data: Some(interaction_data),
                ..Default::default()
            },
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

    let value = context
        .api
        .ssi
        .generate_nonce("OPENID4VCI_FINAL1")
        .await
        .json_value()
        .await;
    let nonce = value["c_nonce"].as_str().unwrap();
    let jwt = proof_jwt(true, Some(nonce)).await;
    let resp = context
        .api
        .ssi
        .issuer_create_credential(
            credential_schema.id,
            &credential_schema.schema_id().await.unwrap(),
            &jwt,
        )
        .await;

    assert_eq!(200, resp.status());

    // Validate that x5t thumbprint matches SHA-256 of x5c DER certificate
    let json_response = resp.json_value().await;
    let credential_b64 = json_response["credentials"][0]["credential"]
        .as_str()
        .unwrap();
    let credential_bytes = Base64UrlSafeNoPadding::decode_to_vec(credential_b64, None).unwrap();

    let headers = MdocIssuerAuthHeaders::from_credential_bytes(&credential_bytes);
    let sha256_bytes = SHA256.hash(&headers.x5c_der).unwrap();
    assert_eq!(sha256_bytes, headers.x5t_thumbprint);
    assert_eq!(hex::decode(&fingerprint).unwrap(), headers.x5t_thumbprint);
}

#[tokio::test]
async fn test_post_issuer_credential_jwt_vc_v2_mapped_claimed() {
    let mut params = PostCredentialTestParams {
        credential_format: Some("JWT".into()),
        use_kid_in_proof: true,
        ..Default::default()
    };
    let context = issuer_setup(None).await;

    let schema = context
        .context
        .db
        .credential_schemas
        .create(
            "schema-1",
            &context.organisation,
            TestingCreateSchemaParams {
                format: params.credential_format.clone(),
                claim_mappings: Some(hashmap! {
                    "firstName".to_string() => "firstName_Mapped".to_string(),
                    "isOver18".to_string() => "isOver18_Mapped".to_string()
                }),
                schema_id: Some("test-schema-id".to_string()),
                ..Default::default()
            },
        )
        .await;
    params.credential_schema = Some(schema);

    let (context, credential_id) = test_post_issuer_credential_with(params, Some(context)).await;

    let credential = context.db.credentials.get(&credential_id).await;
    let serialized_credential_blob = context
        .db
        .blobs
        .get(credential.credential_blob_id.as_ref().unwrap())
        .await
        .unwrap();
    let parsed_credential = Jwt::<serde_json::Value>::decompose_token(
        str::from_utf8(&serialized_credential_blob.value).unwrap(),
    )
    .unwrap();
    parsed_credential.payload.custom["vc"]["credentialSubject"]["firstName_Mapped"]
        .assert_eq(&"test".to_string());
    parsed_credential.payload.custom["vc"]["credentialSubject"]["isOver18_Mapped"].assert_eq(&true);
}

struct MdocIssuerAuthHeaders {
    x5t_thumbprint: Vec<u8>,
    x5c_der: Vec<u8>,
}

impl MdocIssuerAuthHeaders {
    fn from_credential_bytes(credential_bytes: &[u8]) -> Self {
        let issuer_signed: ciborium::Value = ciborium::from_reader(credential_bytes).unwrap();

        // issuerAuth is a COSE_Sign1 array: [protected_bstr, unprotected_map, payload, sig]
        let cose_sign1 = issuer_signed
            .as_map()
            .unwrap()
            .iter()
            .find_map(|(k, v)| (k.as_text() == Some("issuerAuth")).then(|| v.as_array().unwrap()))
            .unwrap();

        // Protected header: bstr containing a CBOR-serialized map (COSE label 34 = x5t)
        let protected_bytes = cose_sign1[0].as_bytes().unwrap();
        let protected_map: ciborium::Value =
            ciborium::from_reader(protected_bytes.as_slice()).unwrap();
        let x5t = protected_map
            .as_map()
            .unwrap()
            .iter()
            .find_map(|(k, v)| {
                (*k == ciborium::Value::Integer(34i64.into())).then(|| v.as_array().unwrap())
            })
            .unwrap();
        let x5t_thumbprint = x5t[1].as_bytes().unwrap().to_owned();

        // Unprotected header: CBOR map (COSE label 33 = x5chain)
        let x5c_der = cose_sign1[1]
            .as_map()
            .unwrap()
            .iter()
            .find_map(|(k, v)| {
                (*k == ciborium::Value::Integer(33i64.into()))
                    .then(|| v.as_bytes().unwrap().clone())
            })
            .unwrap();

        Self {
            x5t_thumbprint,
            x5c_der,
        }
    }
}
