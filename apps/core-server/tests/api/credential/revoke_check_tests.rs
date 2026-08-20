use one_core::model::credential::{Credential, CredentialRole, CredentialStateEnum};
use one_core::model::did::{Did, DidType, KeyRole, RelatedKey};
use one_core::model::history::HistoryAction;
use one_core::model::identifier::{Identifier, IdentifierData, IdentifierState, IdentifierType};
use one_core::model::interaction::InteractionType;
use one_core::proto::jwt::mapper::{bin_to_b64url_string, string_to_b64url_string};
use one_core::provider::credential_formatter::model::{CredentialData, Issuer};
use one_core::provider::credential_formatter::vcdm::VcdmCredential;
use one_core::provider::key_algorithm::KeyAlgorithm;
use one_core::provider::key_algorithm::eddsa::Eddsa;
use one_core::service::test_utilities::dummy_organisation;
use one_crypto::Signer;
use one_crypto::signer::eddsa::{EDDSASigner, KeyPair};
use serde_json::{Value, json};
use shared_types::SerializedCredential;
use similar_asserts::assert_eq;
use uuid::Uuid;
use wiremock::http::Method;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::fixtures::interaction::{InteractionDataParams, dummy_interaction_data};
use crate::fixtures::mdoc::format_mdoc_credential;
use crate::fixtures::{TestingCredentialParams, TestingDidParams, TestingIdentifierParams};
use crate::utils::context::TestContext;
use crate::utils::db_clients::blobs::TestingBlobParams;
use crate::utils::db_clients::credential_schemas::TestingCreateSchemaParams;
use crate::utils::db_clients::interactions::TestingInteractionParams;
use crate::utils::db_clients::keys::eddsa_testing_params;
use crate::utils::field_match::FieldHelpers;

#[tokio::test]
async fn test_revoke_check_failed_if_not_holder_role() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test",
            &organisation,
            TestingCreateSchemaParams {
                format: Some("JWT".into()),
                ..Default::default()
            },
        )
        .await;

    let did = context
        .db
        .dids
        .create(
            organisation.clone(),
            TestingDidParams {
                did_method: Some("KEY".into()),
                did: Some(
                    "did:key:z6Mkv3HL52XJNh4rdtnPKPRndGwU8nAuVpE7yFFie5SNxZkX"
                        .parse()
                        .unwrap(),
                ),
                ..Default::default()
            },
        )
        .await;

    let identifier = context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                did: Some(did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;

    let issuer_credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                role: Some(CredentialRole::Issuer),
                ..Default::default()
            },
        )
        .await;

    let verifier_credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                role: Some(CredentialRole::Verifier),
                ..Default::default()
            },
        )
        .await;

    let issuer_revocation_check_response = context
        .api
        .credentials
        .revocation_check(issuer_credential.id, None)
        .await;

    let verifier_revocation_check_response = context
        .api
        .credentials
        .revocation_check(verifier_credential.id, None)
        .await;

    assert_eq!(issuer_revocation_check_response.status(), 400);
    assert_eq!(verifier_revocation_check_response.status(), 400);
}

#[tokio::test]
async fn test_revoke_check_failed_if_only_offered() {
    // GIVEN
    let (context, organisation, _, identifier, ..) = TestContext::new_with_did(None).await;

    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test",
            &organisation,
            TestingCreateSchemaParams {
                format: Some("JWT".into()),
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
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                role: Some(CredentialRole::Holder),
                ..Default::default()
            },
        )
        .await;

    let resp = context
        .api
        .credentials
        .revocation_check(credential.id, None)
        .await;

    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    resp[0]["credentialId"].assert_eq(&credential.id);
    assert_eq!("OFFERED", resp[0]["status"]);
    assert_eq!(false, resp[0]["success"]);
}

#[tokio::test]
async fn test_revoke_check_success_bitstring_status_list() {
    // GIVEN
    let mock_server = MockServer::start().await;

    let expected_status_lookups = 1;
    let (context, credential, _, _) =
        setup_bitstring_status_list_success(&mock_server, expected_status_lookups).await;

    // WHEN
    let resp = context
        .api
        .credentials
        .revocation_check(credential.id, None)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    resp[0]["credentialId"].assert_eq(&credential.id);
    assert_eq!("ACCEPTED", resp[0]["status"]);
    assert_eq!(true, resp[0]["success"]);
    assert!(resp[0]["reason"].is_null());
}

#[tokio::test]
async fn test_revoke_check_success_bitstring_status_list_with_force_refresh() {
    // GIVEN
    let mock_server = MockServer::start().await;

    // two lookups expected:
    // - initial lookup
    // - second check is cached --> no lookup
    // - third call sends lookup due to cache bypass
    let expected_status_lookups = 2;
    let (context, credential, issuer_did, revocation_list_url) =
        setup_bitstring_status_list_success(&mock_server, expected_status_lookups).await;

    // WHEN
    // inital lookup
    context
        .api
        .credentials
        .revocation_check(credential.id, None)
        .await;

    // THEN
    let result = context
        .db
        .remote_entities
        .get_by_key(&revocation_list_url)
        .await;
    assert!(result.is_some());
    let result = context
        .db
        .remote_entities
        .get_by_key(issuer_did.did.as_str())
        .await;
    assert!(result.is_some());

    // using cached information
    let before_test = one_core::clock::now_utc();
    context
        .api
        .credentials
        .revocation_check(credential.id, None)
        .await;

    let statuslist_credential_entry = context
        .db
        .remote_entities
        .get_by_key(&revocation_list_url)
        .await
        .unwrap();

    assert!(statuslist_credential_entry.last_used >= before_test);
    assert!(statuslist_credential_entry.last_used <= one_core::clock::now_utc());

    // bypassing the cache
    context
        .api
        .credentials
        .revocation_check(credential.id, Some(true))
        .await;

    let statuslist_credential_entry2 = context
        .db
        .remote_entities
        .get_by_key(&revocation_list_url)
        .await
        .unwrap();

    assert!(statuslist_credential_entry2.last_used >= before_test);
    assert!(statuslist_credential_entry2.last_used <= one_core::clock::now_utc());

    assert!(statuslist_credential_entry.created_date < statuslist_credential_entry2.created_date);
}

async fn setup_bitstring_status_list_success(
    mock_server: &MockServer,
    expected_status_lookups: u64,
) -> (TestContext, Credential, Did, String) {
    let key_alg = Eddsa;
    let key_pair = EDDSASigner::generate_key_pair();
    let issuer_did = format!(
        "did:key:{}",
        key_alg
            .reconstruct_key(&key_pair.public, None, None)
            .unwrap()
            .signature()
            .unwrap()
            .public()
            .as_multibase()
            .unwrap()
    );

    let revocation_list_url = format!(
        "{}/ssi/revocation/v1/list/2880d8dd-ce3f-4d74-b463-a2c0da07a5cf#2",
        mock_server.uri()
    );
    let header_json = json!({
      "alg": "EDDSA",
      "typ": "JWT"
    });
    let credential_payload = json!({
      "iss": issuer_did,
      "sub": "did:key:z6MkhhtucZ67S8yAvHPoJtMVx28z3BfcPN1gpjfni5DT7qSe",
      "vc": {
        "@context": [
          "https://www.w3.org/2018/credentials/v1"
        ],
        "type": [
          "VerifiableCredential"
        ],
        "credentialSubject": {},
        "credentialStatus": {
          "id": format!("{}#2", revocation_list_url),
          "type": "BitstringStatusListEntry",
          "statusPurpose": "revocation",
          "statusListCredential": revocation_list_url,
          "statusListIndex": "2"
        }
      }
    });
    let status_credential_payload = json!({
      "iss": issuer_did,
      "sub": format!("{}#list", revocation_list_url),
      "jti": revocation_list_url,
      "vc": {
        "@context": [
          "https://www.w3.org/2018/credentials/v1",
          "https://w3c.github.io/vc-bitstring-status-list/contexts/v1.jsonld"
        ],
        "id": revocation_list_url,
        "type": [
          "VerifiableCredential",
          "BitstringStatusListCredential"
        ],
        "issuer": issuer_did,
        "issued": "2024-02-08T16:13:23Z",
        "credentialSubject": {
          "id": format!("{}#list", revocation_list_url),
          "type": "BitstringStatusList",
          "statusPurpose": "revocation",
          "encodedList": "uH4sIAAAAAAAA_-3AMQEAAADCoPVPbQwfKAAAAAAAAAAAAAAAAAAAAOBthtJUqwBAAAA"
        }
      }
    });
    let credential_jwt = sign_jwt_helper(&header_json, &credential_payload, &key_pair);
    let bitstring_status_list_credential_jwt =
        sign_jwt_helper(&header_json, &status_credential_payload, &key_pair);

    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let issuer_did = context
        .db
        .dids
        .create(
            organisation.clone(),
            TestingDidParams {
                did_method: Some("KEY".into()),
                did: Some(issuer_did.parse().unwrap()),
                did_type: Some(DidType::Local),
                ..Default::default()
            },
        )
        .await;
    let identifier = context
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

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, Default::default())
        .await;

    let blob = context
        .db
        .blobs
        .create(TestingBlobParams {
            value: Some(credential_jwt.as_bytes().to_vec()),
            ..Default::default()
        })
        .await;

    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                role: Some(CredentialRole::Holder),
                credential_blob_id: Some(blob.id),
                ..Default::default()
            },
        )
        .await;

    context.db.revocation_lists.create(identifier, None).await;

    Mock::given(method(Method::GET))
        .and(path(
            "/ssi/revocation/v1/list/2880d8dd-ce3f-4d74-b463-a2c0da07a5cf",
        ))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "application/jwt")
                .set_body_bytes(bitstring_status_list_credential_jwt.as_bytes().to_vec()),
        )
        .expect(expected_status_lookups)
        .mount(mock_server)
        .await;
    (context, credential, issuer_did, revocation_list_url)
}

fn sign_jwt_helper(jwt_header_json: &Value, payload_json: &Value, key_pair: &KeyPair) -> String {
    let mut token = format!(
        "{}.{}",
        string_to_b64url_string(&jwt_header_json.to_string()).unwrap(),
        string_to_b64url_string(&payload_json.to_string()).unwrap(),
    );

    let signature = EDDSASigner {}
        .sign(token.as_bytes(), &key_pair.public, &key_pair.private)
        .unwrap();
    let signature_encoded = bin_to_b64url_string(&signature).unwrap();

    token.push('.');
    token.push_str(&signature_encoded);
    token
}

#[tokio::test]
async fn test_revoke_check_mdoc_update() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let local_key = context
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
                did_method: Some("KEY".into()),
                did: Some(
                    "did:key:z6Mkv3HL52XJNh4rdtnPKPRndGwU8nAuVpE7yFFie5SNxZkX"
                        .parse()
                        .unwrap(),
                ),
                keys: Some(vec![RelatedKey {
                    role: KeyRole::Authentication,
                    key: local_key.clone(),
                    reference: "1".to_string(),
                }]),
                ..Default::default()
            },
        )
        .await;
    let identifier = context
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

    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test",
            &organisation,
            TestingCreateSchemaParams {
                format: Some("MDOC".into()),
                ..Default::default()
            },
        )
        .await;

    let interaction_data = dummy_interaction_data(
        &context,
        &credential_schema,
        InteractionDataParams::with_format("mso_mdoc".to_string()),
    );
    let interaction = context
        .db
        .interactions
        .create(
            &organisation,
            InteractionType::Issuance,
            TestingInteractionParams {
                data: Some(interaction_data),
                ..Default::default()
            },
        )
        .await;

    let blob = context
        .db
        .blobs
        .create(TestingBlobParams {
            value: Some(expired_mdoc_credential().await.as_ref().into()),
            ..Default::default()
        })
        .await;

    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &identifier,
            "OPENID4VCI_FINAL1",
            TestingCredentialParams {
                interaction: Some(interaction),
                key: Some(local_key),
                holder_identifier: Some(identifier.clone()),
                role: Some(CredentialRole::Holder),
                credential_blob_id: Some(blob.id),
                ..Default::default()
            },
        )
        .await;

    context
        .server_mock
        .ssi_nonce_endpoint("OPENID4VCI_FINAL1", "123", 1)
        .await;
    let valid_credential = valid_mdoc_credential().await;
    context
        .server_mock
        .ssi_credential_endpoint(&credential_schema.id, "123", &[&valid_credential], 1, None)
        .await;

    // WHEN
    let resp = context
        .api
        .credentials
        .revocation_check(credential.id, None)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    resp[0]["credentialId"].assert_eq(&credential.id);
    assert_eq!("ACCEPTED", resp[0]["status"]);
    assert_eq!(true, resp[0]["success"]);
    assert!(resp[0]["reason"].is_null());

    let updated_credentials = context
        .db
        .blobs
        .get(&credential.credential_blob_id.unwrap())
        .await
        .unwrap();
    assert_eq!(
        updated_credentials.value,
        valid_credential.as_ref().as_bytes().to_vec()
    );
}

#[tokio::test]
async fn test_revoke_check_mdoc_update_invalid() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let local_key = context
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
                did_method: Some("KEY".into()),
                did: Some(
                    "did:key:z6Mkv3HL52XJNh4rdtnPKPRndGwU8nAuVpE7yFFie5SNxZkX"
                        .parse()
                        .unwrap(),
                ),
                keys: Some(vec![RelatedKey {
                    role: KeyRole::Authentication,
                    key: local_key.clone(),
                    reference: "1".to_string(),
                }]),
                ..Default::default()
            },
        )
        .await;
    let identifier = context
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

    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test",
            &organisation,
            TestingCreateSchemaParams {
                format: Some("MDOC".into()),
                ..Default::default()
            },
        )
        .await;

    let interaction_data = dummy_interaction_data(
        &context,
        &credential_schema,
        InteractionDataParams::with_format("mso_mdoc".to_string()),
    );
    let interaction = context
        .db
        .interactions
        .create(
            &organisation,
            InteractionType::Issuance,
            TestingInteractionParams {
                data: Some(interaction_data),
                ..Default::default()
            },
        )
        .await;
    let expired_credential = expired_mdoc_credential().await;
    let blob = context
        .db
        .blobs
        .create(TestingBlobParams {
            value: Some(expired_credential.as_ref().into()),
            ..Default::default()
        })
        .await;
    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &identifier,
            "OPENID4VCI_FINAL1",
            TestingCredentialParams {
                credential_blob_id: Some(blob.id),
                interaction: Some(interaction),
                key: Some(local_key),
                holder_identifier: Some(identifier.clone()),
                role: Some(CredentialRole::Holder),
                ..Default::default()
            },
        )
        .await;

    context
        .server_mock
        .ssi_nonce_endpoint("OPENID4VCI_FINAL1", "123", 1)
        .await;
    context
        .server_mock
        .ssi_credential_endpoint(
            &credential_schema.id,
            "123",
            &["this is not a valid mdoc"],
            1,
            None,
        )
        .await;

    // WHEN
    let resp = context
        .api
        .credentials
        .revocation_check(credential.id, None)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    resp[0]["credentialId"].assert_eq(&credential.id);
    assert_eq!("SUSPENDED", resp[0]["status"]);
    assert!(resp[0]["reason"].is_null());

    let updated_credentials = context
        .db
        .blobs
        .get(&credential.credential_blob_id.unwrap())
        .await
        .unwrap();
    assert_eq!(
        updated_credentials.value,
        expired_credential.as_ref().as_bytes().to_vec() // invalid content was rejected / credential not updated
    );
}

#[tokio::test]
async fn test_revoke_check_mdoc_update_force_refresh() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let local_key = context
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
                did_method: Some("KEY".into()),
                did: Some(
                    "did:key:z6Mkv3HL52XJNh4rdtnPKPRndGwU8nAuVpE7yFFie5SNxZkX"
                        .parse()
                        .unwrap(),
                ),
                keys: Some(vec![RelatedKey {
                    role: KeyRole::Authentication,
                    key: local_key.clone(),
                    reference: "1".to_string(),
                }]),
                ..Default::default()
            },
        )
        .await;
    let identifier = context
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

    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test",
            &organisation,
            TestingCreateSchemaParams {
                format: Some("MDOC".into()),
                ..Default::default()
            },
        )
        .await;

    let interaction_data = dummy_interaction_data(
        &context,
        &credential_schema,
        InteractionDataParams::with_format("mso_mdoc".to_string()),
    );

    let interaction = context
        .db
        .interactions
        .create(
            &organisation,
            InteractionType::Issuance,
            TestingInteractionParams {
                data: Some(interaction_data),
                ..Default::default()
            },
        )
        .await;

    let valid_credential = valid_mdoc_credential().await;
    let blob = context
        .db
        .blobs
        .create(TestingBlobParams {
            value: Some(valid_credential.as_ref().into()),
            ..Default::default()
        })
        .await;

    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &identifier,
            "OPENID4VCI_FINAL1",
            TestingCredentialParams {
                credential_blob_id: Some(blob.id),
                interaction: Some(interaction),
                key: Some(local_key),
                holder_identifier: Some(identifier.clone()),
                role: Some(CredentialRole::Holder),
                ..Default::default()
            },
        )
        .await;

    context
        .server_mock
        .ssi_nonce_endpoint("OPENID4VCI_FINAL1", "123", 2)
        .await;
    let valid_credential2 = valid_mdoc_credential().await;
    context
        .server_mock
        .ssi_credential_endpoint(&credential_schema.id, "123", &[&valid_credential2], 2, None)
        .await;

    // WHEN
    for _ in 0..2 {
        let before_refresh = one_core::clock::now_utc();
        let resp = context
            .api
            .credentials
            .revocation_check(credential.id, Some(true))
            .await;

        // THEN
        assert_eq!(resp.status(), 200);
        let resp = resp.json_value().await;

        resp[0]["credentialId"].assert_eq(&credential.id);
        assert_eq!("ACCEPTED", resp[0]["status"]);
        assert_eq!(true, resp[0]["success"]);
        assert!(resp[0]["reason"].is_null());

        let updated_credentials = context
            .db
            .blobs
            .get(&credential.credential_blob_id.unwrap())
            .await
            .unwrap();
        assert_eq!(
            updated_credentials.value,
            valid_credential2.as_ref().as_bytes().to_vec()
        );
        assert!(updated_credentials.last_modified > before_refresh);
    }
}

#[tokio::test]
async fn test_revoke_check_token_update() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let local_key = context
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
                did_method: Some("KEY".into()),
                did: Some(
                    "did:key:z6Mkv3HL52XJNh4rdtnPKPRndGwU8nAuVpE7yFFie5SNxZkX"
                        .parse()
                        .unwrap(),
                ),
                ..Default::default()
            },
        )
        .await;
    let identifier = context
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

    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test",
            &organisation,
            TestingCreateSchemaParams {
                format: Some("MDOC".into()),
                allow_suspension: Some(false),
                ..Default::default()
            },
        )
        .await;

    let interaction_data = dummy_interaction_data(
        &context,
        &credential_schema,
        InteractionDataParams {
            format: Some("mso_mdoc".to_string()),
            access_token_expired: true,
            ..Default::default()
        },
    );
    let interaction = context
        .db
        .interactions
        .create(
            &organisation,
            InteractionType::Issuance,
            TestingInteractionParams {
                data: Some(interaction_data.clone()),
                ..Default::default()
            },
        )
        .await;

    let valid_credential = to_be_updated_mdoc_credential().await;
    let blob = context
        .db
        .blobs
        .create(TestingBlobParams {
            value: Some(valid_credential.as_ref().into()),
            ..Default::default()
        })
        .await;
    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &identifier,
            "OPENID4VCI_FINAL1",
            TestingCredentialParams {
                credential_blob_id: Some(blob.id),
                interaction: Some(interaction),
                key: Some(local_key),
                holder_identifier: Some(identifier.clone()),
                role: Some(CredentialRole::Holder),
                ..Default::default()
            },
        )
        .await;

    context
        .server_mock
        .refresh_token(&credential_schema.id)
        .await;

    // WHEN
    let resp = context
        .api
        .credentials
        .revocation_check(credential.id, None)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    resp[0]["credentialId"].assert_eq(&credential.id);
    assert_eq!("ACCEPTED", resp[0]["status"]);
    assert_eq!(true, resp[0]["success"]);
    assert!(resp[0]["reason"].is_null());

    let updated_credentials = context.db.credentials.get(&credential.id).await;
    let interaction = updated_credentials
        .interaction
        .unwrap()
        .as_ref()
        .await
        .unwrap()
        .to_owned();

    // Interaction data updated.
    assert_ne!(interaction.data, Some(interaction_data));
}

#[tokio::test]
async fn test_revoke_check_mdoc_tokens_expired() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let local_key = context
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
                did_method: Some("KEY".into()),
                did: Some(
                    "did:key:z6Mkv3HL52XJNh4rdtnPKPRndGwU8nAuVpE7yFFie5SNxZkX"
                        .parse()
                        .unwrap(),
                ),
                ..Default::default()
            },
        )
        .await;
    let identifier = context
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

    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test",
            &organisation,
            TestingCreateSchemaParams {
                format: Some("MDOC".into()),
                allow_suspension: Some(true),
                ..Default::default()
            },
        )
        .await;

    let interaction_data = dummy_interaction_data(
        &context,
        &credential_schema,
        InteractionDataParams {
            format: Some("mso_mdoc".to_string()),
            access_token_expired: true,
            refresh_token_expired: true,
            ..Default::default()
        },
    );
    let interaction = context
        .db
        .interactions
        .create(
            &organisation,
            InteractionType::Issuance,
            TestingInteractionParams {
                data: Some(interaction_data),
                ..Default::default()
            },
        )
        .await;

    let expired_credential = expired_mdoc_credential().await;
    let blob = context
        .db
        .blobs
        .create(TestingBlobParams {
            value: Some(expired_credential.as_ref().into()),
            ..Default::default()
        })
        .await;
    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &identifier,
            "OPENID4VCI_FINAL1",
            TestingCredentialParams {
                credential_blob_id: Some(blob.id),
                interaction: Some(interaction),
                key: Some(local_key),
                holder_identifier: Some(identifier.clone()),
                role: Some(CredentialRole::Holder),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context
        .api
        .credentials
        .revocation_check(credential.id, None)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    resp[0]["credentialId"].assert_eq(&credential.id);
    assert_eq!("REVOKED", resp[0]["status"]);
    assert_eq!(true, resp[0]["success"]);
    assert!(resp[0]["reason"].is_null());

    let updated_credentials_blob = context
        .db
        .blobs
        .get(&credential.credential_blob_id.unwrap())
        .await
        .unwrap();
    assert_eq!(
        updated_credentials_blob.value,
        expired_credential.as_ref().as_bytes().to_vec()
    );
    let updated_credentials = context.db.credentials.get(&credential.id).await;
    assert_eq!(updated_credentials.state, CredentialStateEnum::Revoked,);
}

#[tokio::test]
async fn test_revoke_check_mdoc_fail_to_update_token_valid_mso() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let local_key = context
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
                did_method: Some("KEY".into()),
                did: Some(
                    "did:key:z6Mkv3HL52XJNh4rdtnPKPRndGwU8nAuVpE7yFFie5SNxZkX"
                        .parse()
                        .unwrap(),
                ),
                ..Default::default()
            },
        )
        .await;
    let identifier = context
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

    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test",
            &organisation,
            TestingCreateSchemaParams {
                format: Some("MDOC".into()),
                allow_suspension: Some(false),
                ..Default::default()
            },
        )
        .await;

    let interaction_data = dummy_interaction_data(
        &context,
        &credential_schema,
        InteractionDataParams::with_format("mso_mdoc".to_string()),
    );

    let interaction = context
        .db
        .interactions
        .create(
            &organisation,
            InteractionType::Issuance,
            TestingInteractionParams {
                data: Some(interaction_data),
                ..Default::default()
            },
        )
        .await;

    let valid_credential = valid_mdoc_credential().await;
    let blob = context
        .db
        .blobs
        .create(TestingBlobParams {
            value: Some(valid_credential.as_ref().into()),
            ..Default::default()
        })
        .await;
    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &identifier,
            "OPENID4VCI_FINAL1",
            TestingCredentialParams {
                credential_blob_id: Some(blob.id),
                interaction: Some(interaction),
                key: Some(local_key),
                holder_identifier: Some(identifier.clone()),
                role: Some(CredentialRole::Holder),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context
        .api
        .credentials
        .revocation_check(credential.id, None)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    resp[0]["credentialId"].assert_eq(&credential.id);
    assert_eq!("ACCEPTED", resp[0]["status"]);
    assert_eq!(true, resp[0]["success"]);
    assert!(resp[0]["reason"].is_null());

    let updated_credentials = context.db.credentials.get(&credential.id).await;
    assert_eq!(updated_credentials.state, CredentialStateEnum::Accepted,);
}

#[tokio::test]
async fn test_suspended_to_valid_mdoc() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let local_key = context
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
                did_method: Some("KEY".into()),
                did: Some(
                    "did:key:z6Mkv3HL52XJNh4rdtnPKPRndGwU8nAuVpE7yFFie5SNxZkX"
                        .parse()
                        .unwrap(),
                ),
                keys: Some(vec![RelatedKey {
                    role: KeyRole::Authentication,
                    key: local_key.clone(),
                    reference: "1".to_string(),
                }]),
                ..Default::default()
            },
        )
        .await;
    let identifier = context
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

    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test",
            &organisation,
            TestingCreateSchemaParams {
                format: Some("MDOC".into()),
                allow_suspension: Some(true),
                ..Default::default()
            },
        )
        .await;

    let interaction_data = dummy_interaction_data(
        &context,
        &credential_schema,
        InteractionDataParams {
            format: Some("mso_mdoc".to_string()),
            access_token_expired: true,
            ..Default::default()
        },
    );
    let interaction = context
        .db
        .interactions
        .create(
            &organisation,
            InteractionType::Issuance,
            TestingInteractionParams {
                data: Some(interaction_data),
                ..Default::default()
            },
        )
        .await;

    let expired_credential = expired_mdoc_credential().await;
    let blob = context
        .db
        .blobs
        .create(TestingBlobParams {
            value: Some(expired_credential.as_ref().into()),
            ..Default::default()
        })
        .await;
    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Suspended,
            &identifier,
            "OPENID4VCI_FINAL1",
            TestingCredentialParams {
                credential_blob_id: Some(blob.id),
                interaction: Some(interaction),
                key: Some(local_key),
                holder_identifier: Some(identifier.clone()),
                role: Some(CredentialRole::Holder),
                ..Default::default()
            },
        )
        .await;

    context
        .server_mock
        .refresh_token(&credential_schema.id)
        .await;

    context
        .server_mock
        .ssi_nonce_endpoint("OPENID4VCI_FINAL1", "123", 1)
        .await;
    let valid_credential = valid_mdoc_credential().await;
    context
        .server_mock
        .ssi_credential_endpoint(&credential_schema.id, "321", &[&valid_credential], 1, None)
        .await;
    let history_previous = context
        .db
        .histories
        .get_by_entity_id(&credential.id.into())
        .await;

    // WHEN
    let resp = context
        .api
        .credentials
        .revocation_check(credential.id, None)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    resp[0]["credentialId"].assert_eq(&credential.id);
    assert_eq!("ACCEPTED", resp[0]["status"]);
    assert_eq!(true, resp[0]["success"]);
    assert!(resp[0]["reason"].is_null());

    let updated_credentials_blob = context
        .db
        .blobs
        .get(&credential.credential_blob_id.unwrap())
        .await
        .unwrap();
    assert_eq!(
        updated_credentials_blob.value,
        valid_credential.as_ref().as_bytes().to_vec()
    );
    let updated_credentials = context.db.credentials.get(&credential.id).await;
    assert_eq!(updated_credentials.state, CredentialStateEnum::Accepted,);
    let history = context
        .db
        .histories
        .get_by_entity_id(&credential.id.into())
        .await;
    // unsuspend added two new history entries
    assert_eq!(history.values.len(), history_previous.values.len() + 2);
    // Within the first two entries there needs to be one Reactivated and one Accepted
    assert!(
        history
            .values
            .iter()
            .take(2)
            .any(|x| x.action == HistoryAction::Accepted)
    );
    assert!(
        history
            .values
            .iter()
            .take(2)
            .any(|x| x.action == HistoryAction::Reactivated)
    );
}

#[tokio::test]
async fn test_suspended_to_suspended_update_failed() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let local_key = context
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
                did_method: Some("KEY".into()),
                did: Some(
                    "did:key:z6Mkv3HL52XJNh4rdtnPKPRndGwU8nAuVpE7yFFie5SNxZkX"
                        .parse()
                        .unwrap(),
                ),
                ..Default::default()
            },
        )
        .await;
    let identifier = context
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

    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test",
            &organisation,
            TestingCreateSchemaParams {
                format: Some("MDOC".into()),
                allow_suspension: Some(true),
                ..Default::default()
            },
        )
        .await;

    let interaction_data = dummy_interaction_data(
        &context,
        &credential_schema,
        InteractionDataParams {
            format: Some("mso_mdoc".to_string()),
            access_token_expired: true,
            ..Default::default()
        },
    );
    let interaction = context
        .db
        .interactions
        .create(
            &organisation,
            InteractionType::Issuance,
            TestingInteractionParams {
                data: Some(interaction_data),
                ..Default::default()
            },
        )
        .await;

    let expired_credential = expired_mdoc_credential().await;
    let blob = context
        .db
        .blobs
        .create(TestingBlobParams {
            value: Some(expired_credential.as_ref().into()),
            ..Default::default()
        })
        .await;
    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Suspended,
            &identifier,
            "OPENID4VCI_FINAL1",
            TestingCredentialParams {
                credential_blob_id: Some(blob.id),
                interaction: Some(interaction),
                key: Some(local_key),
                holder_identifier: Some(identifier.clone()),
                role: Some(CredentialRole::Holder),
                ..Default::default()
            },
        )
        .await;

    context
        .server_mock
        .refresh_token(&credential_schema.id)
        .await;

    // WHEN
    let resp = context
        .api
        .credentials
        .revocation_check(credential.id, None)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    resp[0]["credentialId"].assert_eq(&credential.id);
    assert_eq!("SUSPENDED", resp[0]["status"]);
    assert_eq!(true, resp[0]["success"]);
    assert!(resp[0]["reason"].is_null());

    let updated_credentials_blob = context
        .db
        .blobs
        .get(&credential.credential_blob_id.unwrap())
        .await
        .unwrap();
    assert_eq!(
        updated_credentials_blob.value,
        expired_credential.as_ref().as_bytes().to_vec()
    );
    let updated_credentials = context.db.credentials.get(&credential.id).await;
    assert_eq!(updated_credentials.state, CredentialStateEnum::Suspended,);
}

#[tokio::test]
async fn test_revoke_check_failed_deleted_credential() {
    // GIVEN
    // contains statusListCredential=http://0.0.0.0:4444/ssi/revocation/v1/list/2880d8dd-ce3f-4d74-b463-a2c0da07a5cf
    let credential_jwt = "eyJhbGciOiJFRERTQSIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE3MDc0MDk2ODksImV4cCI6MTc3MDQ4MTY4OSwibmJmIjoxNzA3NDA5NjI5LCJpc3MiOiJkaWQ6a2V5Ono2TWtrdHJ3bUpwdU1ISGtrcVkzZzV4VVA2S0tCMWVYeExvNktaRFo1THBmQmhyYyIsInN1YiI6ImRpZDprZXk6ejZNa2hodHVjWjY3Uzh5QXZIUG9KdE1WeDI4ejNCZmNQTjFncGpmbmk1RFQ3cVNlIiwianRpIjoiODhmYjlhZDItZWZlMC00YWRlLTgyNTEtMmIzOTc4NjQ5MGFmIiwidmMiOnsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiXSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCJdLCJjcmVkZW50aWFsU3ViamVjdCI6eyJhZ2UiOiI1NSJ9LCJjcmVkZW50aWFsU3RhdHVzIjp7ImlkIjoiaHR0cDovLzAuMC4wLjA6NDQ0NC9zc2kvcmV2b2NhdGlvbi92MS9saXN0LzI4ODBkOGRkLWNlM2YtNGQ3NC1iNDYzLWEyYzBkYTA3YTVjZiMyIiwidHlwZSI6IkJpdHN0cmluZ1N0YXR1c0xpc3RFbnRyeSIsInN0YXR1c1B1cnBvc2UiOiJyZXZvY2F0aW9uIiwic3RhdHVzTGlzdENyZWRlbnRpYWwiOiJodHRwOi8vMC4wLjAuMDo0NDQ0L3NzaS9yZXZvY2F0aW9uL3YxL2xpc3QvMjg4MGQ4ZGQtY2UzZi00ZDc0LWI0NjMtYTJjMGRhMDdhNWNmIiwic3RhdHVzTGlzdEluZGV4IjoiMiJ9fX0.-r0uxZCI2DAaxO8VHZOsZdcP9oMQhCeGjxOtQyDqITu_SPhuVGg2RZXvQT1C9r1p3CyG3bQRV0W0JOnN0QXtBA";

    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let issuer_did = context
        .db
        .dids
        .create(
            organisation.clone(),
            TestingDidParams {
                did_method: Some("KEY".into()),
                did: Some(
                    "did:key:z6MkktrwmJpuMHHkkqY3g5xUP6KKB1eXxLo6KZDZ5LpfBhrc"
                        .parse()
                        .unwrap(),
                ),
                did_type: Some(DidType::Local),
                ..Default::default()
            },
        )
        .await;
    let identifier = context
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

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, Default::default())
        .await;
    let blob = context
        .db
        .blobs
        .create(TestingBlobParams {
            value: Some(credential_jwt.as_bytes().to_vec()),
            ..Default::default()
        })
        .await;
    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                credential_blob_id: Some(blob.id),
                deleted_at: Some(one_core::clock::now_utc()),
                ..Default::default()
            },
        )
        .await;

    context.db.revocation_lists.create(identifier, None).await;

    // WHEN
    let resp = context
        .api
        .credentials
        .revocation_check(credential.id, None)
        .await;

    // THEN
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_revoke_check_expires_single_credential() {
    // GIVEN
    let (context, organisation, _, identifier, ..) = TestContext::new_with_did(None).await;

    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test",
            &organisation,
            TestingCreateSchemaParams {
                format: Some("JWT".into()),
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
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                role: Some(CredentialRole::Holder),
                expires_at: Some(one_core::clock::now_utc() - time::Duration::days(1)),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context
        .api
        .credentials
        .revocation_check(credential.id, None)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    resp[0]["credentialId"].assert_eq(&credential.id);
    assert_eq!("EXPIRED", resp[0]["status"]);
    assert_eq!(true, resp[0]["success"]);
    assert!(resp[0]["reason"].is_null());

    let updated_credential = context.db.credentials.get(&credential.id).await;
    assert_eq!(updated_credential.state, CredentialStateEnum::Expired);

    // subsequent check is a no-op short-circuit (refresh no longer possible)
    let resp = context
        .api
        .credentials
        .revocation_check(credential.id, Some(true))
        .await;
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    assert_eq!("EXPIRED", resp[0]["status"]);
    assert_eq!(true, resp[0]["success"]);
}

#[tokio::test]
async fn test_revoke_check_batch_parent_stays_accepted_when_item_expires_but_refresh_token_valid() {
    // GIVEN
    let (context, organisation, _, identifier, ..) = TestContext::new_with_did(None).await;

    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test",
            &organisation,
            TestingCreateSchemaParams {
                format: Some("JWT".into()),
                batch_size: Some(2),
                ..Default::default()
            },
        )
        .await;

    let interaction_data = dummy_interaction_data(
        &context,
        &credential_schema,
        InteractionDataParams {
            refresh_token_expired: false,
            ..Default::default()
        },
    );
    let interaction = context
        .db
        .interactions
        .create(
            &organisation,
            InteractionType::Issuance,
            TestingInteractionParams {
                data: Some(interaction_data),
                ..Default::default()
            },
        )
        .await;

    let parent_credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                r#type: Some(one_core::model::credential::CredentialType::BatchParent),
                role: Some(CredentialRole::Holder),
                interaction: Some(interaction.clone()),
                ..Default::default()
            },
        )
        .await;

    let expired_item = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                r#type: Some(one_core::model::credential::CredentialType::BatchItem),
                parent_id: Some(parent_credential.id),
                role: Some(CredentialRole::Holder),
                expires_at: Some(one_core::clock::now_utc() - time::Duration::days(1)),
                interaction: Some(interaction.clone()),
                ..Default::default()
            },
        )
        .await;

    // an irrevocable credential (no `credentialStatus`) so the status check succeeds
    // without needing a configured revocation method
    let key_pair = EDDSASigner::generate_key_pair();
    let header_json = json!({
      "alg": "EDDSA",
      "typ": "JWT"
    });
    let credential_payload = json!({
      "iss": "did:key:z6MkktrwmJpuMHHkkqY3g5xUP6KKB1eXxLo6KZDZ5LpfBhrc",
      "sub": "did:key:z6MkhhtucZ67S8yAvHPoJtMVx28z3BfcPN1gpjfni5DT7qSe",
      "vc": {
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "type": ["VerifiableCredential"],
        "credentialSubject": {}
      }
    });
    let credential_jwt = sign_jwt_helper(&header_json, &credential_payload, &key_pair);
    let blob = context
        .db
        .blobs
        .create(TestingBlobParams {
            value: Some(credential_jwt.as_bytes().to_vec()),
            ..Default::default()
        })
        .await;

    let active_item = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                r#type: Some(one_core::model::credential::CredentialType::BatchItem),
                parent_id: Some(parent_credential.id),
                role: Some(CredentialRole::Holder),
                credential_blob_id: Some(blob.id),
                interaction: Some(interaction.clone()),
                ..Default::default()
            },
        )
        .await;

    // WHEN - one item expired, but the shared refresh token is still valid
    let resp = context
        .api
        .credentials
        .revocation_check(parent_credential.id, None)
        .await;

    // THEN - parent stays ACCEPTED (batch is still renewable), the item is individually EXPIRED
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    assert_eq!("ACCEPTED", resp[0]["status"]);
    assert_eq!(true, resp[0]["success"]);

    let updated_parent = context.db.credentials.get(&parent_credential.id).await;
    assert_eq!(updated_parent.state, CredentialStateEnum::Accepted);
    let updated_expired_item = context.db.credentials.get(&expired_item.id).await;
    assert_eq!(updated_expired_item.state, CredentialStateEnum::Expired);
    let updated_active_item = context.db.credentials.get(&active_item.id).await;
    assert_eq!(updated_active_item.state, CredentialStateEnum::Accepted);
}

/// The parent is only terminally EXPIRED once every item has individually expired *and* the
/// shared refresh token has also expired - i.e. there's no way left to either use an existing
/// item or renew the batch.
#[tokio::test]
async fn test_revoke_check_batch_parent_expires_when_all_items_and_refresh_token_expired() {
    // GIVEN
    let (context, organisation, _, identifier, ..) = TestContext::new_with_did(None).await;

    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test",
            &organisation,
            TestingCreateSchemaParams {
                format: Some("JWT".into()),
                batch_size: Some(1),
                ..Default::default()
            },
        )
        .await;

    let interaction_data = dummy_interaction_data(
        &context,
        &credential_schema,
        InteractionDataParams {
            refresh_token_expired: true,
            ..Default::default()
        },
    );
    let interaction = context
        .db
        .interactions
        .create(
            &organisation,
            InteractionType::Issuance,
            TestingInteractionParams {
                data: Some(interaction_data),
                ..Default::default()
            },
        )
        .await;

    let parent_credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                r#type: Some(one_core::model::credential::CredentialType::BatchParent),
                role: Some(CredentialRole::Holder),
                interaction: Some(interaction.clone()),
                ..Default::default()
            },
        )
        .await;

    let expired_item = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                r#type: Some(one_core::model::credential::CredentialType::BatchItem),
                parent_id: Some(parent_credential.id),
                role: Some(CredentialRole::Holder),
                expires_at: Some(one_core::clock::now_utc() - time::Duration::days(1)),
                interaction: Some(interaction.clone()),
                ..Default::default()
            },
        )
        .await;

    // WHEN - the only item is individually expired, and so is the shared refresh token
    let resp = context
        .api
        .credentials
        .revocation_check(parent_credential.id, None)
        .await;

    // THEN - the parent becomes EXPIRED
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    assert_eq!("EXPIRED", resp[0]["status"]);
    assert_eq!(true, resp[0]["success"]);

    let updated_parent = context.db.credentials.get(&parent_credential.id).await;
    assert_eq!(updated_parent.state, CredentialStateEnum::Expired);
    let updated_expired_item = context.db.credentials.get(&expired_item.id).await;
    assert_eq!(updated_expired_item.state, CredentialStateEnum::Expired);
}

/// The shared refresh token can expire the parent even if an item is still individually valid:
/// once the batch can no longer be renewed, it's dead regardless of item state.
#[tokio::test]
async fn test_revoke_check_batch_parent_expires_when_refresh_token_expired_even_if_item_valid() {
    // GIVEN
    let (context, organisation, _, identifier, ..) = TestContext::new_with_did(None).await;

    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test",
            &organisation,
            TestingCreateSchemaParams {
                format: Some("JWT".into()),
                batch_size: Some(2),
                ..Default::default()
            },
        )
        .await;

    let interaction_data = dummy_interaction_data(
        &context,
        &credential_schema,
        InteractionDataParams {
            refresh_token_expired: true,
            ..Default::default()
        },
    );
    let interaction = context
        .db
        .interactions
        .create(
            &organisation,
            InteractionType::Issuance,
            TestingInteractionParams {
                data: Some(interaction_data),
                ..Default::default()
            },
        )
        .await;

    let parent_credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                r#type: Some(one_core::model::credential::CredentialType::BatchParent),
                role: Some(CredentialRole::Holder),
                interaction: Some(interaction.clone()),
                ..Default::default()
            },
        )
        .await;

    // an irrevocable, not individually expired credential (no `credentialStatus`) so the status
    // check succeeds without needing a configured revocation method
    let key_pair = EDDSASigner::generate_key_pair();
    let header_json = json!({
      "alg": "EDDSA",
      "typ": "JWT"
    });
    let credential_payload = json!({
      "iss": "did:key:z6MkktrwmJpuMHHkkqY3g5xUP6KKB1eXxLo6KZDZ5LpfBhrc",
      "sub": "did:key:z6MkhhtucZ67S8yAvHPoJtMVx28z3BfcPN1gpjfni5DT7qSe",
      "vc": {
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "type": ["VerifiableCredential"],
        "credentialSubject": {}
      }
    });
    let credential_jwt = sign_jwt_helper(&header_json, &credential_payload, &key_pair);
    let blob = context
        .db
        .blobs
        .create(TestingBlobParams {
            value: Some(credential_jwt.as_bytes().to_vec()),
            ..Default::default()
        })
        .await;

    let active_item = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                r#type: Some(one_core::model::credential::CredentialType::BatchItem),
                parent_id: Some(parent_credential.id),
                role: Some(CredentialRole::Holder),
                credential_blob_id: Some(blob.id),
                interaction: Some(interaction.clone()),
                ..Default::default()
            },
        )
        .await;

    // WHEN - the shared refresh token has expired, but the item itself is still valid
    let resp = context
        .api
        .credentials
        .revocation_check(parent_credential.id, None)
        .await;

    // THEN - the parent becomes EXPIRED anyway (it can no longer be renewed)
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    assert_eq!("EXPIRED", resp[0]["status"]);
    assert_eq!(true, resp[0]["success"]);

    let updated_parent = context.db.credentials.get(&parent_credential.id).await;
    assert_eq!(updated_parent.state, CredentialStateEnum::Expired);
    let updated_active_item = context.db.credentials.get(&active_item.id).await;
    assert_eq!(updated_active_item.state, CredentialStateEnum::Accepted);
}

/// The parent's own business-level `expires_at` is authoritative: once it's passed, the parent
/// is EXPIRED regardless of the refresh token still being valid and its items still being valid.
#[tokio::test]
async fn test_revoke_check_batch_parent_expires_when_own_expires_at_passed() {
    // GIVEN
    let (context, organisation, _, identifier, ..) = TestContext::new_with_did(None).await;

    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test",
            &organisation,
            TestingCreateSchemaParams {
                format: Some("JWT".into()),
                batch_size: Some(1),
                ..Default::default()
            },
        )
        .await;

    let interaction_data = dummy_interaction_data(
        &context,
        &credential_schema,
        InteractionDataParams {
            refresh_token_expired: false,
            ..Default::default()
        },
    );
    let interaction = context
        .db
        .interactions
        .create(
            &organisation,
            InteractionType::Issuance,
            TestingInteractionParams {
                data: Some(interaction_data),
                ..Default::default()
            },
        )
        .await;

    let parent_credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                r#type: Some(one_core::model::credential::CredentialType::BatchParent),
                role: Some(CredentialRole::Holder),
                expires_at: Some(one_core::clock::now_utc() - time::Duration::days(1)),
                interaction: Some(interaction.clone()),
                ..Default::default()
            },
        )
        .await;

    // an irrevocable, not individually expired credential (no `credentialStatus`) so the status
    // check succeeds without needing a configured revocation method
    let key_pair = EDDSASigner::generate_key_pair();
    let header_json = json!({
      "alg": "EDDSA",
      "typ": "JWT"
    });
    let credential_payload = json!({
      "iss": "did:key:z6MkktrwmJpuMHHkkqY3g5xUP6KKB1eXxLo6KZDZ5LpfBhrc",
      "sub": "did:key:z6MkhhtucZ67S8yAvHPoJtMVx28z3BfcPN1gpjfni5DT7qSe",
      "vc": {
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "type": ["VerifiableCredential"],
        "credentialSubject": {}
      }
    });
    let credential_jwt = sign_jwt_helper(&header_json, &credential_payload, &key_pair);
    let blob = context
        .db
        .blobs
        .create(TestingBlobParams {
            value: Some(credential_jwt.as_bytes().to_vec()),
            ..Default::default()
        })
        .await;

    let valid_item = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                r#type: Some(one_core::model::credential::CredentialType::BatchItem),
                parent_id: Some(parent_credential.id),
                role: Some(CredentialRole::Holder),
                credential_blob_id: Some(blob.id),
                interaction: Some(interaction.clone()),
                ..Default::default()
            },
        )
        .await;

    // WHEN - the parent's own `expires_at` has passed, even though the item and refresh token
    // are still valid
    let resp = context
        .api
        .credentials
        .revocation_check(parent_credential.id, None)
        .await;

    // THEN - the parent becomes EXPIRED
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    assert_eq!("EXPIRED", resp[0]["status"]);
    assert_eq!(true, resp[0]["success"]);

    let updated_parent = context.db.credentials.get(&parent_credential.id).await;
    assert_eq!(updated_parent.state, CredentialStateEnum::Expired);
    let updated_valid_item = context.db.credentials.get(&valid_item.id).await;
    assert_eq!(updated_valid_item.state, CredentialStateEnum::Accepted);
}

async fn valid_mdoc_credential() -> SerializedCredential {
    let params = json!({
        "expirationSeconds": 86_400,
        "msoExpectedUpdateInSeconds": 300,
        "msoMinimumRefreshSeconds": 300,
        "leewaySeconds": 60
    });
    minimal_mdoc_credential(params).await
}

async fn to_be_updated_mdoc_credential() -> SerializedCredential {
    let params = json!({
        "expirationSeconds": 86_400,     // not expired
        "msoExpectedUpdateInSeconds": -10, // ready for update
        "msoMinimumRefreshSeconds": 0, // refresh immediately
        "leewaySeconds": 60
    });
    minimal_mdoc_credential(params).await
}

async fn expired_mdoc_credential() -> SerializedCredential {
    let params = json!({
        "expirationSeconds": -86_400,     // already expired
        "msoExpectedUpdateInSeconds": -86_400,
        "msoMinimumRefreshSeconds": 0, // refresh immediately
        "leewaySeconds": 60
    });
    minimal_mdoc_credential(params).await
}

async fn minimal_mdoc_credential(params: serde_json::Value) -> SerializedCredential {
    let credential = CredentialData {
        vcdm: VcdmCredential {
            context: Default::default(),
            id: None,
            r#type: vec![],
            issuer: Issuer::Url("https://example.issuer.com".parse().unwrap()),
            valid_from: None,
            issuance_date: None,
            valid_until: None,
            expiration_date: None,
            credential_subject: vec![],
            credential_status: vec![],
            proof: None,
            credential_schema: Some(vec![
                one_core::provider::credential_formatter::model::CredentialSchema {
                    id: "schema".to_string(),
                    r#type: "schema".to_string(),
                    metadata: None,
                },
            ]),
            refresh_service: None,
            name: None,
            description: None,
            terms_of_use: None,
            evidence: None,
            related_resource: None,
        },
        claims: vec![],
        holder_identifier: Some(Identifier {
            id: Uuid::new_v4().into(),
            created_date: one_core::clock::now_utc(),
            last_modified: one_core::clock::now_utc(),
            name: "holder".to_string(),
            data: IdentifierData::Did(
                (Did {
                    deleted_at: None,
                    id: Uuid::new_v4().into(),
                    created_date: one_core::clock::now_utc(),
                    last_modified: one_core::clock::now_utc(),
                    name: "holder".to_string(),
                    did: "did:key:z6Mkv3HL52XJNh4rdtnPKPRndGwU8nAuVpE7yFFie5SNxZkX"
                        .parse()
                        .unwrap(),
                    did_type: DidType::Local,
                    did_method: "KEY".into(),
                    deactivated: false,
                    log: None,
                    keys: Default::default(),
                    organisation: dummy_organisation(None).into(),
                })
                .into(),
            ),
            is_remote: true,
            state: IdentifierState::Active,
            deleted_at: None,
            organisation: dummy_organisation(None).into(),
            trust_information: Default::default(),
        }),
        holder_key_id: None,
        issuer_certificate: None,
    };

    format_mdoc_credential(credential, params).await
}
