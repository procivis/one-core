use one_core::model::credential::{Credential, CredentialRole, CredentialStateEnum};
use one_core::model::did::{Did, DidType, KeyRole, RelatedKey};
use one_core::model::history::HistoryAction;
use one_core::model::identifier::{Identifier, IdentifierState, IdentifierType};
use one_core::model::interaction::InteractionType;
use one_core::model::revocation_list::RevocationListPurpose;
use one_core::provider::credential_formatter::mdoc_formatter::Params;
use one_core::provider::credential_formatter::model::{CredentialData, CredentialSchema, Issuer};
use one_core::provider::credential_formatter::vcdm::VcdmCredential;
use one_core::provider::key_algorithm::KeyAlgorithm;
use one_core::provider::key_algorithm::eddsa::Eddsa;
use one_core::util::jwt::mapper::{bin_to_b64url_string, string_to_b64url_string};
use one_crypto::Signer;
use one_crypto::signer::eddsa::{EDDSASigner, KeyPair};
use serde_json::{Value, json};
use similar_asserts::assert_eq;
use time::macros::format_description;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;
use wiremock::http::Method;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::fixtures::mdoc::format_mdoc_credential;
use crate::fixtures::{
    TestingCredentialParams, TestingDidParams, TestingIdentifierParams, encrypted_token,
};
use crate::utils::context::TestContext;
use crate::utils::db_clients::blobs::TestingBlobParams;
use crate::utils::db_clients::credential_schemas::TestingCreateSchemaParams;
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
            "NONE",
            TestingCreateSchemaParams {
                format: Some("JWT".to_string()),
                ..Default::default()
            },
        )
        .await;

    let did = context
        .db
        .dids
        .create(
            Some(organisation.clone()),
            TestingDidParams {
                did_method: Some("KEY".to_string()),
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
            "NONE",
            TestingCreateSchemaParams {
                format: Some("JWT".to_string()),
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
async fn test_revoke_check_success_statuslist2021() {
    // GIVEN
    let mock_server = MockServer::builder().start().await;
    let (context, organisation) = TestContext::new_with_organisation(None).await;

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

    let header = json!({
      "alg": "EDDSA",
      "typ": "JWT"
    });

    let port = mock_server.address().port();
    let credential_payload = json!({
      "iat": 1701259637,
      "exp": 1764331637,
      "nbf": 1701259577,
      "iss": issuer_did,
      "sub": "dd2ff016-5fbe-43b0-a2ba-3b023ecc54fb",
      "jti": "3c480b51-24d4-4c79-905b-27148b62cde6",
      "vc": {
        "@context": [
          "https://www.w3.org/2018/credentials/v1",
          "https://w3id.org/vc/status-list/2021/v1"
        ],
        "type": [
          "VerifiableCredential"
        ],
        "credentialSubject": {
          "string": "string"
        },
        "credentialStatus": {
          "id": format!("http://0.0.0.0:{port}/ssi/revocation/v1/list/8bf6dc8f-228f-415c-83f2-95d851c1927b#0"),
          "type": "StatusList2021Entry",
          "statusPurpose": "revocation",
          "statusListCredential": format!("http://0.0.0.0:{port}/ssi/revocation/v1/list/8bf6dc8f-228f-415c-83f2-95d851c1927b"),
          "statusListIndex": "0"
        }
      }
    });

    let status_list_payload = json!({
      "iss": issuer_did,
      "sub": format!("http://0.0.0.0:{port}/ssi/revocation/v1/list/8bf6dc8f-228f-415c-83f2-95d851c1927b#list"),
      "jti": format!("http://0.0.0.0:{port}/ssi/revocation/v1/list/8bf6dc8f-228f-415c-83f2-95d851c1927b"),
      "vc": {
        "@context": [
          "https://www.w3.org/2018/credentials/v1",
          "https://w3id.org/vc/status-list/2021/v1"
        ],
        "id": format!("http://0.0.0.0:{port}/ssi/revocation/v1/list/8bf6dc8f-228f-415c-83f2-95d851c1927b"),
        "type": [
          "VerifiableCredential",
          "StatusList2021Credential"
        ],
        "issuer": issuer_did,
        "issued": "2023-11-29T12:07:16Z",
        "credentialSubject": {
          "id": format!("http://0.0.0.0:{port}/ssi/revocation/v1/list/8bf6dc8f-228f-415c-83f2-95d851c1927b#list"),
          "type": "StatusList2021",
          "statusPurpose": "revocation",
          "encodedList": "uH4sIAAAAAAAA_-3AMQEAAADCoPVPbQwfKAAAAAAAAAAAAAAAAAAAAOBthtJUqwBAAAA"
        }
      }
    });

    let credential_jwt = sign_jwt_helper(&header, &credential_payload, &key_pair);
    let status_list_credential_jwt = sign_jwt_helper(&header, &status_list_payload, &key_pair);
    Mock::given(method(Method::GET))
        .and(path(
            "/ssi/revocation/v1/list/8bf6dc8f-228f-415c-83f2-95d851c1927b",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_string(status_list_credential_jwt))
        .expect(1)
        .mount(&mock_server)
        .await;

    let issuer_did = context
        .db
        .dids
        .create(
            Some(organisation.clone()),
            TestingDidParams {
                did_method: Some("KEY".to_string()),
                did: Some(issuer_did.parse().unwrap()),
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
        .create("test", &organisation, "STATUSLIST2021", Default::default())
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
                role: Some(CredentialRole::Holder),
                ..Default::default()
            },
        )
        .await;

    context
        .db
        .revocation_lists
        .create(identifier, RevocationListPurpose::Revocation, None, None)
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
    let before_test = OffsetDateTime::now_utc();
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
    assert!(statuslist_credential_entry.last_used <= OffsetDateTime::now_utc());

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
    assert!(statuslist_credential_entry2.last_used <= OffsetDateTime::now_utc());

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
            Some(organisation.clone()),
            TestingDidParams {
                did_method: Some("KEY".to_string()),
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
        .create(
            "test",
            &organisation,
            "BITSTRINGSTATUSLIST",
            Default::default(),
        )
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

    context
        .db
        .revocation_lists
        .create(identifier, RevocationListPurpose::Revocation, None, None)
        .await;

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
async fn test_revoke_check_success_lvvc() {
    // GIVEN
    let (context, _mock_server, credential) =
        setup_lvvc_revoke_check_valid(CredentialStateEnum::Accepted).await;

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
async fn test_revoke_check_success_lvvc_initially_suspended() {
    // GIVEN
    let (context, _mock_server, credential) =
        setup_lvvc_revoke_check_valid(CredentialStateEnum::Suspended).await;
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

async fn setup_lvvc_revoke_check_valid(
    initial_state: CredentialStateEnum,
) -> (TestContext, MockServer, Credential) {
    let key_pair = EDDSASigner::generate_key_pair();
    let issuer_did = format!(
        "did:key:{}",
        Eddsa
            .reconstruct_key(&key_pair.public, None, None)
            .unwrap()
            .signature()
            .unwrap()
            .public()
            .as_multibase()
            .unwrap()
    );

    let mock_server = MockServer::builder().start().await;
    let base_url = mock_server.uri();
    let jwt_header = json!({
      "alg": "EDDSA",
      "typ": "JWT"
    });
    let credential_payload = json!({
      "iat": 1707409689,
      "exp": 1770481689,
      "nbf": 1707409629,
      "iss": issuer_did,
      "sub": "did:key:z6MkhhtucZ67S8yAvHPoJtMVx28z3BfcPN1gpjfni5DT7qSe",
      "jti": "88fb9ad2-efe0-4ade-8251-2b39786490af",
      "vc": {
        "@context": [
          "https://www.w3.org/2018/credentials/v1"
        ],
        "type": [
          "VerifiableCredential"
        ],
        "id": format!("{base_url}/api/credential/v1/2880d8dd-ce3f-4d74-b463-a2c0da07a5cf"),
        "credentialSubject": {
          "age": "55"
        },
        "credentialStatus": {
          "id":  format!("{base_url}/ssi/revocation/v1/lvvc/2880d8dd-ce3f-4d74-b463-a2c0da07a5cf"),
          "type": "LVVC"
        }
      }
    });

    let lvvc_payload = json!({
      "iat": 1707409689,
      "exp": 1770481689,
      "nbf": 1707409629,
      "iss": issuer_did,
      "sub": "did:key:z6MkhhtucZ67S8yAvHPoJtMVx28z3BfcPN1gpjfni5DT7qSe",
      "jti": "88fb9ad2-efe0-4ade-8251-2b39786490af",
      "vc": {
        "@context": [
          "https://www.w3.org/2018/credentials/v1"
        ],
        "type": [
          "VerifiableCredential"
        ],
        "id": format!("{base_url}/ssi/revocation/v1/lvvc/2880d8dd-ce3f-4d74-b463-a2c0da07a5cf"),
        "credentialSubject": {
          "id": format!("{base_url}/api/credential/v1/2880d8dd-ce3f-4d74-b463-a2c0da07a5cf"),
          "status": "ACCEPTED"
        }
      }
    });

    let credential_jwt = sign_jwt_helper(&jwt_header, &credential_payload, &key_pair);
    let lvvc_credential_jwt = sign_jwt_helper(&jwt_header, &lvvc_payload, &key_pair);

    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let holder_key = context
        .db
        .keys
        .create(&organisation, eddsa_testing_params())
        .await;
    let holder_did = context
        .db
        .dids
        .create(
            Some(organisation.clone()),
            TestingDidParams {
                did_method: Some("KEY".to_string()),
                did: Some(
                    "did:key:z6MkktrwmJpuMHHkkqY3g5xUP6KKB1eXxLo6KZDZ5LpfBhrc"
                        .parse()
                        .unwrap(),
                ),
                did_type: Some(DidType::Local),
                keys: Some(vec![RelatedKey {
                    role: KeyRole::Authentication,
                    key: holder_key,
                    reference: "1".to_string(),
                }]),
                ..Default::default()
            },
        )
        .await;
    let holder_identifier = context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                did: Some(holder_did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(holder_did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;
    let issuer_did = context
        .db
        .dids
        .create(
            Some(organisation.clone()),
            TestingDidParams {
                did_method: Some("KEY".to_string()),
                did: Some(
                    "did:key:z6MkhhtucZ67S8yAvHPoJtMVx28z3BfcPN1gpjfni5DT7qSe"
                        .parse()
                        .unwrap(),
                ),
                did_type: Some(DidType::Remote),
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

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, "LVVC", Default::default())
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
            initial_state,
            &issuer_identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                credential_blob_id: Some(blob.id),
                holder_identifier: Some(holder_identifier),
                role: Some(CredentialRole::Holder),
                ..Default::default()
            },
        )
        .await;

    context
        .db
        .revocation_lists
        .create(
            issuer_identifier,
            RevocationListPurpose::Revocation,
            None,
            None,
        )
        .await;

    Mock::given(method(Method::GET))
        .and(path(
            "/ssi/revocation/v1/lvvc/2880d8dd-ce3f-4d74-b463-a2c0da07a5cf",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "credential": lvvc_credential_jwt,
            "format": "JWT"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;
    (context, mock_server, credential)
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
            Some(organisation.clone()),
            TestingDidParams {
                did_method: Some("KEY".to_string()),
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
            "NONE",
            TestingCreateSchemaParams {
                format: Some("MDOC".to_string()),
                ..Default::default()
            },
        )
        .await;

    let format = format_description!("[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond]Z");
    // Token is up to date
    let a_couple_of_seconds_in_future = (OffsetDateTime::now_utc() + time::Duration::seconds(20))
        .format(&format)
        .unwrap();
    let issuer_url = format!(
        "{}/ssi/openid4vci/draft-13/{}",
        context.server_mock.uri(),
        credential_schema.id,
    );
    let interaction_data = serde_json::to_vec(&json!({
        "issuer_url": issuer_url,
        "credential_endpoint": format!("{}/credential", issuer_url),
        "token_endpoint": format!("{}/token", issuer_url),
        "grants":{
            "urn:ietf:params:oauth:grant-type:pre-authorized_code":{
                "pre-authorized_code":"76f2355d-c9cb-4db6-8779-2f3b81062f8e"
            }
        },
        "access_token": encrypted_token("123"),
        "access_token_expires_at": a_couple_of_seconds_in_future,
        "refresh_token": encrypted_token("123"),
        "refresh_token_expires_at": a_couple_of_seconds_in_future,
    }))
    .unwrap();

    let interaction = context
        .db
        .interactions
        .create(
            None,
            &interaction_data,
            &organisation,
            InteractionType::Issuance,
        )
        .await;

    let blob = context
        .db
        .blobs
        .create(TestingBlobParams {
            value: Some(expired_mdoc_credential().await.as_bytes().to_vec()),
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
                interaction: Some(interaction),
                key: Some(local_key),
                holder_identifier: Some(identifier.clone()),
                role: Some(CredentialRole::Holder),
                credential_blob_id: Some(blob.id),
                ..Default::default()
            },
        )
        .await;

    let valid_credential = valid_mdoc_credential().await;
    context
        .server_mock
        .ssi_credential_endpoint(
            &credential_schema.id,
            "123",
            &valid_credential,
            "mso_mdoc",
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
    assert_eq!("ACCEPTED", resp[0]["status"]);
    assert_eq!(true, resp[0]["success"]);
    assert!(resp[0]["reason"].is_null());

    let updated_credentials = context
        .db
        .blobs
        .get(&credential.credential_blob_id.unwrap())
        .await
        .unwrap();
    assert_eq!(updated_credentials.value, valid_credential.as_bytes());
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
            Some(organisation.clone()),
            TestingDidParams {
                did_method: Some("KEY".to_string()),
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
            "NONE",
            TestingCreateSchemaParams {
                format: Some("MDOC".to_string()),
                ..Default::default()
            },
        )
        .await;

    let format = format_description!("[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond]Z");
    // Token is up to date
    let a_couple_of_seconds_in_future = (OffsetDateTime::now_utc() + Duration::seconds(20))
        .format(&format)
        .unwrap();
    let issuer_url = format!(
        "{}/ssi/openid4vci/draft-13/{}",
        context.server_mock.uri(),
        credential_schema.id,
    );
    let interaction_data = serde_json::to_vec(&json!({
        "issuer_url": issuer_url,
        "credential_endpoint": format!("{}/credential", issuer_url),
        "token_endpoint": format!("{}/token", issuer_url),
        "grants":{
            "urn:ietf:params:oauth:grant-type:pre-authorized_code":{
                "pre-authorized_code":"76f2355d-c9cb-4db6-8779-2f3b81062f8e"
            }
        },
        "access_token": encrypted_token("123"),
        "access_token_expires_at": a_couple_of_seconds_in_future,
        "refresh_token": encrypted_token("123"),
        "refresh_token_expires_at": a_couple_of_seconds_in_future,
    }))
    .unwrap();

    let interaction = context
        .db
        .interactions
        .create(
            None,
            &interaction_data,
            &organisation,
            InteractionType::Issuance,
        )
        .await;
    let expired_credential = expired_mdoc_credential().await;
    let blob = context
        .db
        .blobs
        .create(TestingBlobParams {
            value: Some(expired_credential.as_bytes().to_vec()),
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
        .ssi_credential_endpoint(
            &credential_schema.id,
            "123",
            "this is not a valid mdoc",
            "mso_mdoc",
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
        expired_credential.as_bytes() // invalid content was rejected / credential not updated
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
            Some(organisation.clone()),
            TestingDidParams {
                did_method: Some("KEY".to_string()),
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
            "NONE",
            TestingCreateSchemaParams {
                format: Some("MDOC".to_string()),
                ..Default::default()
            },
        )
        .await;

    let format = format_description!("[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond]Z");
    // Token is up to date
    let a_couple_of_seconds_in_future = (OffsetDateTime::now_utc() + time::Duration::seconds(20))
        .format(&format)
        .unwrap();
    let issuer_url = format!(
        "{}/ssi/openid4vci/draft-13/{}",
        context.server_mock.uri(),
        credential_schema.id,
    );
    let interaction_data = serde_json::to_vec(&json!({
        "issuer_url": issuer_url,
        "credential_endpoint": format!("{}/credential", issuer_url),
        "token_endpoint": format!("{}/token", issuer_url),
        "grants":{
            "urn:ietf:params:oauth:grant-type:pre-authorized_code":{
                "pre-authorized_code":"76f2355d-c9cb-4db6-8779-2f3b81062f8e"
            }
        },
        "access_token": encrypted_token("123"),
        "access_token_expires_at": a_couple_of_seconds_in_future,
        "refresh_token": encrypted_token("123"),
        "refresh_token_expires_at": a_couple_of_seconds_in_future,
    }))
    .unwrap();

    let interaction = context
        .db
        .interactions
        .create(
            None,
            &interaction_data,
            &organisation,
            InteractionType::Issuance,
        )
        .await;

    let valid_credential = valid_mdoc_credential().await;
    let blob = context
        .db
        .blobs
        .create(TestingBlobParams {
            value: Some(valid_credential.as_bytes().to_vec()),
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
                interaction: Some(interaction),
                key: Some(local_key),
                holder_identifier: Some(identifier.clone()),
                role: Some(CredentialRole::Holder),
                ..Default::default()
            },
        )
        .await;

    let valid_credential2 = valid_mdoc_credential().await;
    context
        .server_mock
        .ssi_credential_endpoint(
            &credential_schema.id,
            "123",
            &valid_credential2,
            "mso_mdoc",
            2,
            None,
        )
        .await;

    // WHEN
    for _ in 0..2 {
        let before_refresh = OffsetDateTime::now_utc();
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
        assert_eq!(updated_credentials.value, valid_credential2.as_bytes());
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
            Some(organisation.clone()),
            TestingDidParams {
                did_method: Some("KEY".to_string()),
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
            "NONE",
            TestingCreateSchemaParams {
                format: Some("MDOC".to_string()),
                ..Default::default()
            },
        )
        .await;

    let format = format_description!("[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond]Z");
    // Token is up outdated
    let a_couple_of_seconds_ago = (OffsetDateTime::now_utc() - time::Duration::seconds(20))
        .format(&format)
        .unwrap();
    let a_couple_of_seconds_in_future = (OffsetDateTime::now_utc() + time::Duration::seconds(20))
        .format(&format)
        .unwrap();
    let issuer_url = format!(
        "{}/ssi/openid4vci/draft-13/{}",
        context.server_mock.uri(),
        credential_schema.id,
    );

    let interaction_data = serde_json::to_vec(&json!({
        "issuer_url": issuer_url,
        "credential_endpoint": format!("{}/credential", issuer_url),
        "token_endpoint": format!("{}/token", issuer_url),
        "grants":{
            "urn:ietf:params:oauth:grant-type:pre-authorized_code":{
                "pre-authorized_code":"76f2355d-c9cb-4db6-8779-2f3b81062f8e"
            }
        },
        "access_token": encrypted_token("123"),
        "access_token_expires_at": a_couple_of_seconds_ago,
        "refresh_token": encrypted_token("123"),
        "refresh_token_expires_at": a_couple_of_seconds_in_future,
    }))
    .unwrap();

    let interaction = context
        .db
        .interactions
        .create(
            None,
            &interaction_data,
            &organisation,
            InteractionType::Issuance,
        )
        .await;

    let valid_credential = valid_mdoc_credential().await;
    let blob = context
        .db
        .blobs
        .create(TestingBlobParams {
            value: Some(valid_credential.as_bytes().to_vec()),
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
    let interaction = updated_credentials.interaction.unwrap();

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
            Some(organisation.clone()),
            TestingDidParams {
                did_method: Some("KEY".to_string()),
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
            "MDOC_MSO_UPDATE_SUSPENSION",
            TestingCreateSchemaParams {
                format: Some("MDOC".to_string()),
                ..Default::default()
            },
        )
        .await;

    let format = format_description!("[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond]Z");
    // Token is outdated
    let a_couple_of_seconds_ago = (OffsetDateTime::now_utc() - time::Duration::seconds(20))
        .format(&format)
        .unwrap();
    let issuer_url = format!(
        "{}/ssi/openid4vci/draft-13/{}",
        context.server_mock.uri(),
        credential_schema.id,
    );
    let interaction_data = serde_json::to_vec(&json!({
        "issuer_url": issuer_url,
        "credential_endpoint": format!("{}/credential", issuer_url),
        "token_endpoint": format!("{}/token", issuer_url),
        "grants":{
            "urn:ietf:params:oauth:grant-type:pre-authorized_code":{
                "pre-authorized_code":"76f2355d-c9cb-4db6-8779-2f3b81062f8e"
            }
        },
        "access_token": encrypted_token("invalid"),
        "access_token_expires_at": a_couple_of_seconds_ago,
        "refresh_token": encrypted_token("invalid"),
        "refresh_token_expires_at": a_couple_of_seconds_ago,
    }))
    .unwrap();

    let interaction = context
        .db
        .interactions
        .create(
            None,
            &interaction_data,
            &organisation,
            InteractionType::Issuance,
        )
        .await;

    let expired_credential = expired_mdoc_credential().await;
    let blob = context
        .db
        .blobs
        .create(TestingBlobParams {
            value: Some(expired_credential.as_bytes().to_vec()),
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
        expired_credential.as_bytes()
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
            Some(organisation.clone()),
            TestingDidParams {
                did_method: Some("KEY".to_string()),
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
            "NONE",
            TestingCreateSchemaParams {
                format: Some("MDOC".to_string()),
                ..Default::default()
            },
        )
        .await;

    let format = format_description!("[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond]Z");
    // Token is up outdated
    let a_couple_of_seconds_ago = (OffsetDateTime::now_utc() - time::Duration::seconds(20))
        .format(&format)
        .unwrap();
    let issuer_url = format!(
        "{}/ssi/openid4vci/draft-13/{}",
        context.server_mock.uri(),
        credential_schema.id,
    );
    let interaction_data = serde_json::to_vec(&json!({
        "issuer_url": issuer_url,
        "credential_endpoint": format!("{}/credential", issuer_url),
        "token_endpoint": format!("{}/token", issuer_url),
        "grants":{
            "urn:ietf:params:oauth:grant-type:pre-authorized_code":{
                "pre-authorized_code":"76f2355d-c9cb-4db6-8779-2f3b81062f8e"
            }
        },
        "access_token": encrypted_token("invalid"),
        "access_token_expires_at": a_couple_of_seconds_ago,
        "refresh_token": encrypted_token("invalid"),
        "refresh_token_expires_at": a_couple_of_seconds_ago,
    }))
    .unwrap();

    let interaction = context
        .db
        .interactions
        .create(
            None,
            &interaction_data,
            &organisation,
            InteractionType::Issuance,
        )
        .await;

    let valid_credential = valid_mdoc_credential().await;
    let blob = context
        .db
        .blobs
        .create(TestingBlobParams {
            value: Some(valid_credential.as_bytes().to_vec()),
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
            Some(organisation.clone()),
            TestingDidParams {
                did_method: Some("KEY".to_string()),
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
            "MDOC_MSO_UPDATE_SUSPENSION",
            TestingCreateSchemaParams {
                format: Some("MDOC".to_string()),
                ..Default::default()
            },
        )
        .await;

    let format = format_description!("[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond]Z");
    // Token is up outdated
    let a_couple_of_seconds_ago = (OffsetDateTime::now_utc() - time::Duration::seconds(20))
        .format(&format)
        .unwrap();
    let a_couple_of_seconds_in_future = (OffsetDateTime::now_utc() + time::Duration::seconds(20))
        .format(&format)
        .unwrap();
    let issuer_url = format!(
        "{}/ssi/openid4vci/draft-13/{}",
        context.server_mock.uri(),
        credential_schema.id,
    );
    let interaction_data = serde_json::to_vec(&json!({
        "issuer_url": issuer_url,
        "credential_endpoint": format!("{}/credential", issuer_url),
        "token_endpoint": format!("{}/token", issuer_url),
        "grants":{
            "urn:ietf:params:oauth:grant-type:pre-authorized_code":{
                "pre-authorized_code":"76f2355d-c9cb-4db6-8779-2f3b81062f8e"
            }
        },
        "access_token": encrypted_token("invalid"),
        "access_token_expires_at": a_couple_of_seconds_ago,
        "refresh_token": encrypted_token("valid"),
        "refresh_token_expires_at": a_couple_of_seconds_in_future,
    }))
    .unwrap();

    let interaction = context
        .db
        .interactions
        .create(
            None,
            &interaction_data,
            &organisation,
            InteractionType::Issuance,
        )
        .await;

    let expired_credential = expired_mdoc_credential().await;
    let blob = context
        .db
        .blobs
        .create(TestingBlobParams {
            value: Some(expired_credential.as_bytes().to_vec()),
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
            "OPENID4VCI_DRAFT13",
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

    let valid_credential = valid_mdoc_credential().await;
    context
        .server_mock
        .ssi_credential_endpoint(
            &credential_schema.id,
            "321",
            &valid_credential,
            "mso_mdoc",
            1,
            None,
        )
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
    assert_eq!(updated_credentials_blob.value, valid_credential.as_bytes());
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
            Some(organisation.clone()),
            TestingDidParams {
                did_method: Some("KEY".to_string()),
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
            "MDOC_MSO_UPDATE_SUSPENSION",
            TestingCreateSchemaParams {
                format: Some("MDOC".to_string()),
                ..Default::default()
            },
        )
        .await;

    let format = format_description!("[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond]Z");
    // Token is up outdated
    let a_couple_of_seconds_ago = (OffsetDateTime::now_utc() - time::Duration::seconds(20))
        .format(&format)
        .unwrap();
    let a_couple_of_seconds_in_future = (OffsetDateTime::now_utc() + time::Duration::seconds(20))
        .format(&format)
        .unwrap();
    let issuer_url = format!(
        "{}/ssi/openid4vci/draft-13/{}",
        context.server_mock.uri(),
        credential_schema.id,
    );
    let interaction_data = serde_json::to_vec(&json!({
        "issuer_url": issuer_url,
        "credential_endpoint": format!("{}/credential", issuer_url),
        "token_endpoint": format!("{}/token", issuer_url),
        "grants":{
            "urn:ietf:params:oauth:grant-type:pre-authorized_code":{
                "pre-authorized_code":"76f2355d-c9cb-4db6-8779-2f3b81062f8e"
            }
        },
        "access_token": encrypted_token("invalid"),
        "access_token_expires_at": a_couple_of_seconds_ago,
        "refresh_token": encrypted_token("valid"),
        "refresh_token_expires_at": a_couple_of_seconds_in_future,
    }))
    .unwrap();

    let interaction = context
        .db
        .interactions
        .create(
            None,
            &interaction_data,
            &organisation,
            InteractionType::Issuance,
        )
        .await;

    let expired_credential = expired_mdoc_credential().await;
    let blob = context
        .db
        .blobs
        .create(TestingBlobParams {
            value: Some(expired_credential.as_bytes().to_vec()),
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
            "OPENID4VCI_DRAFT13",
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
        expired_credential.as_bytes()
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
            Some(organisation.clone()),
            TestingDidParams {
                did_method: Some("KEY".to_string()),
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
        .create(
            "test",
            &organisation,
            "BITSTRINGSTATUSLIST",
            Default::default(),
        )
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
                deleted_at: Some(OffsetDateTime::now_utc()),
                ..Default::default()
            },
        )
        .await;

    context
        .db
        .revocation_lists
        .create(identifier, RevocationListPurpose::Revocation, None, None)
        .await;

    // WHEN
    let resp = context
        .api
        .credentials
        .revocation_check(credential.id, None)
        .await;

    // THEN
    assert_eq!(resp.status(), 404);
}

async fn valid_mdoc_credential() -> String {
    let params = Params {
        mso_expires_in: Duration::days(1),
        mso_expected_update_in: Duration::seconds(300),
        mso_minimum_refresh_time: Duration::seconds(300),
        leeway: 60,
        embed_layout_properties: None,
    };
    minimal_mdoc_credential(params).await
}

async fn expired_mdoc_credential() -> String {
    let params = Params {
        mso_expires_in: Duration::days(-1), // already expired
        mso_expected_update_in: Duration::days(-1),
        mso_minimum_refresh_time: Duration::seconds(0), // refresh immediately
        leeway: 60,
        embed_layout_properties: None,
    };
    minimal_mdoc_credential(params).await
}

async fn minimal_mdoc_credential(params: Params) -> String {
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
            credential_schema: Some(vec![CredentialSchema {
                id: "schema".to_string(),
                r#type: "schema".to_string(),
                metadata: None,
            }]),
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
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            name: "holder".to_string(),
            r#type: IdentifierType::Did,
            is_remote: true,
            state: IdentifierState::Active,
            deleted_at: None,
            organisation: None,
            did: Some(Did {
                id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                name: "holder".to_string(),
                did: "did:key:z6Mkv3HL52XJNh4rdtnPKPRndGwU8nAuVpE7yFFie5SNxZkX"
                    .parse()
                    .unwrap(),
                did_type: DidType::Local,
                did_method: "KEY".to_string(),
                deactivated: false,
                log: None,
                keys: None,
                organisation: None,
            }),
            key: None,
            certificates: None,
        }),
        holder_key_id: None,
        issuer_certificate: None,
    };

    format_mdoc_credential(credential, params).await
}
