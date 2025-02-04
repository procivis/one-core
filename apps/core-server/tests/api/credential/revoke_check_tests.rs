use one_core::model::credential::{Credential, CredentialRole, CredentialStateEnum};
use one_core::model::did::{Did, DidType, KeyRole, RelatedKey};
use one_core::model::revocation_list::RevocationListPurpose;
use one_core::provider::credential_formatter::jwt::mapper::{
    bin_to_b64url_string, string_to_b64url_string,
};
use one_core::provider::key_algorithm::eddsa::Algorithm::Ed25519;
use one_core::provider::key_algorithm::eddsa::{Eddsa, EddsaParams};
use one_core::provider::key_algorithm::KeyAlgorithm;
use one_crypto::signer::eddsa::{EDDSASigner, KeyPair};
use one_crypto::Signer;
use serde_json::json;
use time::macros::format_description;
use time::OffsetDateTime;
use wiremock::http::Method;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::fixtures::{TestingCredentialParams, TestingDidParams};
use crate::utils::context::TestContext;
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
            &organisation,
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

    let issuer_credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &did,
            "OPENID4VC",
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
            &did,
            "OPENID4VC",
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
async fn test_revoke_check_success_statuslist2021() {
    // GIVEN
    // contains statusListCredential=http://0.0.0.0:3000/ssi/revocation/v1/list/8bf6dc8f-228f-415c-83f2-95d851c1927b
    let credential_jwt = "eyJhbGciOiJFRERTQSIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE3MDEyNTk2MzcsImV4cCI6MTc2NDMzMTYzNywibmJmIjoxNzAxMjU5NTc3LCJpc3MiOiJkaWQ6a2V5Ono2TWt2M0hMNTJYSk5oNHJkdG5QS1BSbmRHd1U4bkF1VnBFN3lGRmllNVNOeFprWCIsInN1YiI6ImRkMmZmMDE2LTVmYmUtNDNiMC1hMmJhLTNiMDIzZWNjNTRmYiIsImp0aSI6IjNjNDgwYjUxLTI0ZDQtNGM3OS05MDViLTI3MTQ4YjYyY2RlNiIsInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIiwiaHR0cHM6Ly93M2lkLm9yZy92Yy9zdGF0dXMtbGlzdC8yMDIxL3YxIl0sInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiXSwiY3JlZGVudGlhbFN1YmplY3QiOnsic3RyaW5nIjoic3RyaW5nIn0sImNyZWRlbnRpYWxTdGF0dXMiOnsiaWQiOiJodHRwOi8vMC4wLjAuMDozMDAwL3NzaS9yZXZvY2F0aW9uL3YxL2xpc3QvOGJmNmRjOGYtMjI4Zi00MTVjLTgzZjItOTVkODUxYzE5MjdiIzAiLCJ0eXBlIjoiU3RhdHVzTGlzdDIwMjFFbnRyeSIsInN0YXR1c1B1cnBvc2UiOiJyZXZvY2F0aW9uIiwic3RhdHVzTGlzdENyZWRlbnRpYWwiOiJodHRwOi8vMC4wLjAuMDozMDAwL3NzaS9yZXZvY2F0aW9uL3YxL2xpc3QvOGJmNmRjOGYtMjI4Zi00MTVjLTgzZjItOTVkODUxYzE5MjdiIiwic3RhdHVzTGlzdEluZGV4IjoiMCJ9fX0.JUe1lljvJAXMMLr9mKOKLMFJ1XQr_GzL0i8JTOvt1_uNwVgQzMFQPqMUZ-sQg2JtWogDHLaUsjW64yFyc7ExCg";
    let status_list_credential_jwt = "eyJhbGciOiJFRERTQSIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJkaWQ6a2V5Ono2TWt2M0hMNTJYSk5oNHJkdG5QS1BSbmRHd1U4bkF1VnBFN3lGRmllNVNOeFprWCIsInN1YiI6Imh0dHA6Ly8wLjAuMC4wOjMwMDAvc3NpL3Jldm9jYXRpb24vdjEvbGlzdC84YmY2ZGM4Zi0yMjhmLTQxNWMtODNmMi05NWQ4NTFjMTkyN2IjbGlzdCIsImp0aSI6Imh0dHA6Ly8wLjAuMC4wOjMwMDAvc3NpL3Jldm9jYXRpb24vdjEvbGlzdC84YmY2ZGM4Zi0yMjhmLTQxNWMtODNmMi05NWQ4NTFjMTkyN2IiLCJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOi8vdzNpZC5vcmcvdmMvc3RhdHVzLWxpc3QvMjAyMS92MSJdLCJpZCI6Imh0dHA6Ly8wLjAuMC4wOjMwMDAvc3NpL3Jldm9jYXRpb24vdjEvbGlzdC84YmY2ZGM4Zi0yMjhmLTQxNWMtODNmMi05NWQ4NTFjMTkyN2IiLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiU3RhdHVzTGlzdDIwMjFDcmVkZW50aWFsIl0sImlzc3VlciI6ImRpZDprZXk6ejZNa3YzSEw1MlhKTmg0cmR0blBLUFJuZEd3VThuQXVWcEU3eUZGaWU1U054WmtYIiwiaXNzdWVkIjoiMjAyMy0xMS0yOVQxMjowNzoxNloiLCJjcmVkZW50aWFsU3ViamVjdCI6eyJpZCI6Imh0dHA6Ly8wLjAuMC4wOjMwMDAvc3NpL3Jldm9jYXRpb24vdjEvbGlzdC84YmY2ZGM4Zi0yMjhmLTQxNWMtODNmMi05NWQ4NTFjMTkyN2IjbGlzdCIsInR5cGUiOiJTdGF0dXNMaXN0MjAyMSIsInN0YXR1c1B1cnBvc2UiOiJyZXZvY2F0aW9uIiwiZW5jb2RlZExpc3QiOiJINHNJQUFBQUFBQUFfLTNBTVFFQUFBRENvUFZQYlF3ZktBQUFBQUFBQUFBQUFBQUFBQUFBQU9CdGh0SlVxd0JBQUFBIn19fQ.Gzx-gGYnA_ZWQWYPg1jBDOwRuPpBZS3qPcxJLb9gaFv5yOVS_IapihlqwpA5CL7u5gz26x4tKm_zZZTP-S_eDg";
    // We need to make sure other tests don't call on port 3000
    let mock_server = MockServer::builder()
        .listener(std::net::TcpListener::bind("127.0.0.1:3000").unwrap())
        .start()
        .await;

    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let issuer_did = context
        .db
        .dids
        .create(
            &organisation,
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
    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, "STATUSLIST2021", Default::default())
        .await;
    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &issuer_did,
            "OPENID4VC",
            TestingCredentialParams {
                credential: Some(credential_jwt),
                role: Some(CredentialRole::Holder),
                ..Default::default()
            },
        )
        .await;

    context
        .db
        .revocation_lists
        .create(&issuer_did, RevocationListPurpose::Revocation, None, None)
        .await;

    Mock::given(method(Method::GET))
        .and(path(
            "/ssi/revocation/v1/list/8bf6dc8f-228f-415c-83f2-95d851c1927b",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_string(status_list_credential_jwt))
        .expect(1)
        .mount(&mock_server)
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

    assert_eq!(statuslist_credential_entry.hit_counter, 1);

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

    assert_eq!(statuslist_credential_entry2.hit_counter, 0);
    assert!(statuslist_credential_entry.created_date < statuslist_credential_entry2.created_date);
}

async fn setup_bitstring_status_list_success(
    mock_server: &MockServer,
    expected_status_lookups: u64,
) -> (TestContext, Credential, Did, String) {
    let key_alg = Eddsa::new(EddsaParams { algorithm: Ed25519 });
    let key_pair = EDDSASigner::generate_key_pair();
    let issuer_did = format!(
        "did:key:{}",
        key_alg.get_multibase(&key_pair.public).unwrap()
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
          "encodedList": "H4sIAAAAAAAA_-3AMQEAAADCoPVPbQwfKAAAAAAAAAAAAAAAAAAAAOBthtJUqwBAAAA"
        }
      }
    });
    let credential_jwt = sign_jwt_helper(
        &header_json.to_string(),
        &credential_payload.to_string(),
        &key_pair,
    );
    let bitstring_status_list_credential_jwt = sign_jwt_helper(
        &header_json.to_string(),
        &status_credential_payload.to_string(),
        &key_pair,
    );

    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let issuer_did = context
        .db
        .dids
        .create(
            &organisation,
            TestingDidParams {
                did_method: Some("KEY".to_string()),
                did: Some(issuer_did.parse().unwrap()),
                did_type: Some(DidType::Local),
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
    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &issuer_did,
            "OPENID4VC",
            TestingCredentialParams {
                credential: Some(&credential_jwt),
                role: Some(CredentialRole::Holder),
                ..Default::default()
            },
        )
        .await;

    context
        .db
        .revocation_lists
        .create(&issuer_did, RevocationListPurpose::Revocation, None, None)
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

fn sign_jwt_helper(jwt_header_json: &str, payload_json: &str, key_pair: &KeyPair) -> String {
    let mut token = format!(
        "{}.{}",
        string_to_b64url_string(jwt_header_json).unwrap(),
        string_to_b64url_string(payload_json).unwrap(),
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
    // contains id=http://0.0.0.0:4445/ssi/revocation/v1/lvvc/2880d8dd-ce3f-4d74-b463-a2c0da07a5cf
    let credential_jwt = "eyJhbGciOiJFRERTQSIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE3MDc0MDk2ODksImV4cCI6MTc3MDQ4MTY4OSwibmJmIjoxNzA3NDA5NjI5LCJpc3MiOiJkaWQ6a2V5Ono2TWtrdHJ3bUpwdU1ISGtrcVkzZzV4VVA2S0tCMWVYeExvNktaRFo1THBmQmhyYyIsInN1YiI6ImRpZDprZXk6ejZNa2hodHVjWjY3Uzh5QXZIUG9KdE1WeDI4ejNCZmNQTjFncGpmbmk1RFQ3cVNlIiwianRpIjoiODhmYjlhZDItZWZlMC00YWRlLTgyNTEtMmIzOTc4NjQ5MGFmIiwidmMiOnsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiXSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCJdLCJpZCI6Imh0dHA6Ly8wLjAuMC4wOjQ0NDUvYXBpL2NyZWRlbnRpYWwvdjEvMjg4MGQ4ZGQtY2UzZi00ZDc0LWI0NjMtYTJjMGRhMDdhNWNmIiwiY3JlZGVudGlhbFN1YmplY3QiOnsiYWdlIjoiNTUifSwiY3JlZGVudGlhbFN0YXR1cyI6eyJpZCI6Imh0dHA6Ly8wLjAuMC4wOjQ0NDUvc3NpL3Jldm9jYXRpb24vdjEvbHZ2Yy8yODgwZDhkZC1jZTNmLTRkNzQtYjQ2My1hMmMwZGEwN2E1Y2YiLCJ0eXBlIjoiTFZWQyJ9fX0.-r0uxZCI2DAaxO8VHZOsZdcP9oMQhCeGjxOtQyDqITu_SPhuVGg2RZXvQT1C9r1p3CyG3bQRV0W0JOnN0QXtBA";
    let lvvc_credential_jwt = "eyJhbGciOiJFRERTQSIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE3MDc0MDk2ODksImV4cCI6MTc3MDQ4MTY4OSwibmJmIjoxNzA3NDA5NjI5LCJpc3MiOiJkaWQ6a2V5Ono2TWtrdHJ3bUpwdU1ISGtrcVkzZzV4VVA2S0tCMWVYeExvNktaRFo1THBmQmhyYyIsInN1YiI6ImRpZDprZXk6ejZNa2hodHVjWjY3Uzh5QXZIUG9KdE1WeDI4ejNCZmNQTjFncGpmbmk1RFQ3cVNlIiwianRpIjoiODhmYjlhZDItZWZlMC00YWRlLTgyNTEtMmIzOTc4NjQ5MGFmIiwidmMiOnsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiXSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCJdLCJpZCI6Imh0dHA6Ly8wLjAuMC4wOjQ0NDUvc3NpL3Jldm9jYXRpb24vdjEvbHZ2Yy8yODgwZDhkZC1jZTNmLTRkNzQtYjQ2My1hMmMwZGEwN2E1Y2YiLCJjcmVkZW50aWFsU3ViamVjdCI6eyJpZCI6Imh0dHA6Ly8wLjAuMC4wOjQ0NDUvYXBpL2NyZWRlbnRpYWwvdjEvMjg4MGQ4ZGQtY2UzZi00ZDc0LWI0NjMtYTJjMGRhMDdhNWNmIiwic3RhdHVzIjoiQUNDRVBURUQifX19.Z5PVZfjoLwkKUlJ-2EQN7QWip8S10NbbaatRpfuEgK2EYT2V0c__9Z_4zBJ5mtFvHyucxTb5r8wVcTNo-A0-DA";

    let mock_server = MockServer::builder()
        .listener(std::net::TcpListener::bind("127.0.0.1:4445").unwrap())
        .start()
        .await;

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
            &organisation,
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
                }]),
                ..Default::default()
            },
        )
        .await;
    let issuer_did = context
        .db
        .dids
        .create(
            &organisation,
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
    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, "LVVC", Default::default())
        .await;
    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &issuer_did,
            "OPENID4VC",
            TestingCredentialParams {
                credential: Some(credential_jwt),
                holder_did: Some(holder_did),
                role: Some(CredentialRole::Holder),
                ..Default::default()
            },
        )
        .await;

    context
        .db
        .revocation_lists
        .create(&issuer_did, RevocationListPurpose::Revocation, None, None)
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

static CREDENTIAL_CONTENT_OUTDATED: &str = "ompuYW1lU3BhY2VzomRyb290gdgYWFykaGRpZ2VzdElEAGZyYW5kb21YIJjSKig920Ai2ntgdAfGnRb-s0TORYA9W8b4mYjhw3u5cWVsZW1lbnRJZGVudGlmaWVyY0tleWxlbGVtZW50VmFsdWVkdGVzdHgZY2gucHJvY2l2aXMubWRvY19sYXlvdXQuMYPYGFhqpGhkaWdlc3RJRAFmcmFuZG9tWCBKbY7V0w4TKYTcJrmG_d1W6VU5Jb4_HCvN9RblZeaECXFlbGVtZW50SWRlbnRpZmllcmJpZGxlbGVtZW50VmFsdWVzb3JnLmlzby4yMzIyMC4xLm1JRNgYWMikaGRpZ2VzdElEAmZyYW5kb21YIG2uLPgrFExjiexjLUr5tMOSlDeiUnlxfyOLHuWUn6mVcWVsZW1lbnRJZGVudGlmaWVycGxheW91dFByb3BlcnRpZXNsZWxlbWVudFZhbHVlpmpiYWNrZ3JvdW5komVjb2xvcmVjb2xvcmVpbWFnZfZkbG9nb_ZwcHJpbWFyeUF0dHJpYnV0ZfZyc2Vjb25kYXJ5QXR0cmlidXRl9nBwaWN0dXJlQXR0cmlidXRl9mRjb2Rl9tgYWGOkaGRpZ2VzdElEA2ZyYW5kb21YIO7RwQ0lUbZZQPJ-2o4eru1n4Z3u1-KxfZvj5uo8dM_bcWVsZW1lbnRJZGVudGlmaWVyamxheW91dFR5cGVsZWxlbWVudFZhbHVlZENBUkRqaXNzdWVyQXV0aIRDoQEmoRghWQOLMIIDhzCCAyygAwIBAgIUahQKX8KQ86zDl0g9Wy3kW6oxFOQwCgYIKoZIzj0EAwIwYjELMAkGA1UEBhMCQ0gxDzANBgNVBAcMBlp1cmljaDERMA8GA1UECgwIUHJvY2l2aXMxETAPBgNVBAsMCFByb2NpdmlzMRwwGgYDVQQDDBNjYS5kZXYubWRsLXBsdXMuY29tMB4XDTI0MDUxNDA5MDAwMFoXDTI4MDIyOTAwMDAwMFowVTELMAkGA1UEBhMCQ0gxDzANBgNVBAcMBlp1cmljaDEUMBIGA1UECgwLUHJvY2l2aXMgQUcxHzAdBgNVBAMMFnRlc3QuZXMyNTYucHJvY2l2aXMuY2gwOTATBgcqhkjOPQIBBggqhkjOPQMBBwMiAAJx38tO0JCdq3ZecMSW6a-BAAzllydQxVOQ-KDjnwLXJ6OCAeswggHnMA4GA1UdDwEB_wQEAwIHgDAVBgNVHSUBAf8ECzAJBgcogYxdBQECMAwGA1UdEwEB_wQCMAAwHwYDVR0jBBgwFoAU7RqwneJgRVAAO9paNDIamL4tt8UwWgYDVR0fBFMwUTBPoE2gS4ZJaHR0cHM6Ly9jYS5kZXYubWRsLXBsdXMuY29tL2NybC80MENEMjI1NDdGMzgzNEM1MjZDNUMyMkUxQTI2QzdFMjAzMzI0NjY4LzCByAYIKwYBBQUHAQEEgbswgbgwWgYIKwYBBQUHMAKGTmh0dHA6Ly9jYS5kZXYubWRsLXBsdXMuY29tL2lzc3Vlci80MENEMjI1NDdGMzgzNEM1MjZDNUMyMkUxQTI2QzdFMjAzMzI0NjY4LmRlcjBaBggrBgEFBQcwAYZOaHR0cDovL2NhLmRldi5tZGwtcGx1cy5jb20vb2NzcC80MENEMjI1NDdGMzgzNEM1MjZDNUMyMkUxQTI2QzdFMjAzMzI0NjY4L2NlcnQvMCYGA1UdEgQfMB2GG2h0dHBzOi8vY2EuZGV2Lm1kbC1wbHVzLmNvbTAhBgNVHREEGjAYghZ0ZXN0LmVzMjU2LnByb2NpdmlzLmNoMB0GA1UdDgQWBBTGxO0mgPbDCn3_AoQxNFemFp40RTAKBggqhkjOPQQDAgNJADBGAiEAiRmxICo5Gxa4dlcK0qeyGDqyBOA9s_EI1V1b4KfIsl0CIQCHu0eIGECUJIffrjmSc7P6YnQfxgocBUko7nra5E0LhlkB99gYWQHypmd2ZXJzaW9uYzEuMG9kaWdlc3RBbGdvcml0aG1nU0hBLTI1Nmx2YWx1ZURpZ2VzdHOiZHJvb3ShAFggNe0Hk1dWKLOZJepp994MYA8ysT8FjnF2-z2Rl1jr9yB4GWNoLnByb2NpdmlzLm1kb2NfbGF5b3V0LjGjAVgg9LozcGRnhO0Oo_YkKFP00rQFY3TDzA9YoGXLs2iK_U0CWCBA6eF3OEgUB0VRtK3wxZX51_vkkvuI_gptomPDOPL8tANYILkTzzl3N4tq_nfykJWMmem_zZg7RYhR20zigE0ax8grbWRldmljZUtleUluZm-haWRldmljZUtleaQBAiABIVggcd_LTtCQnat2XnDElumvgQAM5ZcnUMVTkPig458C1yciWCCJpCY9SCKvzQjZcIWqfb8o-p1YfQ_EzMII_xbe4_GVQGdkb2NUeXBlc29yZy5pc28uMjMyMjAuMS5tSURsdmFsaWRpdHlJbmZvpGZzaWduZWTAdDIwMjQtMTAtMjNUMDY6NTQ6MTZaaXZhbGlkRnJvbcB0MjAyNC0xMC0yM1QwNjo1NDoxNlpqdmFsaWRVbnRpbMB0MjAyNC0xMC0yM1QwNjo1NDozNlpuZXhwZWN0ZWRVcGRhdGXAdDIwMjQtMTAtMjNUMDY6NTQ6MjZaWEATHzcmg9pVWNf_lExfcVRKLYWmDTKMpX6iDAvVWYmDRadG0dgLntcyufhqWZi6J7DO_wfbpFgS6YNVEUjkRhO5";
static CREDENTIAL_CONTENT_VALID: &str = "ompuYW1lU3BhY2VzomRyb290gdgYWFykaGRpZ2VzdElEAGZyYW5kb21YIA_N3wZ1v23KZ6f1llv4FOZ4P8h47vj94DhJWc8_5JjdcWVsZW1lbnRJZGVudGlmaWVyY0tleWxlbGVtZW50VmFsdWVkdGVzdHgZY2gucHJvY2l2aXMubWRvY19sYXlvdXQuMYPYGFhqpGhkaWdlc3RJRAFmcmFuZG9tWCD4SPq4-b9E62xRK-mSF5Iw4u__mlHEKctXQr5rkzjfh3FlbGVtZW50SWRlbnRpZmllcmJpZGxlbGVtZW50VmFsdWVzb3JnLmlzby4yMzIyMC4xLm1JRNgYWMikaGRpZ2VzdElEAmZyYW5kb21YIOLNTtn9i_sVQ7hUG9Rb1Jgo6S2XByWgHCGP0dBEuARwcWVsZW1lbnRJZGVudGlmaWVycGxheW91dFByb3BlcnRpZXNsZWxlbWVudFZhbHVlpmpiYWNrZ3JvdW5komVjb2xvcmVjb2xvcmVpbWFnZfZkbG9nb_ZwcHJpbWFyeUF0dHJpYnV0ZfZyc2Vjb25kYXJ5QXR0cmlidXRl9nBwaWN0dXJlQXR0cmlidXRl9mRjb2Rl9tgYWGOkaGRpZ2VzdElEA2ZyYW5kb21YIAT_On_5m4XZQY-kx-dKRPUSYZpvBuShHI1KeyLTs-tZcWVsZW1lbnRJZGVudGlmaWVyamxheW91dFR5cGVsZWxlbWVudFZhbHVlZENBUkRqaXNzdWVyQXV0aIRDoQEmoRghWQOLMIIDhzCCAyygAwIBAgIUahQKX8KQ86zDl0g9Wy3kW6oxFOQwCgYIKoZIzj0EAwIwYjELMAkGA1UEBhMCQ0gxDzANBgNVBAcMBlp1cmljaDERMA8GA1UECgwIUHJvY2l2aXMxETAPBgNVBAsMCFByb2NpdmlzMRwwGgYDVQQDDBNjYS5kZXYubWRsLXBsdXMuY29tMB4XDTI0MDUxNDA5MDAwMFoXDTI4MDIyOTAwMDAwMFowVTELMAkGA1UEBhMCQ0gxDzANBgNVBAcMBlp1cmljaDEUMBIGA1UECgwLUHJvY2l2aXMgQUcxHzAdBgNVBAMMFnRlc3QuZXMyNTYucHJvY2l2aXMuY2gwOTATBgcqhkjOPQIBBggqhkjOPQMBBwMiAAJx38tO0JCdq3ZecMSW6a-BAAzllydQxVOQ-KDjnwLXJ6OCAeswggHnMA4GA1UdDwEB_wQEAwIHgDAVBgNVHSUBAf8ECzAJBgcogYxdBQECMAwGA1UdEwEB_wQCMAAwHwYDVR0jBBgwFoAU7RqwneJgRVAAO9paNDIamL4tt8UwWgYDVR0fBFMwUTBPoE2gS4ZJaHR0cHM6Ly9jYS5kZXYubWRsLXBsdXMuY29tL2NybC80MENEMjI1NDdGMzgzNEM1MjZDNUMyMkUxQTI2QzdFMjAzMzI0NjY4LzCByAYIKwYBBQUHAQEEgbswgbgwWgYIKwYBBQUHMAKGTmh0dHA6Ly9jYS5kZXYubWRsLXBsdXMuY29tL2lzc3Vlci80MENEMjI1NDdGMzgzNEM1MjZDNUMyMkUxQTI2QzdFMjAzMzI0NjY4LmRlcjBaBggrBgEFBQcwAYZOaHR0cDovL2NhLmRldi5tZGwtcGx1cy5jb20vb2NzcC80MENEMjI1NDdGMzgzNEM1MjZDNUMyMkUxQTI2QzdFMjAzMzI0NjY4L2NlcnQvMCYGA1UdEgQfMB2GG2h0dHBzOi8vY2EuZGV2Lm1kbC1wbHVzLmNvbTAhBgNVHREEGjAYghZ0ZXN0LmVzMjU2LnByb2NpdmlzLmNoMB0GA1UdDgQWBBTGxO0mgPbDCn3_AoQxNFemFp40RTAKBggqhkjOPQQDAgNJADBGAiEAiRmxICo5Gxa4dlcK0qeyGDqyBOA9s_EI1V1b4KfIsl0CIQCHu0eIGECUJIffrjmSc7P6YnQfxgocBUko7nra5E0LhlkB99gYWQHypmd2ZXJzaW9uYzEuMG9kaWdlc3RBbGdvcml0aG1nU0hBLTI1Nmx2YWx1ZURpZ2VzdHOiZHJvb3ShAFggRpYenHUnzSbQbKmWIZI_BCwvghl1sOB4sGHxVx8fONt4GWNoLnByb2NpdmlzLm1kb2NfbGF5b3V0LjGjAVgg1FiRNnOwf8ZYKpkmqI4RRPhuK7kBp-SnGp7C0ylDCYMCWCDNDYNNvIsdmDH4g3DoO6nPvr6cs24w6dj22JIzKtVe8wNYIGKZcKRVQqvsWWTlF6M_IlV6Mj0sbORb9teoHlNfUE76bWRldmljZUtleUluZm-haWRldmljZUtleaQBAiABIVggcd_LTtCQnat2XnDElumvgQAM5ZcnUMVTkPig458C1yciWCCJpCY9SCKvzQjZcIWqfb8o-p1YfQ_EzMII_xbe4_GVQGdkb2NUeXBlc29yZy5pc28uMjMyMjAuMS5tSURsdmFsaWRpdHlJbmZvpGZzaWduZWTAdDIwMjQtMTAtMjNUMDk6MDY6MzdaaXZhbGlkRnJvbcB0MjAyNC0xMC0yM1QwOTowNjozN1pqdmFsaWRVbnRpbMB0NTE5My0wOS0wN1QxODo1MzoxNlpuZXhwZWN0ZWRVcGRhdGXAdDUxOTMtMDktMDdUMTg6NTM6MTZaWEA9xMH7syX8sOtOp9cdJ-fAxqqTkgH5dae4Uq8-hm0KOwBqAQnHtIEZdNoouEAQ3OAfQULMPCe-osTG432uvNJO";

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
            &organisation,
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
                }]),
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
        "{}/ssi/oidc-issuer/v1/{}",
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
        "access_token": "123",
        "access_token_expires_at": a_couple_of_seconds_in_future,
        "refresh_token": "123",
        "refresh_token_expires_at": a_couple_of_seconds_in_future,
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
            CredentialStateEnum::Accepted,
            &issuer_did,
            "OPENID4VC",
            TestingCredentialParams {
                credential: Some(CREDENTIAL_CONTENT_OUTDATED),
                interaction: Some(interaction),
                key: Some(local_key),
                holder_did: Some(issuer_did.clone()),
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
            CREDENTIAL_CONTENT_VALID,
            "mso_mdoc",
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
    assert_eq!(
        updated_credentials.credential,
        CREDENTIAL_CONTENT_VALID.as_bytes()
    );
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
            &organisation,
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
        "{}/ssi/oidc-issuer/v1/{}",
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
        "access_token": "123",
        "access_token_expires_at": a_couple_of_seconds_ago,
        "refresh_token": "123",
        "refresh_token_expires_at": a_couple_of_seconds_in_future,
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
            CredentialStateEnum::Accepted,
            &issuer_did,
            "OPENID4VC",
            TestingCredentialParams {
                credential: Some(CREDENTIAL_CONTENT_VALID),
                interaction: Some(interaction),
                key: Some(local_key),
                holder_did: Some(issuer_did.clone()),
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
            &organisation,
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
        "{}/ssi/oidc-issuer/v1/{}",
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
        "access_token": "invalid",
        "access_token_expires_at": a_couple_of_seconds_ago,
        "refresh_token": "invalid",
        "refresh_token_expires_at": a_couple_of_seconds_ago,
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
            CredentialStateEnum::Accepted,
            &issuer_did,
            "OPENID4VC",
            TestingCredentialParams {
                credential: Some(CREDENTIAL_CONTENT_OUTDATED),
                interaction: Some(interaction),
                key: Some(local_key),
                holder_did: Some(issuer_did.clone()),
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

    let updated_credentials = context.db.credentials.get(&credential.id).await;
    assert_eq!(
        updated_credentials.credential,
        CREDENTIAL_CONTENT_OUTDATED.as_bytes()
    );
    assert_eq!(updated_credentials.state, CredentialStateEnum::Revoked,);
}

#[tokio::test]
async fn test_revoke_check_mdoc_fali_to_update_token_valid_mso() {
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
            &organisation,
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
        "{}/ssi/oidc-issuer/v1/{}",
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
        "access_token": "invalid",
        "access_token_expires_at": a_couple_of_seconds_ago,
        "refresh_token": "invalid",
        "refresh_token_expires_at": a_couple_of_seconds_ago,
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
            CredentialStateEnum::Accepted,
            &issuer_did,
            "OPENID4VC",
            TestingCredentialParams {
                credential: Some(CREDENTIAL_CONTENT_VALID),
                interaction: Some(interaction),
                key: Some(local_key),
                holder_did: Some(issuer_did.clone()),
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
async fn test_suspended_to_valid() {
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
            &organisation,
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
                }]),
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
        "{}/ssi/oidc-issuer/v1/{}",
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
        "access_token": "invalid",
        "access_token_expires_at": a_couple_of_seconds_ago,
        "refresh_token": "valid",
        "refresh_token_expires_at": a_couple_of_seconds_in_future,
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
            CredentialStateEnum::Suspended,
            &issuer_did,
            "OPENID4VC",
            TestingCredentialParams {
                credential: Some(CREDENTIAL_CONTENT_OUTDATED),
                interaction: Some(interaction),
                key: Some(local_key),
                holder_did: Some(issuer_did.clone()),
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
        .ssi_credential_endpoint(
            &credential_schema.id,
            "321",
            CREDENTIAL_CONTENT_VALID,
            "mso_mdoc",
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
    assert_eq!(
        updated_credentials.credential,
        CREDENTIAL_CONTENT_VALID.as_bytes()
    );
    assert_eq!(updated_credentials.state, CredentialStateEnum::Accepted,);
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
            &organisation,
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
        "{}/ssi/oidc-issuer/v1/{}",
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
        "access_token": "invalid",
        "access_token_expires_at": a_couple_of_seconds_ago,
        "refresh_token": "valid",
        "refresh_token_expires_at": a_couple_of_seconds_in_future,
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
            CredentialStateEnum::Suspended,
            &issuer_did,
            "OPENID4VC",
            TestingCredentialParams {
                credential: Some(CREDENTIAL_CONTENT_OUTDATED),
                interaction: Some(interaction),
                key: Some(local_key),
                holder_did: Some(issuer_did.clone()),
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

    let updated_credentials = context.db.credentials.get(&credential.id).await;
    assert_eq!(
        updated_credentials.credential,
        CREDENTIAL_CONTENT_OUTDATED.as_bytes()
    );
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
            &organisation,
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
    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &issuer_did,
            "OPENID4VC",
            TestingCredentialParams {
                credential: Some(credential_jwt),
                deleted_at: Some(OffsetDateTime::now_utc()),
                ..Default::default()
            },
        )
        .await;

    context
        .db
        .revocation_lists
        .create(&issuer_did, RevocationListPurpose::Revocation, None, None)
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
