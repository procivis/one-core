use one_core::model::credential::{CredentialRole, CredentialStateEnum};
use one_core::model::did::{DidType, KeyRole, RelatedKey};
use one_core::model::revocation_list::RevocationListPurpose;
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

//#[tokio::test]
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

    let (context, organisation) = TestContext::new_with_organisation().await;
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
            "PROCIVIS_TEMPORARY",
            TestingCredentialParams {
                credential: Some(credential_jwt),
                ..Default::default()
            },
        )
        .await;

    context
        .db
        .revocation_lists
        .create(&issuer_did, RevocationListPurpose::Revocation, None)
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
        .revocation_check(credential.id)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    resp[0]["credentialId"].assert_eq(&credential.id);
    assert_eq!("ACCEPTED", resp[0]["status"]);
    assert_eq!(true, resp[0]["success"]);
    assert!(resp[0]["reason"].is_null());
}

//#[tokio::test]
async fn test_revoke_check_success_bitstring_status_list() {
    // GIVEN
    // contains statusListCredential=http://0.0.0.0:4444/ssi/revocation/v1/list/2880d8dd-ce3f-4d74-b463-a2c0da07a5cf
    let credential_jwt = "eyJhbGciOiJFRERTQSIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE3MDc0MDk2ODksImV4cCI6MTc3MDQ4MTY4OSwibmJmIjoxNzA3NDA5NjI5LCJpc3MiOiJkaWQ6a2V5Ono2TWtrdHJ3bUpwdU1ISGtrcVkzZzV4VVA2S0tCMWVYeExvNktaRFo1THBmQmhyYyIsInN1YiI6ImRpZDprZXk6ejZNa2hodHVjWjY3Uzh5QXZIUG9KdE1WeDI4ejNCZmNQTjFncGpmbmk1RFQ3cVNlIiwianRpIjoiODhmYjlhZDItZWZlMC00YWRlLTgyNTEtMmIzOTc4NjQ5MGFmIiwidmMiOnsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiXSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCJdLCJjcmVkZW50aWFsU3ViamVjdCI6eyJhZ2UiOiI1NSJ9LCJjcmVkZW50aWFsU3RhdHVzIjp7ImlkIjoiaHR0cDovLzAuMC4wLjA6NDQ0NC9zc2kvcmV2b2NhdGlvbi92MS9saXN0LzI4ODBkOGRkLWNlM2YtNGQ3NC1iNDYzLWEyYzBkYTA3YTVjZiMyIiwidHlwZSI6IkJpdHN0cmluZ1N0YXR1c0xpc3RFbnRyeSIsInN0YXR1c1B1cnBvc2UiOiJyZXZvY2F0aW9uIiwic3RhdHVzTGlzdENyZWRlbnRpYWwiOiJodHRwOi8vMC4wLjAuMDo0NDQ0L3NzaS9yZXZvY2F0aW9uL3YxL2xpc3QvMjg4MGQ4ZGQtY2UzZi00ZDc0LWI0NjMtYTJjMGRhMDdhNWNmIiwic3RhdHVzTGlzdEluZGV4IjoiMiJ9fX0.-r0uxZCI2DAaxO8VHZOsZdcP9oMQhCeGjxOtQyDqITu_SPhuVGg2RZXvQT1C9r1p3CyG3bQRV0W0JOnN0QXtBA";
    let bitstring_status_list_credential_jwt = "eyJhbGciOiJFRERTQSIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJkaWQ6a2V5Ono2TWtrdHJ3bUpwdU1ISGtrcVkzZzV4VVA2S0tCMWVYeExvNktaRFo1THBmQmhyYyIsInN1YiI6Imh0dHA6Ly8wLjAuMC4wOjMwMDAvc3NpL3Jldm9jYXRpb24vdjEvbGlzdC8yODgwZDhkZC1jZTNmLTRkNzQtYjQ2My1hMmMwZGEwN2E1Y2YjbGlzdCIsImp0aSI6Imh0dHA6Ly8wLjAuMC4wOjMwMDAvc3NpL3Jldm9jYXRpb24vdjEvbGlzdC8yODgwZDhkZC1jZTNmLTRkNzQtYjQ2My1hMmMwZGEwN2E1Y2YiLCJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOi8vdzNjLmdpdGh1Yi5pby92Yy1iaXRzdHJpbmctc3RhdHVzLWxpc3QvY29udGV4dHMvdjEuanNvbmxkIl0sImlkIjoiaHR0cDovLzAuMC4wLjA6MzAwMC9zc2kvcmV2b2NhdGlvbi92MS9saXN0LzI4ODBkOGRkLWNlM2YtNGQ3NC1iNDYzLWEyYzBkYTA3YTVjZiIsInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJCaXRzdHJpbmdTdGF0dXNMaXN0Q3JlZGVudGlhbCJdLCJpc3N1ZXIiOiJkaWQ6a2V5Ono2TWtrdHJ3bUpwdU1ISGtrcVkzZzV4VVA2S0tCMWVYeExvNktaRFo1THBmQmhyYyIsImlzc3VlZCI6IjIwMjQtMDItMDhUMTY6MTM6MjNaIiwiY3JlZGVudGlhbFN1YmplY3QiOnsiaWQiOiJodHRwOi8vMC4wLjAuMDozMDAwL3NzaS9yZXZvY2F0aW9uL3YxL2xpc3QvMjg4MGQ4ZGQtY2UzZi00ZDc0LWI0NjMtYTJjMGRhMDdhNWNmI2xpc3QiLCJ0eXBlIjoiQml0c3RyaW5nU3RhdHVzTGlzdCIsInN0YXR1c1B1cnBvc2UiOiJyZXZvY2F0aW9uIiwiZW5jb2RlZExpc3QiOiJINHNJQUFBQUFBQUFfLTNBTVFFQUFBRENvUFZQYlF3ZktBQUFBQUFBQUFBQUFBQUFBQUFBQU9CdGh0SlVxd0JBQUFBIn19fQ.Z5PVZfjoLwkKUlJ-2EQN7QWip8S10NbbaatRpfuEgK2EYT2V0c__9Z_4zBJ5mtFvHyucxTb5r8wVcTNo-A0-DA";

    let mock_server = MockServer::builder()
        .listener(std::net::TcpListener::bind("127.0.0.1:4444").unwrap())
        .start()
        .await;

    let (context, organisation) = TestContext::new_with_organisation().await;
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
                ..Default::default()
            },
        )
        .await;

    context
        .db
        .revocation_lists
        .create(&issuer_did, RevocationListPurpose::Revocation, None)
        .await;

    Mock::given(method(Method::GET))
        .and(path(
            "/ssi/revocation/v1/list/2880d8dd-ce3f-4d74-b463-a2c0da07a5cf",
        ))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(bitstring_status_list_credential_jwt),
        )
        .expect(1)
        .mount(&mock_server)
        .await;

    // WHEN
    let resp = context
        .api
        .credentials
        .revocation_check(credential.id)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    resp[0]["credentialId"].assert_eq(&credential.id);
    assert_eq!("ACCEPTED", resp[0]["status"]);
    assert_eq!(true, resp[0]["success"]);
    assert!(resp[0]["reason"].is_null());
}

//#[tokio::test]
async fn test_revoke_check_success_lvvc() {
    // GIVEN
    // contains id=http://0.0.0.0:4445/ssi/revocation/v1/lvvc/2880d8dd-ce3f-4d74-b463-a2c0da07a5cf
    let credential_jwt = "eyJhbGciOiJFRERTQSIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE3MDc0MDk2ODksImV4cCI6MTc3MDQ4MTY4OSwibmJmIjoxNzA3NDA5NjI5LCJpc3MiOiJkaWQ6a2V5Ono2TWtrdHJ3bUpwdU1ISGtrcVkzZzV4VVA2S0tCMWVYeExvNktaRFo1THBmQmhyYyIsInN1YiI6ImRpZDprZXk6ejZNa2hodHVjWjY3Uzh5QXZIUG9KdE1WeDI4ejNCZmNQTjFncGpmbmk1RFQ3cVNlIiwianRpIjoiODhmYjlhZDItZWZlMC00YWRlLTgyNTEtMmIzOTc4NjQ5MGFmIiwidmMiOnsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiXSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCJdLCJpZCI6Imh0dHA6Ly8wLjAuMC4wOjQ0NDUvYXBpL2NyZWRlbnRpYWwvdjEvMjg4MGQ4ZGQtY2UzZi00ZDc0LWI0NjMtYTJjMGRhMDdhNWNmIiwiY3JlZGVudGlhbFN1YmplY3QiOnsiYWdlIjoiNTUifSwiY3JlZGVudGlhbFN0YXR1cyI6eyJpZCI6Imh0dHA6Ly8wLjAuMC4wOjQ0NDUvc3NpL3Jldm9jYXRpb24vdjEvbHZ2Yy8yODgwZDhkZC1jZTNmLTRkNzQtYjQ2My1hMmMwZGEwN2E1Y2YiLCJ0eXBlIjoiTFZWQyJ9fX0.-r0uxZCI2DAaxO8VHZOsZdcP9oMQhCeGjxOtQyDqITu_SPhuVGg2RZXvQT1C9r1p3CyG3bQRV0W0JOnN0QXtBA";
    let lvvc_credential_jwt = "eyJhbGciOiJFRERTQSIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE3MDc0MDk2ODksImV4cCI6MTc3MDQ4MTY4OSwibmJmIjoxNzA3NDA5NjI5LCJpc3MiOiJkaWQ6a2V5Ono2TWtrdHJ3bUpwdU1ISGtrcVkzZzV4VVA2S0tCMWVYeExvNktaRFo1THBmQmhyYyIsInN1YiI6ImRpZDprZXk6ejZNa2hodHVjWjY3Uzh5QXZIUG9KdE1WeDI4ejNCZmNQTjFncGpmbmk1RFQ3cVNlIiwianRpIjoiODhmYjlhZDItZWZlMC00YWRlLTgyNTEtMmIzOTc4NjQ5MGFmIiwidmMiOnsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiXSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCJdLCJpZCI6Imh0dHA6Ly8wLjAuMC4wOjQ0NDUvc3NpL3Jldm9jYXRpb24vdjEvbHZ2Yy8yODgwZDhkZC1jZTNmLTRkNzQtYjQ2My1hMmMwZGEwN2E1Y2YiLCJjcmVkZW50aWFsU3ViamVjdCI6eyJpZCI6Imh0dHA6Ly8wLjAuMC4wOjQ0NDUvYXBpL2NyZWRlbnRpYWwvdjEvMjg4MGQ4ZGQtY2UzZi00ZDc0LWI0NjMtYTJjMGRhMDdhNWNmIiwic3RhdHVzIjoiQUNDRVBURUQifX19.Z5PVZfjoLwkKUlJ-2EQN7QWip8S10NbbaatRpfuEgK2EYT2V0c__9Z_4zBJ5mtFvHyucxTb5r8wVcTNo-A0-DA";

    let mock_server = MockServer::builder()
        .listener(std::net::TcpListener::bind("127.0.0.1:4445").unwrap())
        .start()
        .await;

    let (context, organisation) = TestContext::new_with_organisation().await;
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
        .create(&issuer_did, RevocationListPurpose::Revocation, None)
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
        .revocation_check(credential.id)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    resp[0]["credentialId"].assert_eq(&credential.id);
    assert_eq!("ACCEPTED", resp[0]["status"]);
    assert_eq!(true, resp[0]["success"]);
    assert!(resp[0]["reason"].is_null());
}

static CREDENTIAL_CONTENT_OUTDATED: &str = "ompuYW1lU3BhY2VzoWRyb290gdgYWFykaGRpZ2VzdElEAGZyYW5kb21YILRDxI9MRD1_2dvxXCU632DA3ncWDvcQSlxWUAyV86dxcWVsZW1lbnRJZGVudGlmaWVyY0tleWxlbGVtZW50VmFsdWVkdGVzdGppc3N1ZXJBdXRohEOhASehGCFZA2UwggNhMIIDB6ADAgECAhQ5-tBbtXe3UN_nAXngcyNriNdKKjAKBggqhkjOPQQDAjBiMQswCQYDVQQGEwJDSDEPMA0GA1UEBwwGWnVyaWNoMREwDwYDVQQKDAhQcm9jaXZpczERMA8GA1UECwwIUHJvY2l2aXMxHDAaBgNVBAMME2NhLmRldi5tZGwtcGx1cy5jb20wHhcNMjQwNTE0MDcyNzAwWhcNMjQwODEyMDAwMDAwWjBKMQswCQYDVQQGEwJDSDEPMA0GA1UEBwwGWnVyaWNoMRQwEgYDVQQKDAtQcm9jaXZpcyBBRzEUMBIGA1UEAwwLcHJvY2l2aXMuY2gwKjAFBgMrZXADIQDcs4rEHmKT1aKSBCao0W2a680LQUwUVVevoBNWgv6RPqOCAeAwggHcMA4GA1UdDwEB_wQEAwIHgDAVBgNVHSUBAf8ECzAJBgcogYxdBQECMAwGA1UdEwEB_wQCMAAwHwYDVR0jBBgwFoAU7RqwneJgRVAAO9paNDIamL4tt8UwWgYDVR0fBFMwUTBPoE2gS4ZJaHR0cHM6Ly9jYS5kZXYubWRsLXBsdXMuY29tL2NybC80MENEMjI1NDdGMzgzNEM1MjZDNUMyMkUxQTI2QzdFMjAzMzI0NjY4LzCByAYIKwYBBQUHAQEEgbswgbgwWgYIKwYBBQUHMAKGTmh0dHA6Ly9jYS5kZXYubWRsLXBsdXMuY29tL2lzc3Vlci80MENEMjI1NDdGMzgzNEM1MjZDNUMyMkUxQTI2QzdFMjAzMzI0NjY4LmRlcjBaBggrBgEFBQcwAYZOaHR0cDovL2NhLmRldi5tZGwtcGx1cy5jb20vb2NzcC80MENEMjI1NDdGMzgzNEM1MjZDNUMyMkUxQTI2QzdFMjAzMzI0NjY4L2NlcnQvMCYGA1UdEgQfMB2GG2h0dHBzOi8vY2EuZGV2Lm1kbC1wbHVzLmNvbTAWBgNVHREEDzANggtwcm9jaXZpcy5jaDAdBgNVHQ4EFgQUrPuMkGVyPhaWk6AzOMrCKUNn-iAwCgYIKoZIzj0EAwIDSAAwRQIgOPbDm85Bpw0B8h0eZ-qWyfScGkGVsF0LvzhVPSWoDUUCIQC0IYp_093p07LPqR7fR8Vv5h8po6ZsOeBnd2VkiHh2-FkBT9gYWQFKpmd2ZXJzaW9uYzEuMG9kaWdlc3RBbGdvcml0aG1nU0hBLTI1Nmx2YWx1ZURpZ2VzdHOhZHJvb3ShAFggVfmUvisRWHv6FqlLnkNIuNBqB5L3LuBp9CwjkW4D6R9tZGV2aWNlS2V5SW5mb6FpZGV2aWNlS2V5owEBIAYhWCA1Kez7uQnJEmT8FJmDjtpJbe1EI88UDydsvJkucktW4Gdkb2NUeXBlc29yZy5pc28uMjMyMjAuMS5tSURsdmFsaWRpdHlJbmZvpGZzaWduZWTAdDIwMjQtMDYtMDRUMDY6NDc6MjBaaXZhbGlkRnJvbcB0MjAyNC0wNi0wNFQwNjo0NzoyMFpqdmFsaWRVbnRpbMB0MjAyNC0wNi0wNFQwNjo0Nzo1MFpuZXhwZWN0ZWRVcGRhdGXAdDIwMjQtMDYtMDRUMDY6NDc6NDBaWECqz879-uP6BF3OlGrJ0kv48Oux-V_jgx-7oTSDbNSGRcaTXlFzilqxF92e9vvTyVx-ay46z9_LU2Hjcmhk7REC";
static CREDENTIAL_CONTENT_VALID: &str = "ompuYW1lU3BhY2VzoWRyb290gdgYWFykaGRpZ2VzdElEAGZyYW5kb21YIJUToekj2hzGwDn2XaufO2ElxqPd-E0jJEP2Z8kg1XGscWVsZW1lbnRJZGVudGlmaWVyY0tleWxlbGVtZW50VmFsdWVkdGVzdGppc3N1ZXJBdXRohEOhASehGCFZA2UwggNhMIIDB6ADAgECAhQ5-tBbtXe3UN_nAXngcyNriNdKKjAKBggqhkjOPQQDAjBiMQswCQYDVQQGEwJDSDEPMA0GA1UEBwwGWnVyaWNoMREwDwYDVQQKDAhQcm9jaXZpczERMA8GA1UECwwIUHJvY2l2aXMxHDAaBgNVBAMME2NhLmRldi5tZGwtcGx1cy5jb20wHhcNMjQwNTE0MDcyNzAwWhcNMjQwODEyMDAwMDAwWjBKMQswCQYDVQQGEwJDSDEPMA0GA1UEBwwGWnVyaWNoMRQwEgYDVQQKDAtQcm9jaXZpcyBBRzEUMBIGA1UEAwwLcHJvY2l2aXMuY2gwKjAFBgMrZXADIQDcs4rEHmKT1aKSBCao0W2a680LQUwUVVevoBNWgv6RPqOCAeAwggHcMA4GA1UdDwEB_wQEAwIHgDAVBgNVHSUBAf8ECzAJBgcogYxdBQECMAwGA1UdEwEB_wQCMAAwHwYDVR0jBBgwFoAU7RqwneJgRVAAO9paNDIamL4tt8UwWgYDVR0fBFMwUTBPoE2gS4ZJaHR0cHM6Ly9jYS5kZXYubWRsLXBsdXMuY29tL2NybC80MENEMjI1NDdGMzgzNEM1MjZDNUMyMkUxQTI2QzdFMjAzMzI0NjY4LzCByAYIKwYBBQUHAQEEgbswgbgwWgYIKwYBBQUHMAKGTmh0dHA6Ly9jYS5kZXYubWRsLXBsdXMuY29tL2lzc3Vlci80MENEMjI1NDdGMzgzNEM1MjZDNUMyMkUxQTI2QzdFMjAzMzI0NjY4LmRlcjBaBggrBgEFBQcwAYZOaHR0cDovL2NhLmRldi5tZGwtcGx1cy5jb20vb2NzcC80MENEMjI1NDdGMzgzNEM1MjZDNUMyMkUxQTI2QzdFMjAzMzI0NjY4L2NlcnQvMCYGA1UdEgQfMB2GG2h0dHBzOi8vY2EuZGV2Lm1kbC1wbHVzLmNvbTAWBgNVHREEDzANggtwcm9jaXZpcy5jaDAdBgNVHQ4EFgQUrPuMkGVyPhaWk6AzOMrCKUNn-iAwCgYIKoZIzj0EAwIDSAAwRQIgOPbDm85Bpw0B8h0eZ-qWyfScGkGVsF0LvzhVPSWoDUUCIQC0IYp_093p07LPqR7fR8Vv5h8po6ZsOeBnd2VkiHh2-FkBT9gYWQFKpmd2ZXJzaW9uYzEuMG9kaWdlc3RBbGdvcml0aG1nU0hBLTI1Nmx2YWx1ZURpZ2VzdHOhZHJvb3ShAFggYGdZDIVhTtWtniCgGGSlIDYkXv6RXvQ6XM1-hxjCUuVtZGV2aWNlS2V5SW5mb6FpZGV2aWNlS2V5owEBIAYhWCA1Kez7uQnJEmT8FJmDjtpJbe1EI88UDydsvJkucktW4Gdkb2NUeXBlc29yZy5pc28uMjMyMjAuMS5tSURsdmFsaWRpdHlJbmZvpGZzaWduZWTAdDIwMjQtMDUtMzBUMTE6MDc6MTNaaXZhbGlkRnJvbcB0MjAyNC0wNS0zMFQxMTowNzoxM1pqdmFsaWRVbnRpbMB0MjQyNC0wMi0yM1QxMTowNzoxM1puZXhwZWN0ZWRVcGRhdGXAdDI0MjQtMDItMjNUMTE6MDc6MTNaWEACbTPgPnsWMlj3aUA7bqzpymbHbciXGBQu26JND2aiDKRAuzmJNlyb2nZp8NN0Rf-pI1enHPh-WMXuaT1MYpMG";

#[tokio::test]
async fn test_revoke_check_mdoc_update() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;

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
    // Token is up to date
    let a_couple_of_seconds_ago = (OffsetDateTime::now_utc() + time::Duration::seconds(20))
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
        "access_token": "123",
        "access_token_expires_at": a_couple_of_seconds_ago,
        "refresh_token": "123",
        "refresh_token_expires_at": a_couple_of_seconds_ago,
    }))
    .unwrap();

    let interaction = context
        .db
        .interactions
        .create(None, &context.server_mock.uri(), &interaction_data)
        .await;

    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &issuer_did,
            "PROCIVIS_TEMPORARY",
            TestingCredentialParams {
                credential: Some(CREDENTIAL_CONTENT_OUTDATED),
                interaction: Some(interaction),
                key: Some(local_key),
                holder_did: Some(issuer_did.clone()),
                ..Default::default()
            },
        )
        .await;

    context
        .server_mock
        .ssi_credential_endpoint(&credential_schema.id, "123", CREDENTIAL_CONTENT_VALID)
        .await;

    // WHEN
    let resp = context
        .api
        .credentials
        .revocation_check(credential.id)
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
    let (context, organisation) = TestContext::new_with_organisation().await;

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
        "access_token": "123",
        "access_token_expires_at": a_couple_of_seconds_ago,
        "refresh_token": "123",
        "refresh_token_expires_at": a_couple_of_seconds_ago,
    }))
    .unwrap();

    let interaction = context
        .db
        .interactions
        .create(None, &context.server_mock.uri(), &interaction_data)
        .await;

    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &issuer_did,
            "PROCIVIS_TEMPORARY",
            TestingCredentialParams {
                credential: Some(CREDENTIAL_CONTENT_VALID),
                interaction: Some(interaction),
                key: Some(local_key),
                holder_did: Some(issuer_did.clone()),
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
        .revocation_check(credential.id)
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
async fn test_revoke_check_mdoc_revoked() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;

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
        "access_token": "invalid",
        "access_token_expires_at": a_couple_of_seconds_ago,
        "refresh_token": "invalid",
        "refresh_token_expires_at": a_couple_of_seconds_ago,
    }))
    .unwrap();

    let interaction = context
        .db
        .interactions
        .create(None, &context.server_mock.uri(), &interaction_data)
        .await;

    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &issuer_did,
            "PROCIVIS_TEMPORARY",
            TestingCredentialParams {
                credential: Some(CREDENTIAL_CONTENT_OUTDATED),
                interaction: Some(interaction),
                key: Some(local_key),
                holder_did: Some(issuer_did.clone()),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context
        .api
        .credentials
        .revocation_check(credential.id)
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
    assert_eq!(
        updated_credentials.state.unwrap()[0].state,
        CredentialStateEnum::Revoked,
    );
}

#[tokio::test]
async fn test_revoke_check_mdoc_fali_to_update_token_valid_mso() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;

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
        "access_token": "invalid",
        "access_token_expires_at": a_couple_of_seconds_ago,
        "refresh_token": "invalid",
        "refresh_token_expires_at": a_couple_of_seconds_ago,
    }))
    .unwrap();

    let interaction = context
        .db
        .interactions
        .create(None, &context.server_mock.uri(), &interaction_data)
        .await;

    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &issuer_did,
            "PROCIVIS_TEMPORARY",
            TestingCredentialParams {
                credential: Some(CREDENTIAL_CONTENT_VALID),
                interaction: Some(interaction),
                key: Some(local_key),
                holder_did: Some(issuer_did.clone()),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context
        .api
        .credentials
        .revocation_check(credential.id)
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
        updated_credentials.state.unwrap()[0].state,
        CredentialStateEnum::Accepted,
    );
}
