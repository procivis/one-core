use one_core::model::credential::CredentialStateEnum;
use wiremock::http::Method::Get;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::fixtures::{TestingCredentialParams, TestingDidParams};
use crate::utils::context::TestContext;
use crate::utils::field_match::FieldHelpers;

#[tokio::test]
async fn test_revoke_check_success() {
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
        .create("test", &organisation, "STATUSLIST2021")
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

    context.db.revocation_lists.create(&issuer_did, None).await;

    Mock::given(method(Get))
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
