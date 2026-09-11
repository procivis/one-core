use one_core::error::ErrorCode;
use one_core::model::blob::BlobType;
use one_core::model::credential::{CredentialRole, CredentialStateEnum};
use one_core::model::ecosystem::EcosystemOutcomes;
use one_core::model::history::{HistoryAction, HistoryErrorMetadata, HistoryMetadata};
use serde_json::json;
use similar_asserts::assert_eq;

use crate::fixtures::TestingCredentialParams;
use crate::utils::context::TestContext;
use crate::utils::db_clients::blobs::TestingBlobParams;
use crate::utils::db_clients::histories::TestingHistoryParams;

const ACCESS_CERT: &str = r#"-----BEGIN CERTIFICATE-----
MIIC+jCCAp+gAwIBAgIRAQrC1dwJkUxlszrpRjXZv+QwCgYIKoZIzj0EAwIwEjEQ
MA4GA1UEAwwHQ0EgY2VydDAeFw0yNjA0MDkwODQzMDhaFw0zMTA0MDgwODQzMDha
MGUxCzAJBgNVBAYMAkNIMR0wGwYDVQRRDBRodHRwczovL3NvbWUtdXJsLmNvbTEU
MBIGA1UEAwwLY29tbW9uIG5hbWUxDjAMBgNVBGEMBW9yZ0lkMREwDwYDVQQKDAhP
cmcgbmFtZTAqMAUGAytlcAMhAEoEScmT7ovJTy1wxJgjDya+jToTZbglVNJlE/Ul
q+9fo4IBsDCCAawwHwYDVR0jBBgwFoAUNyjNsnb8v1K0L0BtEPf0uTxrQuAwRgYD
VR0RBD8wPYYUaHR0cHM6Ly9zb21lLXVyaS5jb22gFAYDVQQUoA0MCys0MTIzNDU2
Nzg5gQ90ZXN0ZXJAdGVzdC5jb20wDgYDVR0PAQH/BAQDAgOIMCUGA1UdJQQeMBwG
CCsGAQUFBwMCBgcogYxdBQEGBgcogbU0BAEGMGIGA1UdHwRbMFkwV6BVoFOGUWh0
dHA6Ly8xMjcuMC4wLjE6NjEzNDYvc3NpL3Jldm9jYXRpb24vdjEvY3JsLzJiYzE2
MjllLWM2YWItNGNlNy1hMTlkLWYwN2Q1M2YwYzU3NzAdBgNVHQ4EFgQUYSDrfq7B
9LW8JqFf8Goypix19fswDwYDVR0TAQH/BAUwAwEBADAUBgNVHSAEDTALMAkGBwQA
i+xAAQEwYAYIKwYBBQUHAQEEVDBSMFAGCCsGAQUFBzACpkQWQmh0dHA6Ly8xMjcu
MC4wLjE6NjEzNDYvc3NpL2NhL2Q3NzgxNGI1LWIxZGMtNDIwNS1iZDlmLTA5OGE4
ZTRjNDlkZDAKBggqhkjOPQQDAgNJADBGAiEAuS3o1nlzchI4I0ag0qUxpAUD8/ot
qs3spp6Rlr/mP9wCIQDVavmou3AtikpwkUWe+ZM5HbrwAi6k6lt5nxTPk3tf0A==
-----END CERTIFICATE-----"#;

const REGISTRATION_CERT: &str = "eyJhbGciOiJFZERTQSIsInR5cCI6InJjLXdycCtqd3QiLCJ4NWMiOlsiTUlJREZqQ0NBc2lnQXdJQkFnSVJBV3k1ak0wVWFVT2toYWdBa0FwLzZmTXdCUVlESzJWd01CTXhFVEFQQmdOVkJBTU1DSEJ5YjJOcGRtbHpNQjRYRFRJMk1EUXhNREEzTlRnek1Wb1hEVE14TURRd09UQTNOVGd6TVZvd2dhTXhDekFKQmdOVkJBWU1Ba0ZVTVVNd1FRWURWUVJSRERwb2RIUndjem92TDNkaGJHeGxkQzF5Wld4NWFXNW5MWEJoY25SNUxYSmxaMmx6ZEhKNUxtUmxkaTV3Y205amFYWnBjeTF2Ym1VdVkyOXRNUmt3RndZRFZRUUREQkJHY21Wa1pYSnBheUJVWlhOMGFXNW5NUnd3R2dZRFZRUmhEQk5PVkZKQlZDMW1jbVZrWlhKcGF5QjBaWE4wTVJZd0ZBWURWUVFLREExR2NtVmtaWEpwYXlCVVpYTjBNQ293QlFZREsyVndBeUVBcTVJY3RqbG5XazVUeGV4WnNXNVhTTysrcTB6b2NHOXZYMk0wak5DdlJZMmpnZ0dlTUlJQm1qQWZCZ05WSFNNRUdEQVdnQlFnQm4zcitNTXpEQ2lseHdjbWJNTVRtdlVqOWpBZUJnTlZIUkVFRnpBVmhoTm9kSFJ3Y3pvdkwzTjFjSEJ2Y25RdVkyOXRNQTRHQTFVZER3RUIvd1FFQXdJRGlEQWxCZ05WSFNVRUhqQWNCZ2dyQmdFRkJRY0RBZ1lIS0lHTVhRVUJCZ1lIS0lHMU5BUUJCakJ0QmdOVkhSOEVaakJrTUdLZ1lLQmVobHhvZEhSd2N6b3ZMMk52Y21VdVpHVjJMbkJ5YjJOcGRtbHpMVzl1WlM1amIyMHZjM05wTDNKbGRtOWpZWFJwYjI0dmRqRXZZM0pzTHpCa05XUXhaak16TFRnellXRXRORFU0WXkxaU1tTmpMV0V5WkRrMU1tVmhNbUppWXpBZEJnTlZIUTRFRmdRVWRUS3JBeWtJcUNJZHBGT1NlRzQ5YlRadFY0b3dEd1lEVlIwVEFRSC9CQVV3QXdFQkFEQVVCZ05WSFNBRURUQUxNQWtHQndRQWkreEFBUUV3YXdZSUt3WUJCUVVIQVFFRVh6QmRNRnNHQ0NzR0FRVUZCekFDcGs4V1RXaDBkSEJ6T2k4dlkyOXlaUzVrWlhZdWNISnZZMmwyYVhNdGIyNWxMbU52YlM5emMya3ZZMkV2TkdWa01USTRNREl0TnpneU15MDBZMk5rTFRsalkyVXRNak0wTURRMk16WTFZVFkwTUFVR0F5dGxjQU5CQUtncDdkUlo2ZnVNa3lqbk5PbFBKdDZTeGZ5L0dQeGJQSUkwWHF5THAvT094U1BoUE4rcmJMMEh6eDFGMzFYWUcwVUZ6TFR4UkRQdmpoaXpQQ0p5L2dBPSIsIk1JSUJUakNDQVFDZ0F3SUJBZ0lVRmhRTjN3U0w3N2xOeWRIYnJFUTBudkFsVm93d0JRWURLMlZ3TUJNeEVUQVBCZ05WQkFNTUNIQnliMk5wZG1sek1CNFhEVEkyTURNeE1EQTVNekF3T0ZvWERUTXhNRE13T1RBNU16QXdPRm93RXpFUk1BOEdBMVVFQXd3SWNISnZZMmwyYVhNd0tqQUZCZ01yWlhBRElRQzZ0SjNZaEZPNHFhYUFicmpmSi9ibElNYmROdm5SSUpCS3BRWTRkNVFQenFObU1HUXdId1lEVlIwakJCZ3dGb0FVSUFaOTYvakRNd3dvcGNjSEptekRFNXIxSS9Zd0RnWURWUjBQQVFIL0JBUURBZ0VHTUIwR0ExVWREZ1FXQkJRZ0JuM3IrTU16RENpbHh3Y21iTU1UbXZVajlqQVNCZ05WSFJNQkFmOEVDREFHQVFIL0FnRUFNQVVHQXl0bGNBTkJBTVZ4c1JhUUl3OGdWSVd5QWNCaEcrVHRvT0NwUnBmZWRoNHU0MUJlaTlzU1k3NEFabm5TUlU1NmtZQjA5TTVKMDVXN2pXWDBSN05JSkVtMStUMm5XQWc9Il19.eyJpYXQiOjE3NzYwNjMzNDYsImV4cCI6MTc3ODY1NTM0NiwibmJmIjoxNzc2MDYzMzQ2LCJzdWIiOiJOVFJDSC1jaC5wcm9jaXZpcyIsImF1ZCI6WyJibGkiLCJibGEiXSwianRpIjoiMDU2ZmY3NTUtZTZjMS00OTBhLTg5N2MtODI4ZmU5N2M4ODJhIiwibmFtZSI6IlNwcmludCBSZXZpZXcgV1JQIiwic3ViX2xuIjoiUHJvY2l2aXMgQUciLCJjb3VudHJ5IjoiQ0giLCJyZWdpc3RyeV91cmkiOiJodHRwczovL3dhbGxldC1yZWx5aW5nLXBhcnR5LXJlZ2lzdHJ5LmRldi5wcm9jaXZpcy1vbmUuY29tLyIsInNydl9kZXNjcmlwdGlvbiI6W1t7ImxhbmciOiJlbiIsInZhbHVlIjoiVGhpcyBpcyBhIHNlcnZpY2UgZGVzY3JpcHRpb24ifV1dLCJlbnRpdGxlbWVudHMiOlsiaHR0cHM6Ly91cmkuZXRzaS5vcmcvMTk0NzUvRW50aXRsZW1lbnQvU2VydmljZV9Qcm92aWRlciJdLCJwcml2YWN5X3BvbGljeSI6Imh0dHBzOi8vcHJvY2l2aXMuY2gvcHJpdmFjeSIsImluZm9fdXJpIjoiaHR0cHM6Ly9wcm9jaXZpcy5jaC8iLCJzdXBlcnZpc29yeV9hdXRob3JpdHkiOnsiZW1haWwiOiJpbmZvQHByb2NpdmlzLmNoIiwicGhvbmUiOiIrNDEgNDQgNTIzIDY1IDM1IiwidXJpIjoid3d3LnByb2NpdmlzLmNoIn0sInBvbGljeV9pZCI6WyIwLjQuMC4xOTQ3NS4zLjEiXSwiY2VydGlmaWNhdGVfcG9saWN5IjoiaHR0cHM6Ly90ZXN0LmNlcnRpZmljYXRlL3BvbGljeSIsInN0YXR1cyI6eyJzdGF0dXNfbGlzdCI6eyJ1cmkiOiJodHRwczovL2NvcmUuZGV2LnByb2NpdmlzLW9uZS5jb20vc3NpL3Jldm9jYXRpb24vdjEvbGlzdC80NWM5MjZiZi1hNDUyLTRiMTctYmRhMS03OGZmM2I5ZGQxMjkiLCJpZHgiOiIyIn19LCJwcm92aWRlc19hdHRlc3RhdGlvbnMiOltdLCJjcmVkZW50aWFscyI6W3siZm9ybWF0IjoiZGMrc2Qtand0IiwibWV0YSI6eyJ2Y3RfdmFsdWVzIjpbInVybjpldS5ldXJvcGEuZWMuZXVkaTpwaWQ6MSJdfSwiY2xhaW0iOlt7InBhdGgiOlsiJC5naXZlbl9uYW1lIl0sInZhbHVlcyI6W119XX1dLCJwdXJwb3NlIjpbeyJsYW5nIjoiZW4iLCJ2YWx1ZSI6IlRoaXMgaXMgdGhlIGludGVuZGVkIHVzZSJ9XSwiaW50ZW5kZWRfdXNlX2lkIjoiZjA0ZmU2MjAtMjU4OC00NTFlLWI5OWMtNjJmYjUwZjFlZGQ2Iiwic3VwcG9ydF91cmkiOiJodHRwczovL3Byb2NpdmlzLmNoLyJ9.Amk_SIsm-o-xlAa-gQBwu9kc5iQ6O_3IG-lmuqZ4Ku6WwGcbjgOmYfK4OZN3WHP5XdvFTvQu0AUveEvtJ796DA";
#[tokio::test]
async fn test_get_credential_trust_detail_reports_ecosystem_errors_with_a_200() {
    // GIVEN an issuance no ecosystem trusted, as recorded when it ended
    let (context, organisation, _, identifier, ..) = TestContext::new_with_did(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, Default::default())
        .await;

    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Created,
            &identifier,
            "OPENID4VCI_FINAL1",
            TestingCredentialParams {
                role: Some(CredentialRole::Holder),
                ..Default::default()
            },
        )
        .await;

    let mut outcomes = EcosystemOutcomes::default();
    outcomes.record(
        "EUDI".into(),
        Err(HistoryErrorMetadata {
            error_code: ErrorCode::BR_0477,
            message: "not on the trust list".to_string(),
        }),
    );

    context
        .db
        .histories
        .create(
            &organisation,
            TestingHistoryParams {
                entity_id: Some(credential.id.into()),
                action: Some(HistoryAction::EcosystemsResolved),
                metadata: Some(HistoryMetadata::EcosystemsResolved(outcomes)),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context
        .api
        .credentials
        .get_trust_detail(&credential.id)
        .await;

    // THEN an untrusted issuer is an answer, not a failed request
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    assert_eq!(
        json!({
            "EUDI": {
                "result": "NOT_TRUSTED",
                "error": { "code": "BR_0477", "message": "not on the trust list" },
            }
        }),
        resp["ecosystemErrors"]
    );
}

#[tokio::test]
async fn test_get_credential_trust_detail_success() {
    // GIVEN
    let (context, organisation, _, identifier, ..) = TestContext::new_with_did(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, Default::default())
        .await;

    let ac_blob = context
        .db
        .blobs
        .create(TestingBlobParams {
            value: Some(ACCESS_CERT.as_bytes().to_vec()),
            r#type: Some(BlobType::HistoryMetadata),
            ..Default::default()
        })
        .await;
    let rc_blob = context
        .db
        .blobs
        .create(TestingBlobParams {
            value: Some(REGISTRATION_CERT.as_bytes().to_vec()),
            r#type: Some(BlobType::HistoryMetadata),
            ..Default::default()
        })
        .await;

    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Created,
            &identifier,
            "OPENID4VCI_FINAL1",
            TestingCredentialParams {
                role: Some(CredentialRole::Holder),
                ecosystem: Some("EUDI".into()),
                ..Default::default()
            },
        )
        .await;

    context
        .db
        .histories
        .create(
            &organisation,
            TestingHistoryParams {
                entity_id: Some(credential.id.into()),
                action: Some(HistoryAction::WrpAcReceived),
                metadata_blob_id: Some(ac_blob.id),
                ..Default::default()
            },
        )
        .await;

    context
        .db
        .histories
        .create(
            &organisation,
            TestingHistoryParams {
                entity_id: Some(credential.id.into()),
                action: Some(HistoryAction::WrpRcReceived),
                metadata_blob_id: Some(rc_blob.id),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context
        .api
        .credentials
        .get_trust_detail(&credential.id)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    let rp_data = json!({
         "country": "CH",
         "email": "tester@test.com",
         "identifier": "NTRCH-ch.procivis",
         "isPublicSector": false,
         "name": "Sprint Review WRP",
         "phone": "+4123456789",
         "serviceDescription": [
           {
             "en": "This is a service description"
           }
         ],
         "supervisoryAuthority": {
           "email": "info@procivis.ch",
           "phone": "+41 44 523 65 35",
           "uri": "www.procivis.ch"
         },
         "website": "https://procivis.ch/"
    });
    assert_eq!(
        resp,
        json!({
          "ecosystem": "EUDI",
          "ecosystemErrors": {},
          "eudiEcosystem": rp_data,
          "issuer": rp_data
        })
    );
}
