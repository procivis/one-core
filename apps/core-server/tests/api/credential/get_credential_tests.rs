use one_core::model::blob::BlobType;
use one_core::model::claim_schema::ClaimSchema;
use one_core::model::credential::{CredentialRole, CredentialStateEnum, CredentialType};
use one_core::model::history::{HistoryAction, HistoryMetadata, WalletRelyingPartyMetadata};
use one_core::service::credential::dto::WalletInstanceAttestationDTO;
use similar_asserts::assert_eq;
use sql_data_provider::test_utilities::get_dummy_date;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

use crate::fixtures::{ClaimData, TestingCredentialParams};
use crate::utils::context::TestContext;
use crate::utils::db_clients::blobs::TestingBlobParams;
use crate::utils::db_clients::credential_schemas::TestingCreateSchemaParams;
use crate::utils::db_clients::histories::TestingHistoryParams;
use crate::utils::field_match::FieldHelpers;

#[tokio::test]
async fn test_get_credential_success() {
    // GIVEN
    let (context, organisation, _, identifier, ..) = TestContext::new_with_did(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, Default::default())
        .await;

    let wia_blob_value = serde_json::to_vec(&WalletInstanceAttestationDTO {
        name: "Wallet solution X by Wonderland State Department".to_string(),
        link: "https://wonderland.gov".to_string(),
        attestation: "eyJhbGciOiJFUzI1NiIsInR5cCI6Im9hdXRoLWNsaWVudC1hdHRlc3RhdGlvbitqd3QifQ.eyJpYXQiOjE3NTY3MDc1NTcsImV4cCI6MTc1Njc5Mzk1NywibmJmIjoxNzU2NzA3NTU3LCJpc3MiOiJodHRwczovL2NvcmUuZGV2LnByb2NpdmlzLW9uZS5jb20iLCJzdWIiOiJodHRwczovL2NvcmUuZGV2LnByb2NpdmlzLW9uZS5jb20vUFJPQ0lWSVNfT05FIiwiY25mIjp7Imp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IkdtbV9IbWd3SHZPNUpWZ1lPX3k0TG9hSTRLMzVoVDlmYzByb0lkZjVpRUEifX19.0QT5ybzrQx0d0ID2xx4hzH5NUodykyju2fyo3wIu7ZSobA26gYjcMvZZstg-GcZxjguo9rEkrzdm9ZUt-44wTw".to_string(),
    }).unwrap();

    let wallet_instance_attestation_blob = context
        .db
        .blobs
        .create(TestingBlobParams {
            value: Some(wia_blob_value),
            r#type: Some(BlobType::WalletInstanceAttestation),
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
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                wallet_instance_attestation_blob_id: Some(wallet_instance_attestation_blob.id),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context.api.credentials.get(&credential.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    resp["id"].assert_eq(&credential.id);
    resp["schema"]["organisationId"].assert_eq(&organisation.id);
    assert_eq!(resp["schema"]["name"], "test");
    assert_eq!(resp["schema"]["translations"]["name"]["en"], "test");
    assert!(resp["revocationDate"].is_null());
    assert!(resp["expiresAt"].is_null());
    assert_eq!(resp["state"], "CREATED");
    assert_eq!(resp["role"], "ISSUER");
    assert_eq!(resp["protocol"], "OPENID4VCI_DRAFT13");
    assert_eq!(
        resp["walletInstanceAttestation"]["name"],
        "Wallet solution X by Wonderland State Department"
    );
    assert_eq!(
        resp["walletInstanceAttestation"]["link"],
        "https://wonderland.gov"
    );
    assert_eq!(
        resp["walletInstanceAttestation"]["attestation"],
        "eyJhbGciOiJFUzI1NiIsInR5cCI6Im9hdXRoLWNsaWVudC1hdHRlc3RhdGlvbitqd3QifQ.eyJpYXQiOjE3NTY3MDc1NTcsImV4cCI6MTc1Njc5Mzk1NywibmJmIjoxNzU2NzA3NTU3LCJpc3MiOiJodHRwczovL2NvcmUuZGV2LnByb2NpdmlzLW9uZS5jb20iLCJzdWIiOiJodHRwczovL2NvcmUuZGV2LnByb2NpdmlzLW9uZS5jb20vUFJPQ0lWSVNfT05FIiwiY25mIjp7Imp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IkdtbV9IbWd3SHZPNUpWZ1lPX3k0TG9hSTRLMzVoVDlmYzByb0lkZjVpRUEifX19.0QT5ybzrQx0d0ID2xx4hzH5NUodykyju2fyo3wIu7ZSobA26gYjcMvZZstg-GcZxjguo9rEkrzdm9ZUt-44wTw"
    );
    assert_eq!(
        resp["claims"][0]["schema"]["translations"]["name"]["en"],
        "firstName"
    );
    assert_eq!(
        resp["claims"][1]["schema"]["translations"]["name"]["en"],
        "isOver18"
    );
}

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
async fn test_get_credential_with_trust_information_success() {
    // GIVEN
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
            CredentialStateEnum::Accepted,
            &identifier,
            "OPENID4VCI_FINAL1",
            TestingCredentialParams {
                role: Some(CredentialRole::Holder),
                ecosystem: Some("EUDI".into()),
                ..Default::default()
            },
        )
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

    let rc_blob = context
        .db
        .blobs
        .create(TestingBlobParams {
            value: Some(REGISTRATION_CERT.as_bytes().to_vec()),
            r#type: Some(BlobType::HistoryMetadata),
            ..Default::default()
        })
        .await;
    context
        .db
        .histories
        .create(
            &organisation,
            TestingHistoryParams {
                action: Some(HistoryAction::WrpRcReceived),
                entity_id: Some(credential.id.into()),
                metadata: Some(HistoryMetadata::WalletRelyingParty(
                    WalletRelyingPartyMetadata {
                        name: Some("Sprint Review WRP".to_string()),
                        ..Default::default()
                    },
                )),
                metadata_blob_id: Some(rc_blob.id),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context.api.credentials.get(&credential.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    resp["id"].assert_eq(&credential.id);
    assert_eq!(resp["trustInformation"]["name"], "Sprint Review WRP");
    assert_eq!(resp["trustInformation"]["result"], "TRUSTED");
    assert!(!resp["trustInformation"]["receivedAt"].is_null());
}

#[tokio::test]
async fn test_get_credential_certificate_identifier_success() {
    // GIVEN
    let (context, organisation, identifier, certificate, ..) =
        TestContext::new_with_certificate_identifier(None).await;
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
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams::default(),
        )
        .await;

    // WHEN
    let resp = context.api.credentials.get(&credential.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    resp["id"].assert_eq(&credential.id);
    resp["schema"]["organisationId"].assert_eq(&organisation.id);
    assert_eq!(resp["schema"]["name"], "test");
    assert!(resp["revocationDate"].is_null());
    assert!(resp["expiresAt"].is_null());
    assert_eq!(resp["state"], "CREATED");
    assert_eq!(resp["role"], "ISSUER");
    assert_eq!(resp["protocol"], "OPENID4VCI_DRAFT13");
    assert_eq!(resp["issuerCertificate"]["id"], certificate.id.to_string());
    assert_eq!(
        resp["issuerCertificate"]["x509Attributes"]["subject"],
        "CN=test cert"
    );
}

#[tokio::test]
async fn test_get_credential_success_metadata() {
    // GIVEN
    let (context, org, _, identifier, _) = TestContext::new_with_did(None).await;

    let claim_schema_id = Uuid::new_v4();
    let metadata_claim_schema_id = Uuid::new_v4();
    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "Simple test schema",
            &org,
            TestingCreateSchemaParams {
                schema_id: Some("https://example.org/foo".to_owned()),
                format: Some("SD_JWT_VC".into()),
                claim_schemas: Some(vec![
                    ClaimSchema {
                        id: claim_schema_id.into(),
                        key: "string_claim".to_string(),
                        data_type: "STRING".to_string(),
                        created_date: get_dummy_date(),
                        last_modified: get_dummy_date(),
                        array: false,
                        metadata: false,
                        required: true,
                        translations: Default::default(),
                    },
                    ClaimSchema {
                        id: metadata_claim_schema_id.into(),
                        key: "iss".to_string(),
                        data_type: "STRING".to_string(),
                        created_date: get_dummy_date(),
                        last_modified: get_dummy_date(),
                        array: false,
                        metadata: true,
                        required: false,
                        translations: Default::default(),
                    },
                ]),
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
                claims_data: Some(vec![
                    ClaimData {
                        schema_id: claim_schema_id.into(),
                        path: "string_claim".to_string(),
                        value: Some("test-value-first".to_string()),
                        selectively_disclosable: false,
                    },
                    ClaimData {
                        schema_id: metadata_claim_schema_id.into(),
                        path: "iss".to_string(),
                        value: Some("some-issuer".to_string()),
                        selectively_disclosable: false,
                    },
                ]),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context.api.credentials.get(&credential.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    resp["id"].assert_eq(&credential.id);
    assert_eq!(resp["claims"].as_array().unwrap().len(), 1);
    assert_eq!(resp["claims"][0]["path"], "string_claim".to_string());
}

#[tokio::test]
async fn test_get_credential_success_batch() {
    // GIVEN
    let (context, org, _, identifier, _) = TestContext::new_with_did(None).await;

    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "Simple batch schema",
            &org,
            TestingCreateSchemaParams {
                batch_size: Some(2),
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
                r#type: Some(CredentialType::BatchParent),
                role: Some(CredentialRole::Holder),
                ..Default::default()
            },
        )
        .await;

    let item_credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                r#type: Some(CredentialType::BatchItem),
                parent_id: Some(parent_credential.id),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context.api.credentials.get(&parent_credential.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    resp["id"].assert_eq(&parent_credential.id);
    assert_eq!(resp["type"].as_str().unwrap(), "BATCH_PARENT");
    assert!(!resp.as_object().unwrap().contains_key("parentId"));
    assert_eq!(
        resp["remainingBatchItemCount"]
            .as_number()
            .unwrap()
            .as_u64()
            .unwrap(),
        1
    );

    // WHEN
    let resp = context.api.credentials.get(&item_credential.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    resp["id"].assert_eq(&item_credential.id);
    assert_eq!(resp["type"].as_str().unwrap(), "BATCH_ITEM");
    assert!(
        !resp
            .as_object()
            .unwrap()
            .contains_key("remainingBatchItemCount")
    );
    assert_eq!(
        resp["parentId"].as_str().unwrap(),
        parent_credential.id.to_string()
    );
}

#[tokio::test]
async fn test_get_credential_with_expires_at() {
    // GIVEN
    let (context, organisation, _, identifier, ..) = TestContext::new_with_did(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, Default::default())
        .await;

    let expires_at = get_dummy_date();
    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                expires_at: Some(expires_at),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context.api.credentials.get(&credential.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    resp["id"].assert_eq(&credential.id);
    let returned_expires_at =
        OffsetDateTime::parse(resp["expiresAt"].as_str().unwrap(), &Rfc3339).unwrap();
    assert_eq!(returned_expires_at, expires_at);
}

#[tokio::test]
async fn test_get_mdoc_batch_item_expires_at_matches_mso_validity_expiration() {
    // GIVEN
    let (context, organisation, _, identifier, ..) = TestContext::new_with_did(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test",
            &organisation,
            TestingCreateSchemaParams {
                format: Some("MDOC".into()),
                batch_size: Some(2),
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
                r#type: Some(CredentialType::BatchParent),
                ..Default::default()
            },
        )
        .await;

    // MDOC's `expirationSeconds` config default is 72h - pick a real expiration that doesn't
    // land on `issuanceDate + expirationSeconds`, so a fallback to that computed value (instead
    // of the batch item's own real `expires_at`) would be caught by the assertions below
    let expires_at = get_dummy_date() + time::Duration::hours(1);
    let item_credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                r#type: Some(CredentialType::BatchItem),
                parent_id: Some(parent_credential.id),
                expires_at: Some(expires_at),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context.api.credentials.get(&item_credential.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    resp["id"].assert_eq(&item_credential.id);

    let returned_expires_at =
        OffsetDateTime::parse(resp["expiresAt"].as_str().unwrap(), &Rfc3339).unwrap();
    let mso_expiration = OffsetDateTime::parse(
        resp["mdocMsoValidity"]["expiration"].as_str().unwrap(),
        &Rfc3339,
    )
    .unwrap();

    // the top-level credential expiration must match the mdoc-specific MSO validity expiration
    assert_eq!(expires_at, returned_expires_at);
    assert_eq!(expires_at, mso_expiration);
}
