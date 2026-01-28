use one_core::model::blob::BlobType;
use one_core::model::claim_schema::ClaimSchema;
use one_core::model::credential::{CredentialRole, CredentialStateEnum};
use one_core::model::credential_schema::CredentialSchemaClaim;
use one_core::service::credential::dto::WalletAppAttestationDTO;
use similar_asserts::assert_eq;
use sql_data_provider::test_utilities::get_dummy_date;
use uuid::Uuid;

use crate::fixtures::{ClaimData, TestingCredentialParams};
use crate::utils::context::TestContext;
use crate::utils::db_clients::blobs::TestingBlobParams;
use crate::utils::db_clients::credential_schemas::TestingCreateSchemaParams;
use crate::utils::field_match::FieldHelpers;

#[tokio::test]
async fn test_get_credential_success() {
    // GIVEN
    let (context, organisation, _, identifier, ..) = TestContext::new_with_did(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, None, Default::default())
        .await;

    let waa_blob_value = serde_json::to_vec(&WalletAppAttestationDTO {
        name: "Wallet solution X by Wonderland State Department".to_string(),
        link: "https://wonderland.gov".to_string(),
        attestation: "eyJhbGciOiJFUzI1NiIsInR5cCI6Im9hdXRoLWNsaWVudC1hdHRlc3RhdGlvbitqd3QifQ.eyJpYXQiOjE3NTY3MDc1NTcsImV4cCI6MTc1Njc5Mzk1NywibmJmIjoxNzU2NzA3NTU3LCJpc3MiOiJodHRwczovL2NvcmUuZGV2LnByb2NpdmlzLW9uZS5jb20iLCJzdWIiOiJodHRwczovL2NvcmUuZGV2LnByb2NpdmlzLW9uZS5jb20vUFJPQ0lWSVNfT05FIiwiY25mIjp7Imp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IkdtbV9IbWd3SHZPNUpWZ1lPX3k0TG9hSTRLMzVoVDlmYzByb0lkZjVpRUEifX19.0QT5ybzrQx0d0ID2xx4hzH5NUodykyju2fyo3wIu7ZSobA26gYjcMvZZstg-GcZxjguo9rEkrzdm9ZUt-44wTw".to_string(),
    }).unwrap();

    let wallet_app_attestation_blob = context
        .db
        .blobs
        .create(TestingBlobParams {
            value: Some(waa_blob_value),
            r#type: Some(BlobType::WalletAppAttestation),
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
                wallet_app_attestation_blob_id: Some(wallet_app_attestation_blob.id),
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
    assert!(resp["revocationDate"].is_null());
    assert_eq!(resp["state"], "CREATED");
    assert_eq!(resp["role"], "ISSUER");
    assert_eq!(resp["protocol"], "OPENID4VCI_DRAFT13");
    assert_eq!(
        resp["walletAppAttestation"]["name"],
        "Wallet solution X by Wonderland State Department"
    );
    assert_eq!(
        resp["walletAppAttestation"]["link"],
        "https://wonderland.gov"
    );
    assert_eq!(
        resp["walletAppAttestation"]["attestation"],
        "eyJhbGciOiJFUzI1NiIsInR5cCI6Im9hdXRoLWNsaWVudC1hdHRlc3RhdGlvbitqd3QifQ.eyJpYXQiOjE3NTY3MDc1NTcsImV4cCI6MTc1Njc5Mzk1NywibmJmIjoxNzU2NzA3NTU3LCJpc3MiOiJodHRwczovL2NvcmUuZGV2LnByb2NpdmlzLW9uZS5jb20iLCJzdWIiOiJodHRwczovL2NvcmUuZGV2LnByb2NpdmlzLW9uZS5jb20vUFJPQ0lWSVNfT05FIiwiY25mIjp7Imp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IkdtbV9IbWd3SHZPNUpWZ1lPX3k0TG9hSTRLMzVoVDlmYzByb0lkZjVpRUEifX19.0QT5ybzrQx0d0ID2xx4hzH5NUodykyju2fyo3wIu7ZSobA26gYjcMvZZstg-GcZxjguo9rEkrzdm9ZUt-44wTw"
    );
}

#[tokio::test]
async fn test_get_credential_certificate_identifier_success() {
    // GIVEN
    let (context, organisation, identifier, certificate, ..) =
        TestContext::new_with_certificate_identifier(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, None, Default::default())
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
async fn test_get_credential_with_lvvc_success() {
    // GIVEN
    let (context, organisation, _, identifier, ..) = TestContext::new_with_did(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test",
            &organisation,
            Some("LVVC".into()),
            Default::default(),
        )
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

    context
        .db
        .validity_credentials
        .create_lvvc(None, vec![], credential.id)
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
    assert!(!resp["lvvcIssuanceDate"].is_null());
    assert_eq!(resp["state"], "CREATED");
    assert_eq!(resp["role"], "ISSUER");
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
            None,
            TestingCreateSchemaParams {
                schema_id: Some("https://example.org/foo".to_owned()),
                format: Some("SD_JWT_VC".into()),
                claim_schemas: Some(vec![
                    CredentialSchemaClaim {
                        schema: ClaimSchema {
                            id: claim_schema_id.into(),
                            key: "string_claim".to_string(),
                            data_type: "STRING".to_string(),
                            created_date: get_dummy_date(),
                            last_modified: get_dummy_date(),
                            array: false,
                            metadata: false,
                        },
                        required: true,
                    },
                    CredentialSchemaClaim {
                        schema: ClaimSchema {
                            id: metadata_claim_schema_id.into(),
                            key: "iss".to_string(),
                            data_type: "STRING".to_string(),
                            created_date: get_dummy_date(),
                            last_modified: get_dummy_date(),
                            array: false,
                            metadata: true,
                        },
                        required: false,
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
