use one_core::model::claim_schema::ClaimSchema;
use one_core::model::credential::{CredentialRole, CredentialStateEnum};
use one_core::model::credential_schema::CredentialSchemaClaim;
use similar_asserts::assert_eq;
use sql_data_provider::test_utilities::get_dummy_date;
use uuid::Uuid;

use crate::fixtures::{ClaimData, TestingCredentialParams};
use crate::utils::context::TestContext;
use crate::utils::db_clients::credential_schemas::TestingCreateSchemaParams;
use crate::utils::field_match::FieldHelpers;

#[tokio::test]
async fn test_get_credential_success() {
    // GIVEN
    let (context, organisation, _, identifier, ..) = TestContext::new_with_did(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, "NONE", Default::default())
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
}

#[tokio::test]
async fn test_get_credential_certificate_identifier_success() {
    // GIVEN
    let (context, organisation, identifier, certificate, ..) =
        TestContext::new_with_certificate_identifier(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, "NONE", Default::default())
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
        .create("test", &organisation, "LVVC", Default::default())
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
            "NONE",
            TestingCreateSchemaParams {
                schema_id: Some("https://example.org/foo".to_owned()),
                format: Some("SD_JWT_VC".to_string()),
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
