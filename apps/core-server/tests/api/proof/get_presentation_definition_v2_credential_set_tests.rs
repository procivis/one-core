use dcql::{ClaimQuery, CredentialQuery, CredentialSet, DcqlQuery};
use one_core::model::credential::{Credential, CredentialRole, CredentialStateEnum};
use one_core::model::credential_schema::{CredentialSchema, CredentialSchemaType};
use one_core::model::identifier::Identifier;
use one_core::model::organisation::Organisation;
use serde_json::json;
use similar_asserts::assert_eq;

use crate::fixtures::TestingCredentialParams;
use crate::fixtures::dcql::proof_for_dcql_query;
use crate::utils::context::TestContext;
use crate::utils::db_clients::credential_schemas::TestingCreateSchemaParams;
use crate::utils::field_match::FieldHelpers;

#[tokio::test]
async fn test_get_presentation_definition_v2_credential_sets_simple() {
    // GIVEN
    let (context, org, _, identifier, key) = TestContext::new_with_did(None).await;

    let schema = simple_schema(&context, &org, "https://example.org/foo").await;
    let schema2 = simple_schema(&context, &org, "https://example.org/foo2").await;
    let credential = simple_credential(&context, &identifier, &schema).await;

    let credential_query1 = CredentialQuery::sd_jwt_vc(vec![schema.schema_id.to_string()])
        .id("test_id")
        .claims(vec![
            ClaimQuery::builder()
                .path(vec!["firstName".to_string()])
                .build(),
        ])
        .build();
    let credential_query2 = CredentialQuery::sd_jwt_vc(vec![schema2.schema_id.to_string()])
        .id("test_id2")
        .claims(vec![
            ClaimQuery::builder()
                .path(vec!["firstName".to_string()])
                .build(),
        ])
        .build();
    let dcql_query = DcqlQuery::builder()
        .credentials(vec![credential_query1, credential_query2])
        .credential_sets(vec![CredentialSet {
            required: true,
            options: vec![vec!["test_id".into()], vec!["test_id2".into()]],
        }])
        .build();
    let proof = proof_for_dcql_query(
        &context,
        &org,
        &identifier,
        key,
        &dcql_query,
        "OPENID4VP_FINAL1",
    )
    .await;

    // WHEN
    let resp = context
        .api
        .proofs
        .presentation_definition_v2(proof.id)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let body = resp.json_value().await;
    body["credentialQueries"]["test_id"]["applicableCredentials"][0]["id"]
        .assert_eq(&credential.id);
    body["credentialQueries"]["test_id2"]["failureHint"]["reason"]
        .assert_eq(&"NO_CREDENTIAL".to_string());
    let credential_sets = json!([
      {
        "options": [
          [
            "test_id"
          ],
          [
            "test_id2"
          ]
        ],
        "required": true
      }
    ]);
    body["credentialSets"].assert_eq(&credential_sets);
}

#[tokio::test]
async fn test_get_presentation_definition_v2_credential_sets_multiple_credentials() {
    // GIVEN
    let (context, org, _, identifier, key) = TestContext::new_with_did(None).await;

    let schema = simple_schema(&context, &org, "https://example.org/foo").await;
    let schema2 = simple_schema(&context, &org, "https://example.org/foo2").await;
    let credential1 = simple_credential(&context, &identifier, &schema).await;
    let credential2 = simple_credential(&context, &identifier, &schema).await;
    let credential3 = simple_credential(&context, &identifier, &schema2).await;
    let credential4 = simple_credential(&context, &identifier, &schema2).await;

    let credential_query1 = CredentialQuery::sd_jwt_vc(vec![schema.schema_id.to_string()])
        .id("test_id")
        .claims(vec![
            ClaimQuery::builder()
                .path(vec!["firstName".to_string()])
                .build(),
        ])
        .build();
    let credential_query2 = CredentialQuery::sd_jwt_vc(vec![schema2.schema_id.to_string()])
        .id("test_id2")
        .claims(vec![
            ClaimQuery::builder()
                .path(vec!["firstName".to_string()])
                .build(),
        ])
        .build();
    let dcql_query = DcqlQuery::builder()
        .credentials(vec![credential_query1, credential_query2])
        .credential_sets(vec![
            CredentialSet {
                required: true,
                options: vec![vec!["test_id".into()]],
            },
            CredentialSet {
                required: true,
                options: vec![vec!["test_id2".into()]],
            },
        ])
        .build();
    let proof = proof_for_dcql_query(
        &context,
        &org,
        &identifier,
        key,
        &dcql_query,
        "OPENID4VP_FINAL1",
    )
    .await;

    // WHEN
    let resp = context
        .api
        .proofs
        .presentation_definition_v2(proof.id)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let body = resp.json_value().await;
    let query1_creds = body["credentialQueries"]["test_id"]["applicableCredentials"]
        .as_array()
        .unwrap();
    assert_eq!(query1_creds.len(), 2);
    assert!(
        query1_creds
            .iter()
            .any(|c| c["id"] == credential1.id.to_string())
    );
    assert!(
        query1_creds
            .iter()
            .any(|c| c["id"] == credential2.id.to_string())
    );
    let query2_creds = body["credentialQueries"]["test_id2"]["applicableCredentials"]
        .as_array()
        .unwrap();
    assert_eq!(query2_creds.len(), 2);
    assert!(
        query2_creds
            .iter()
            .any(|c| c["id"] == credential3.id.to_string())
    );
    assert!(
        query2_creds
            .iter()
            .any(|c| c["id"] == credential4.id.to_string())
    );
    let credential_sets = json!([
        {
            "options": [
                [
                    "test_id"
                ]
            ],
            "required": true
        },
        {
            "options": [
                [
                    "test_id2"
                ]
            ],
            "required": true
        }
    ]);
    body["credentialSets"].assert_eq(&credential_sets);
}

#[tokio::test]
async fn test_get_presentation_definition_v2_optional_credential_sets() {
    // GIVEN
    let (context, org, _, identifier, key) = TestContext::new_with_did(None).await;

    let schema = simple_schema(&context, &org, "https://example.org/foo").await;
    let schema2 = simple_schema(&context, &org, "https://example.org/foo2").await;
    let credential1 = simple_credential(&context, &identifier, &schema).await;
    let credential2 = simple_credential(&context, &identifier, &schema2).await;

    let credential_query1 = CredentialQuery::sd_jwt_vc(vec![schema.schema_id.to_string()])
        .id("test_id")
        .claims(vec![
            ClaimQuery::builder()
                .path(vec!["firstName".to_string()])
                .build(),
        ])
        .build();
    let credential_query2 = CredentialQuery::sd_jwt_vc(vec![schema2.schema_id.to_string()])
        .id("test_id2")
        .claims(vec![
            ClaimQuery::builder()
                .path(vec!["firstName".to_string()])
                .build(),
        ])
        .build();
    let dcql_query = DcqlQuery::builder()
        .credentials(vec![credential_query1, credential_query2])
        .credential_sets(vec![
            CredentialSet {
                required: true,
                options: vec![vec!["test_id".into()]],
            },
            CredentialSet {
                required: false,
                options: vec![vec!["test_id2".into()]],
            },
        ])
        .build();
    let proof = proof_for_dcql_query(
        &context,
        &org,
        &identifier,
        key,
        &dcql_query,
        "OPENID4VP_FINAL1",
    )
    .await;

    // WHEN
    let resp = context
        .api
        .proofs
        .presentation_definition_v2(proof.id)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let body = resp.json_value().await;
    body["credentialQueries"]["test_id"]["applicableCredentials"][0]["id"]
        .assert_eq(&credential1.id);
    body["credentialQueries"]["test_id2"]["applicableCredentials"][0]["id"]
        .assert_eq(&credential2.id);
    let credential_sets = json!([
        {
            "options": [
                [
                    "test_id"
                ]
            ],
            "required": true
        },
        {
            "options": [
                [
                    "test_id2"
                ]
            ],
            "required": false
        }
    ]);
    body["credentialSets"].assert_eq(&credential_sets);
}

async fn simple_schema(
    context: &TestContext,
    org: &Organisation,
    schema_id: &str,
) -> CredentialSchema {
    context
        .db
        .credential_schemas
        .create(
            schema_id,
            org,
            "NONE",
            TestingCreateSchemaParams {
                schema_id: Some(schema_id.to_string()),
                format: Some("SD_JWT_VC".to_owned()),
                schema_type: Some(CredentialSchemaType::SdJwtVc),
                ..Default::default()
            },
        )
        .await
}

async fn simple_credential(
    context: &TestContext,
    identifier: &Identifier,
    schema: &CredentialSchema,
) -> Credential {
    context
        .db
        .credentials
        .create(
            schema,
            CredentialStateEnum::Accepted,
            identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                role: Some(CredentialRole::Holder),
                ..Default::default()
            },
        )
        .await
}
