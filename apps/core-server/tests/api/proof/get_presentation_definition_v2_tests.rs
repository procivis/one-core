use dcql::{ClaimQuery, CredentialQuery, DcqlQuery, PathSegment};
use one_core::model::credential::{Credential, CredentialRole, CredentialStateEnum};
use one_core::model::credential_schema::CredentialSchema;
use one_core::model::identifier::Identifier;
use one_core::model::organisation::Organisation;
use serde_json::json;
use similar_asserts::assert_eq;
use uuid::Uuid;

use crate::fixtures::dcql::proof_for_dcql_query;
use crate::fixtures::{ClaimData, TestingCredentialParams};
use crate::utils::context::TestContext;
use crate::utils::field_match::FieldHelpers;

#[tokio::test]
async fn test_get_presentation_definition_2_simple_credential_success() {
    // GIVEN
    let (context, org, _, identifier, key) = TestContext::new_with_did(None).await;
    let schema = complex_sd_jwt_vc_credential_schema(&context, &org).await;
    let claims = vec![claim_data(
        "required_claim",
        "required_claim",
        Some("value"),
        true,
        &schema,
    )];
    let credential = create_credential(
        &context,
        &identifier,
        &schema,
        claims,
        CredentialStateEnum::Accepted,
    )
    .await;

    let credential_query = CredentialQuery::sd_jwt_vc(vec![schema.schema_id])
        .id("test_query_id")
        .claims(vec![
            ClaimQuery::builder()
                .path(vec!["required_claim".to_string()])
                .build(),
        ])
        .build();
    let dcql_query = DcqlQuery::builder()
        .credentials(vec![credential_query])
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
    body["credentialQueries"]["test_query_id"]["applicableCredentials"][0]["id"]
        .assert_eq(&credential.id);
    let credential_sets = json!([
      {
        "options": [
          [
            "test_query_id"
          ]
        ],
        "required": true
      }
    ]);
    body["credentialSets"].assert_eq(&credential_sets);
}

#[tokio::test]
async fn test_get_presentation_definition_2_claim_filtering_success() {
    // GIVEN
    let (context, org, _, identifier, key) = TestContext::new_with_did(None).await;
    let schema = complex_sd_jwt_vc_credential_schema(&context, &org).await;
    let claims = vec![
        claim_data(
            "required_claim",
            "required_claim",
            Some("value"),
            true,
            &schema,
        ),
        claim_data(
            "not_required_claim",
            "not_required_claim",
            Some("value"),
            true,
            &schema,
        ),
    ];
    let credential = create_credential(
        &context,
        &identifier,
        &schema,
        claims,
        CredentialStateEnum::Accepted,
    )
    .await;

    let credential_query = CredentialQuery::sd_jwt_vc(vec![schema.schema_id])
        .id("test_query_id")
        .claims(vec![
            ClaimQuery::builder()
                .path(vec!["required_claim".to_string()])
                .build(),
        ])
        .build();
    let dcql_query = DcqlQuery::builder()
        .credentials(vec![credential_query])
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
    body["credentialQueries"]["test_query_id"]["applicableCredentials"][0]["id"]
        .assert_eq(&credential.id);
    let claims = body["credentialQueries"]["test_query_id"]["applicableCredentials"][0]["claims"]
        .as_array()
        .unwrap();
    assert_eq!(claims.len(), 1);
    assert!(claims.iter().any(|c| c["path"] == "required_claim"
        && c["userSelection"] == false
        && c["required"] == true));
    let credential_sets = json!([
      {
        "options": [
          [
            "test_query_id"
          ]
        ],
        "required": true
      }
    ]);
    body["credentialSets"].assert_eq(&credential_sets);
}

#[tokio::test]
async fn test_get_presentation_definition_2_claim_non_sd_extra_claim() {
    // GIVEN
    let (context, org, _, identifier, key) = TestContext::new_with_did(None).await;
    let schema = complex_sd_jwt_vc_credential_schema(&context, &org).await;
    let claims = vec![
        claim_data(
            "required_claim",
            "required_claim",
            Some("value"),
            true,
            &schema,
        ),
        claim_data(
            "not_required_claim",
            "not_required_claim",
            Some("value"),
            false,
            &schema,
        ),
    ];
    let credential = create_credential(
        &context,
        &identifier,
        &schema,
        claims,
        CredentialStateEnum::Accepted,
    )
    .await;

    let credential_query = CredentialQuery::sd_jwt_vc(vec![schema.schema_id])
        .id("test_query_id")
        .claims(vec![
            ClaimQuery::builder()
                .path(vec!["required_claim".to_string()])
                .build(),
        ])
        .build();
    let dcql_query = DcqlQuery::builder()
        .credentials(vec![credential_query])
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
    body["credentialQueries"]["test_query_id"]["applicableCredentials"][0]["id"]
        .assert_eq(&credential.id);
    let claims = body["credentialQueries"]["test_query_id"]["applicableCredentials"][0]["claims"]
        .as_array()
        .unwrap();
    assert_eq!(claims.len(), 2);
    assert!(claims.iter().any(|c| c["path"] == "required_claim"
        && c["userSelection"] == false
        && c["required"] == true));
    // Because the claim is not selectively disclosable it will be included in the response,
    // despite not being asked for by the verifier.
    assert!(claims.iter().any(|c| c["path"] == "not_required_claim"
        && c["userSelection"] == false
        && c["required"] == true));
    let credential_sets = json!([
      {
        "options": [
          [
            "test_query_id"
          ]
        ],
        "required": true
      }
    ]);
    body["credentialSets"].assert_eq(&credential_sets);
}

#[tokio::test]
async fn test_get_presentation_definition_2_with_user_selection() {
    // GIVEN
    let (context, org, _, identifier, key) = TestContext::new_with_did(None).await;
    let schema = complex_sd_jwt_vc_credential_schema(&context, &org).await;
    let claims = vec![
        claim_data(
            "required_claim",
            "required_claim",
            Some("value"),
            true,
            &schema,
        ),
        claim_data(
            "not_required_claim",
            "not_required_claim",
            Some("value"),
            true,
            &schema,
        ),
    ];
    let credential = create_credential(
        &context,
        &identifier,
        &schema,
        claims,
        CredentialStateEnum::Accepted,
    )
    .await;

    let credential_query = CredentialQuery::sd_jwt_vc(vec![schema.schema_id])
        .id("test_query_id")
        .claims(vec![
            ClaimQuery::builder()
                .path(vec!["required_claim".to_string()])
                .build(),
            ClaimQuery::builder()
                .path(vec!["not_required_claim".to_string()])
                .required(false)
                .build(),
        ])
        .build();
    let dcql_query = DcqlQuery::builder()
        .credentials(vec![credential_query])
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
    body["credentialQueries"]["test_query_id"]["applicableCredentials"][0]["id"]
        .assert_eq(&credential.id);
    let claims = body["credentialQueries"]["test_query_id"]["applicableCredentials"][0]["claims"]
        .as_array()
        .unwrap();
    assert_eq!(claims.len(), 2);
    assert!(claims.iter().any(|c| c["path"] == "required_claim"
        && c["userSelection"] == false
        && c["required"] == true));
    // Optional extra claim with user selection
    assert!(claims.iter().any(|c| c["path"] == "not_required_claim"
        && c["userSelection"] == true
        && c["required"] == false));
    let credential_sets = json!([
      {
        "options": [
          [
            "test_query_id"
          ]
        ],
        "required": true
      }
    ]);
    body["credentialSets"].assert_eq(&credential_sets);
}

#[tokio::test]
async fn test_get_presentation_definition_2_with_user_selection_nesting_mixed_sd() {
    // GIVEN
    let (context, org, _, identifier, key) = TestContext::new_with_did(None).await;
    let schema = complex_sd_jwt_vc_credential_schema(&context, &org).await;
    let claims = vec![
        claim_data("root obj", "root obj", None, true, &schema),
        claim_data(
            "root obj/string",
            "root obj/string",
            Some("nested string"),
            true,
            &schema,
        ),
        claim_data(
            "root obj/number",
            "root obj/number",
            Some("42"),
            false,
            &schema,
        ),
        claim_data(
            "required_claim",
            "required_claim",
            Some("value"),
            true,
            &schema,
        ),
    ];
    let credential = create_credential(
        &context,
        &identifier,
        &schema,
        claims,
        CredentialStateEnum::Accepted,
    )
    .await;

    let credential_query = CredentialQuery::sd_jwt_vc(vec![schema.schema_id])
        .id("test_query_id")
        .claims(vec![
            ClaimQuery::builder()
                .path(vec!["required_claim".to_string()])
                .build(),
            // Optionality: the "root obj" claim and the "root obj/string" claim can _both_ be
            // toggled. Because they are nested, there are interdependencies in the selection
            // (which the front-end will have to correctly handle).
            ClaimQuery::builder()
                .path(vec!["root obj".to_string()])
                .required(false)
                .build(),
            ClaimQuery::builder()
                .path(vec!["root obj".to_string(), "string".to_string()])
                .required(false)
                .build(),
        ])
        .build();
    let dcql_query = DcqlQuery::builder()
        .credentials(vec![credential_query])
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
    body["credentialQueries"]["test_query_id"]["applicableCredentials"][0]["id"]
        .assert_eq(&credential.id);
    let claims = body["credentialQueries"]["test_query_id"]["applicableCredentials"][0]["claims"]
        .as_array()
        .unwrap();
    assert_eq!(claims.len(), 2);
    assert!(claims.iter().any(|c| c["path"] == "required_claim"
        && c["userSelection"] == false
        && c["required"] == true));
    // Optional extra claim with user selection
    let root_obj = claims
        .iter()
        .find(|c| c["path"] == "root obj")
        .expect("root obj not found");
    root_obj["userSelection"].assert_eq(&true);
    root_obj["required"].assert_eq(&false);
    // Children are nested
    let claims = root_obj["value"].as_array().unwrap();
    // sd-child, which was also explicitly requested as optional
    // -> user selection  but not required
    assert!(claims.iter().any(|c| c["path"] == "root obj/string"
        && c["userSelection"] == true
        && c["required"] == false));
    // Non-sd child -> no user selection & required
    assert!(claims.iter().any(|c| c["path"] == "root obj/number"
        && c["userSelection"] == false
        && c["required"] == true));
    let credential_sets = json!([
      {
        "options": [
          [
            "test_query_id"
          ]
        ],
        "required": true
      }
    ]);
    body["credentialSets"].assert_eq(&credential_sets);
}

#[tokio::test]
async fn test_get_presentation_definition_2_no_credential_no_schema() {
    // GIVEN
    let (context, org, _, identifier, key) = TestContext::new_with_did(None).await;
    let credential_query = CredentialQuery::sd_jwt_vc(vec!["https://test-vct.com".to_string()])
        .id("test_query_id")
        .claims(vec![
            ClaimQuery::builder()
                .path(vec!["required_claim".to_string()])
                .build(),
        ])
        .build();
    let dcql_query = DcqlQuery::builder()
        .credentials(vec![credential_query])
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
    let expected_body = json!({
      "credentialQueries": {
        "test_query_id": {
          "failureHint": {
            "reason": "NO_CREDENTIAL"
          },
          "multiple": false
        }
      },
      "credentialSets": [
        {
          "options": [
            [
              "test_query_id"
            ]
          ],
          "required": true
        }
      ]
    });
    body.assert_eq(&expected_body);
}

#[tokio::test]
async fn test_get_presentation_definition_2_nested_array_element_selection() {
    // GIVEN
    let (context, org, _, identifier, key) = TestContext::new_with_did(None).await;
    let schema = complex_sd_jwt_vc_credential_schema(&context, &org).await;
    let claims = vec![
        claim_data(
            "required_claim",
            "required_claim",
            Some("value"),
            true,
            &schema,
        ),
        claim_data("root obj array", "root obj array", None, true, &schema),
        claim_data("root obj array/0", "root obj array", None, true, &schema),
        claim_data("root obj array/1", "root obj array", None, true, &schema),
        claim_data(
            "root obj array/0/nested object",
            "root obj array/nested object",
            None,
            true,
            &schema,
        ),
        claim_data(
            "root obj array/1/nested object",
            "root obj array/nested object",
            None,
            true,
            &schema,
        ),
        claim_data(
            "root obj array/0/nested object/nested string array",
            "root obj array/nested object/nested string array",
            None,
            true,
            &schema,
        ),
        claim_data(
            "root obj array/1/nested object/nested string array",
            "root obj array/nested object/nested string array",
            None,
            true,
            &schema,
        ),
        claim_data(
            "root obj array/0/nested object/nested string array/0",
            "root obj array/nested object/nested string array",
            Some("string arr 00"),
            true,
            &schema,
        ),
        claim_data(
            "root obj array/1/nested object/nested string array/0",
            "root obj array/nested object/nested string array",
            Some("string arr 10"),
            true,
            &schema,
        ),
        claim_data(
            "root obj array/0/nested object/nested string array/1",
            "root obj array/nested object/nested string array",
            Some("string arr 01"),
            true,
            &schema,
        ),
        claim_data(
            "root obj array/1/nested object/nested string array/1",
            "root obj array/nested object/nested string array",
            Some("string arr 11"),
            true,
            &schema,
        ),
    ];
    let credential = create_credential(
        &context,
        &identifier,
        &schema,
        claims,
        CredentialStateEnum::Accepted,
    )
    .await;

    let credential_query = CredentialQuery::sd_jwt_vc(vec![schema.schema_id])
        .id("test_query_id")
        .claims(vec![
            ClaimQuery::builder()
                .path(vec![
                    "root obj array".into(),
                    PathSegment::ArrayAll,
                    "nested object".into(),
                    "nested string array".into(),
                    PathSegment::ArrayIndex(1),
                ])
                .required(false)
                .build(),
        ])
        .build();
    let dcql_query = DcqlQuery::builder()
        .credentials(vec![credential_query])
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
    body["credentialQueries"]["test_query_id"]["applicableCredentials"][0]["id"]
        .assert_eq(&credential.id);
    let root_obj_array =
        &body["credentialQueries"]["test_query_id"]["applicableCredentials"][0]["claims"][0];
    root_obj_array["userSelection"].assert_eq(&false);
    root_obj_array["required"].assert_eq(&false);

    let values = root_obj_array["value"]
        .as_array()
        .expect("root obj array value");
    assert_eq!(values.len(), 2);
    values[0]["userSelection"].assert_eq(&false);
    values[0]["required"].assert_eq(&false);
    values[1]["userSelection"].assert_eq(&false);
    values[1]["required"].assert_eq(&false);

    let nested_string_array1 = &values[0]["value"][0]["value"][0]["value"]
        .as_array()
        .unwrap();
    assert_eq!(nested_string_array1.len(), 1); // index 0 has been filtered out
    let nested_string1 = &nested_string_array1[0];
    nested_string1["userSelection"].assert_eq(&true);
    nested_string1["required"].assert_eq(&false);
    nested_string1["value"].assert_eq(&"string arr 01".to_string());
    nested_string1["path"]
        .assert_eq(&"root obj array/0/nested object/nested string array/1".to_string());

    let nested_string_array2 = &values[1]["value"][0]["value"][0]["value"]
        .as_array()
        .unwrap();
    assert_eq!(nested_string_array2.len(), 1); // index 0 has been filtered out
    let nested_string2 = &nested_string_array2[0];
    nested_string2["userSelection"].assert_eq(&true);
    nested_string2["required"].assert_eq(&false);
    nested_string2["value"].assert_eq(&"string arr 11".to_string());
    nested_string2["path"]
        .assert_eq(&"root obj array/1/nested object/nested string array/1".to_string());
}

#[tokio::test]
async fn test_get_presentation_definition_2_no_credential_with_schema() {
    // GIVEN
    let (context, org, _, identifier, key) = TestContext::new_with_did(None).await;
    let schema = complex_sd_jwt_vc_credential_schema(&context, &org).await;
    let credential_query = CredentialQuery::sd_jwt_vc(vec![schema.schema_id])
        .id("test_query_id")
        .claims(vec![
            ClaimQuery::builder()
                .path(vec!["required_claim".to_string()])
                .build(),
        ])
        .build();
    let dcql_query = DcqlQuery::builder()
        .credentials(vec![credential_query])
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
    body["credentialQueries"]["test_query_id"]["failureHint"]["credentialSchema"]["id"]
        .assert_eq(&schema.id);
    body["credentialQueries"]["test_query_id"]["failureHint"]["reason"]
        .assert_eq(&"NO_CREDENTIAL".to_string());
    let credential_sets = json!([
      {
        "options": [
          [
            "test_query_id"
          ]
        ],
        "required": true
      }
    ]);
    body["credentialSets"].assert_eq(&credential_sets);
}

#[tokio::test]
async fn test_get_presentation_definition_2_inapplicable_credential_with_schema() {
    // GIVEN
    let (context, org, _, identifier, key) = TestContext::new_with_did(None).await;
    let schema = complex_sd_jwt_vc_credential_schema(&context, &org).await;
    let claims = vec![claim_data(
        "required_claim",
        "required_claim",
        Some("value"),
        true,
        &schema,
    )];
    create_credential(
        &context,
        &identifier,
        &schema,
        claims,
        CredentialStateEnum::Accepted,
    )
    .await;

    let credential_query = CredentialQuery::sd_jwt_vc(vec![schema.schema_id])
        .id("test_query_id")
        .claims(vec![
            ClaimQuery::builder()
                .path(vec!["not_required_claim".to_string()])
                .build(),
        ])
        .build();
    let dcql_query = DcqlQuery::builder()
        .credentials(vec![credential_query])
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
    println!("{}", serde_json::to_string_pretty(&body).unwrap());
    body["credentialQueries"]["test_query_id"]["failureHint"]["credentialSchema"]["id"]
        .assert_eq(&schema.id);
    body["credentialQueries"]["test_query_id"]["failureHint"]["reason"]
        .assert_eq(&"CONSTRAINT".to_string());
    let credential_sets = json!([
      {
        "options": [
          [
            "test_query_id"
          ]
        ],
        "required": true
      }
    ]);
    body["credentialSets"].assert_eq(&credential_sets);
}

#[tokio::test]
async fn test_get_presentation_definition_2_inapplicable_credential_validity() {
    // GIVEN
    let (context, org, _, identifier, key) = TestContext::new_with_did(None).await;
    let schema = complex_sd_jwt_vc_credential_schema(&context, &org).await;
    let claims = vec![claim_data(
        "required_claim",
        "required_claim",
        Some("value"),
        true,
        &schema,
    )];
    create_credential(
        &context,
        &identifier,
        &schema,
        claims,
        CredentialStateEnum::Revoked,
    )
    .await;

    let credential_query = CredentialQuery::sd_jwt_vc(vec![schema.schema_id])
        .id("test_query_id")
        .claims(vec![
            ClaimQuery::builder()
                .path(vec!["required_claim".to_string()])
                .build(),
        ])
        .build();
    let dcql_query = DcqlQuery::builder()
        .credentials(vec![credential_query])
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
    body["credentialQueries"]["test_query_id"]["failureHint"]["credentialSchema"]["id"]
        .assert_eq(&schema.id);
    body["credentialQueries"]["test_query_id"]["failureHint"]["reason"]
        .assert_eq(&"VALIDITY".to_string());
    let credential_sets = json!([
      {
        "options": [
          [
            "test_query_id"
          ]
        ],
        "required": true
      }
    ]);
    body["credentialSets"].assert_eq(&credential_sets);
}

async fn create_credential(
    context: &TestContext,
    identifier: &Identifier,
    schema: &CredentialSchema,
    claims: Vec<ClaimData>,
    state: CredentialStateEnum,
) -> Credential {
    context
        .db
        .credentials
        .create(
            schema,
            state,
            identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                role: Some(CredentialRole::Holder),
                claims_data: Some(claims),
                ..Default::default()
            },
        )
        .await
}

fn claim_data(
    path: &str,
    key: &str,
    value: Option<&str>,
    selectively_disclosable: bool,
    schema: &CredentialSchema,
) -> ClaimData {
    let schema_id = schema
        .claim_schemas
        .as_ref()
        .expect("missing claim schemas")
        .iter()
        .find(|claim_schema| claim_schema.schema.key == key)
        .expect("claim schema not found")
        .schema
        .id;

    ClaimData {
        schema_id,
        path: path.to_string(),
        value: value.map(|v| v.to_string()),
        selectively_disclosable,
    }
}

async fn complex_sd_jwt_vc_credential_schema(
    context: &TestContext,
    organisation: &Organisation,
) -> CredentialSchema {
    let vct = "https://example.org/foo";

    context
        .db
        .credential_schemas
        .create_with_claims(
            &Uuid::new_v4(),
            "Complex SD-JWT VC schema",
            organisation,
            "NONE",
            &[
                (Uuid::new_v4(), "root obj", false, "OBJECT", false),
                (Uuid::new_v4(), "root obj/string", false, "STRING", false),
                (Uuid::new_v4(), "root obj/number", false, "NUMBER", false),
                (
                    Uuid::new_v4(),
                    "root obj/nested object",
                    false,
                    "OBJECT",
                    false,
                ),
                (
                    Uuid::new_v4(),
                    "root obj/nested object/value",
                    false,
                    "STRING",
                    false,
                ),
                (Uuid::new_v4(), "root obj array", false, "OBJECT", true),
                (
                    Uuid::new_v4(),
                    "root obj array/nested object",
                    false,
                    "OBJECT",
                    false,
                ),
                (
                    Uuid::new_v4(),
                    "root obj array/nested object/value",
                    false,
                    "STRING",
                    false,
                ),
                (
                    Uuid::new_v4(),
                    "root obj array/nested object/nested string array",
                    false,
                    "STRING",
                    true,
                ),
                (Uuid::new_v4(), "required_claim", true, "STRING", false),
                (Uuid::new_v4(), "not_required_claim", false, "STRING", false),
            ],
            "SD_JWT_VC",
            vct,
        )
        .await
}
