use std::collections::HashMap;

use dcql::{ClaimQuery, ClaimQueryId, CredentialQuery, DcqlQuery};
use one_core::model::credential::{CredentialRole, CredentialStateEnum};
use one_core::model::credential_schema::CredentialSchemaType;
use one_core::model::identifier::Identifier;
use one_core::model::key::Key;
use one_core::model::organisation::Organisation;
use one_core::model::proof::{Proof, ProofStateEnum};
use serde_json::json;
use similar_asserts::assert_eq;
use uuid::Uuid;

use crate::fixtures::TestingCredentialParams;
use crate::utils::context::TestContext;
use crate::utils::db_clients::credential_schemas::TestingCreateSchemaParams;
use crate::utils::field_match::FieldHelpers;

#[tokio::test]
async fn test_get_presentation_definition_dcql_simple() {
    // GIVEN
    let (context, org, _, identifier, key) = TestContext::new_with_did(None).await;

    let vct = "https://example.org/foo";
    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "Simple test schema",
            &org,
            "NONE",
            TestingCreateSchemaParams {
                schema_id: Some(vct.to_string()),
                format: Some("SD_JWT_VC".to_owned()),
                schema_type: Some(CredentialSchemaType::SdJwtVc),
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
                ..Default::default()
            },
        )
        .await;

    let credential_query = CredentialQuery::sd_jwt_vc(vec![vct.to_string()])
        .id("test_id")
        .claims(vec![
            ClaimQuery::builder()
                .path(vec!["firstName".to_string()])
                .build(),
        ])
        .build();
    let dcql_query = DcqlQuery::builder()
        .credentials(vec![credential_query])
        .build();
    let proof = proof_for_dcql_query(&context, &org, &identifier, key, &dcql_query).await;

    // WHEN
    let resp = context.api.proofs.presentation_definition(proof.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let body = resp.json_value().await;
    assert_eq!(body["credentials"][0]["id"], credential.id.to_string());
    body["requestGroups"][0]["requestedCredentials"][0]["applicableCredentials"]
        .assert_eq(&vec![credential.id.to_string()]);
    let field = json!({
        "id": "test_id:firstName",
        "keyMap": {
            credential.id.to_string(): "firstName"
        },
        "name": "firstName",
        "required": true
    });
    body["requestGroups"][0]["requestedCredentials"][0]["fields"].assert_eq(&vec![field]);
}

#[tokio::test]
async fn test_get_presentation_definition_dcql_simple_w3c() {
    // GIVEN
    let (context, org, _, identifier, key) = TestContext::new_with_did(None).await;

    let schema_id = "https://example.org/foo";
    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "Simple test schema",
            &org,
            "NONE",
            TestingCreateSchemaParams {
                schema_id: Some(schema_id.to_string()),
                format: Some("JWT".to_owned()),
                schema_type: Some(CredentialSchemaType::SdJwtVc),
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
                ..Default::default()
            },
        )
        .await;

    let credential_query = CredentialQuery::jwt_vc(vec![vec![
        "https://www.w3.org/ns/credentials/v2".to_owned(),
        "https://core.dev.procivis-one.com/ssi/context/v1/lvvc.json".to_owned(),
        format!("{schema_id}#SimpleTestSchema"),
    ]])
    .id("test_id")
    .claims(vec![
        ClaimQuery::builder()
            .path(vec!["firstName".to_string()])
            .build(),
    ])
    .build();
    let dcql_query = DcqlQuery::builder()
        .credentials(vec![credential_query])
        .build();
    let proof = proof_for_dcql_query(&context, &org, &identifier, key, &dcql_query).await;

    // WHEN
    let resp = context.api.proofs.presentation_definition(proof.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let body = resp.json_value().await;
    assert_eq!(body["credentials"][0]["id"], credential.id.to_string());
    body["requestGroups"][0]["requestedCredentials"][0]["applicableCredentials"]
        .assert_eq(&vec![credential.id.to_string()]);
    let field1 = json!({
        "id": "test_id:firstName",
        "keyMap": {
            credential.id.to_string(): "firstName"
        },
        "name": "firstName",
        "required": true
    });
    // also shown because JWT does not support selective disclosure
    let field2 = json!({
        "id": "test_id:isOver18",
        "keyMap": {
            credential.id.to_string(): "isOver18"
        },
        "name": "isOver18",
        "required": true
    });
    body["requestGroups"][0]["requestedCredentials"][0]["fields"]
        .assert_eq_unordered(&[field1, field2]);
}

#[tokio::test]
async fn test_get_presentation_definition_dcql_inapplicable_credential() {
    // GIVEN
    let (context, org, _, identifier, key) = TestContext::new_with_did(None).await;

    let claim_1 = Uuid::new_v4();
    let claim_2 = Uuid::new_v4();

    let vct = "https://example.org/foo";
    let credential_schema = context
        .db
        .credential_schemas
        .create_with_claims(
            &Uuid::new_v4(),
            "Simple test schema",
            &org,
            "NONE",
            &[
                (claim_1, "firstName", true, "STRING", false),
                (claim_2, "isOver18", false, "BOOLEAN", false),
            ],
            "SD_JWT_VC",
            vct,
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
                claims_data: Some(vec![(claim_1, "firstName", "test-name")]),
                ..Default::default()
            },
        )
        .await;

    let credential_query = CredentialQuery::sd_jwt_vc(vec![vct.to_string()])
        .id("test_id")
        .claims(vec![
            ClaimQuery::builder()
                .id("test-claim-id")
                .path(vec!["isOver18".to_string()])
                .build(),
        ])
        .build();
    let dcql_query = DcqlQuery::builder()
        .credentials(vec![credential_query])
        .build();
    let proof = proof_for_dcql_query(&context, &org, &identifier, key, &dcql_query).await;

    // WHEN
    let resp = context.api.proofs.presentation_definition(proof.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let body = resp.json_value().await;
    assert_eq!(body["credentials"][0]["id"], credential.id.to_string());
    body["requestGroups"][0]["requestedCredentials"][0]["inapplicableCredentials"]
        .assert_eq(&vec![credential.id.to_string()]);
    let field = json!({
        "id": "test-claim-id",
        "keyMap": {},
        "name": "isOver18",
        "required": true
    });
    body["requestGroups"][0]["requestedCredentials"][0]["fields"].assert_eq(&vec![field]);
}

#[tokio::test]
async fn test_get_presentation_definition_dcql_claim_sets() {
    // GIVEN
    let (context, org, _, identifier, key) = TestContext::new_with_did(None).await;

    let claim_1 = Uuid::new_v4();
    let claim_2 = Uuid::new_v4();

    let vct = "https://example.org/foo";
    let credential_schema = context
        .db
        .credential_schemas
        .create_with_claims(
            &Uuid::new_v4(),
            "Simple test schema",
            &org,
            "NONE",
            &[
                (claim_1, "firstName", true, "STRING", false),
                (claim_2, "isOver18", false, "BOOLEAN", false),
            ],
            "SD_JWT_VC",
            vct,
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
                claims_data: Some(vec![(claim_1, "firstName", "test-name")]),
                ..Default::default()
            },
        )
        .await;

    let credential_query = CredentialQuery::sd_jwt_vc(vec![vct.to_string()])
        .id("test_id")
        .claims(vec![
            ClaimQuery::builder()
                .id("claim1")
                .path(vec!["isOver18".to_string()])
                .required(true)
                .build(),
            ClaimQuery::builder()
                .id("claim2")
                .path(vec!["firstName".to_string()])
                .required(true)
                .build(),
        ])
        .claim_sets(vec![
            vec![ClaimQueryId::from("claim1"), ClaimQueryId::from("claim2")],
            vec![ClaimQueryId::from("claim1")],
            vec![ClaimQueryId::from("claim2")],
        ])
        .build();
    let dcql_query = DcqlQuery::builder()
        .credentials(vec![credential_query])
        .build();
    let proof = proof_for_dcql_query(&context, &org, &identifier, key, &dcql_query).await;

    // WHEN
    let resp = context.api.proofs.presentation_definition(proof.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let body = resp.json_value().await;
    assert_eq!(body["credentials"][0]["id"], credential.id.to_string());
    body["requestGroups"][0]["requestedCredentials"][0]["applicableCredentials"]
        .assert_eq(&vec![credential.id.to_string()]);
    let field = json!({
        "id": "claim2",
        "keyMap": {
            credential.id.to_string(): "firstName"
        },
        "name": "firstName",
        "required": true
    });
    body["requestGroups"][0]["requestedCredentials"][0]["fields"].assert_eq(&vec![field]);
}

#[tokio::test]
async fn test_get_presentation_definition_dcql_multiple_applicable_credentials() {
    // GIVEN
    let (context, org, _, identifier, key) = TestContext::new_with_did(None).await;

    let vct = "https://example.org/foo";
    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "Simple test schema",
            &org,
            "NONE",
            TestingCreateSchemaParams {
                schema_id: Some(vct.to_string()),
                format: Some("SD_JWT_VC".to_owned()),
                schema_type: Some(CredentialSchemaType::SdJwtVc),
                ..Default::default()
            },
        )
        .await;

    let credential1 = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                role: Some(CredentialRole::Holder),
                ..Default::default()
            },
        )
        .await;
    let credential2 = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                role: Some(CredentialRole::Holder),
                ..Default::default()
            },
        )
        .await;
    // this one will be silently filtered out as it is in the wrong state
    context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Pending,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                role: Some(CredentialRole::Holder),
                ..Default::default()
            },
        )
        .await;

    let credential_query = CredentialQuery::sd_jwt_vc(vec![vct.to_string()])
        .id("test_id")
        .claims(vec![
            ClaimQuery::builder()
                .id("test-claim-id")
                .path(vec!["isOver18".to_string()])
                .build(),
        ])
        .build();
    let dcql_query = DcqlQuery::builder()
        .credentials(vec![credential_query])
        .build();
    let proof = proof_for_dcql_query(&context, &org, &identifier, key, &dcql_query).await;

    // WHEN
    let resp = context.api.proofs.presentation_definition(proof.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let body = resp.json_value().await;
    assert_eq!(body["credentials"].as_array().unwrap().len(), 2);
    body["requestGroups"][0]["requestedCredentials"][0]["applicableCredentials"]
        .assert_eq_unordered(&[credential1.id.to_string(), credential2.id.to_string()]);
    let key_map = HashMap::from([
        (credential1.id.to_string(), "isOver18".to_string()),
        (credential2.id.to_string(), "isOver18".to_string()),
    ]);
    body["requestGroups"][0]["requestedCredentials"][0]["fields"][0]["keyMap"].assert_eq(&key_map);
}

#[tokio::test]
async fn test_get_presentation_definition_dcql_multiple() {
    // GIVEN
    let (context, org, _, identifier, key) = TestContext::new_with_did(None).await;

    let vct = "https://example.org/foo";
    let credential_schema1 = context
        .db
        .credential_schemas
        .create(
            "Simple sd-jwt-vc schema",
            &org,
            "NONE",
            TestingCreateSchemaParams {
                schema_id: Some(vct.to_string()),
                format: Some("SD_JWT_VC".to_owned()),
                schema_type: Some(CredentialSchemaType::SdJwtVc),
                ..Default::default()
            },
        )
        .await;

    let doctype = "org.iso.18013.5.1.mDL";
    let claim_1 = Uuid::new_v4();
    let claim_2 = Uuid::new_v4();
    let claim_3 = Uuid::new_v4();

    let credential_schema2 = context
        .db
        .credential_schemas
        .create_with_claims(
            &Uuid::new_v4(),
            "Simple mdoc schema",
            &org,
            "NONE",
            &[
                (claim_1, "org.iso.18013.5.1", true, "OBJECT", false),
                (claim_2, "test_1", true, "STRING", false),
                (claim_3, "test_2", false, "BOOLEAN", false),
            ],
            "MDOC",
            doctype,
        )
        .await;

    context
        .db
        .credentials
        .create(
            &credential_schema1,
            CredentialStateEnum::Accepted,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                role: Some(CredentialRole::Holder),
                ..Default::default()
            },
        )
        .await;

    context
        .db
        .credentials
        .create(
            &credential_schema2,
            CredentialStateEnum::Accepted,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                role: Some(CredentialRole::Holder),
                claims_data: Some(vec![(claim_2, "org.iso.18013.5.1/test_1", "test-data")]),
                ..Default::default()
            },
        )
        .await;

    let credential_query1 = CredentialQuery::sd_jwt_vc(vec![vct.to_string()])
        .id("test_id")
        .claims(vec![
            ClaimQuery::builder()
                .path(vec!["firstName".to_string()])
                .build(),
        ])
        .build();
    let credential_query2 = CredentialQuery::mso_mdoc(doctype.to_string())
        .id("test_id2")
        .claims(vec![
            ClaimQuery::builder()
                .path(vec!["org.iso.18013.5.1".to_string(), "test_1".to_string()])
                .build(),
        ])
        .build();
    let dcql_query = DcqlQuery::builder()
        .credentials(vec![credential_query1, credential_query2])
        .build();
    let proof = proof_for_dcql_query(&context, &org, &identifier, key, &dcql_query).await;

    // WHEN
    let resp = context.api.proofs.presentation_definition(proof.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let body = resp.json_value().await;
    assert_eq!(body["credentials"].as_array().unwrap().len(), 2);
    assert_eq!(
        body["requestGroups"][0]["requestedCredentials"][0]["applicableCredentials"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        body["requestGroups"][0]["requestedCredentials"][1]["applicableCredentials"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn test_get_presentation_definition_dcql_no_claims() {
    // GIVEN
    let (context, org, _, identifier, key) = TestContext::new_with_did(None).await;

    let vct = "https://example.org/foo";
    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "Simple test schema",
            &org,
            "NONE",
            TestingCreateSchemaParams {
                schema_id: Some(vct.to_string()),
                format: Some("SD_JWT_VC".to_owned()),
                schema_type: Some(CredentialSchemaType::SdJwtVc),
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
                ..Default::default()
            },
        )
        .await;

    let credential_query = CredentialQuery::sd_jwt_vc(vec![vct.to_string()])
        .id("test_id")
        .build();
    let dcql_query = DcqlQuery::builder()
        .credentials(vec![credential_query])
        .build();
    let proof = proof_for_dcql_query(&context, &org, &identifier, key, &dcql_query).await;

    // WHEN
    let resp = context.api.proofs.presentation_definition(proof.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let body = resp.json_value().await;
    assert_eq!(body["credentials"][0]["id"], credential.id.to_string());
    body["requestGroups"][0]["requestedCredentials"][0]["applicableCredentials"]
        .assert_eq(&vec![credential.id.to_string()]);
    body["requestGroups"][0]["requestedCredentials"][0]["fields"].assert_eq::<Vec<()>>(&vec![]);
}

async fn proof_for_dcql_query(
    context: &TestContext,
    org: &Organisation,
    identifier: &Identifier,
    key: Key,
    dcql_query: &DcqlQuery,
) -> Proof {
    let interaction = context
        .db
        .interactions
        .create(
            None,
            "http://localhost",
            &interaction_data_dcql(dcql_query),
            org,
        )
        .await;

    context
        .db
        .proofs
        .create(
            None,
            identifier,
            None,
            None,
            ProofStateEnum::Requested,
            "OPENID4VP_DRAFT25",
            Some(&interaction),
            key,
            None,
        )
        .await
}

fn interaction_data_dcql(dcql_query: &DcqlQuery) -> Vec<u8> {
    json!({
        "response_type": "vp_token",
        "state": "4ae7e7d5-2ac5-4325-858f-d93ff1fb4f8b",
        "nonce": "xKpt9wiB4apJ1MVTzQv1zdDty2dVWkl7",
        "client_id_scheme": "redirect_uri",
        "client_id": "http://0.0.0.0:3000/ssi/openid4vp/draft-20/response",
        "response_mode": "direct_post",
        "response_uri": "http://0.0.0.0:3000/ssi/openid4vp/draft-20/response",
        "dcql_query": dcql_query,
    })
    .to_string()
    .into_bytes()
}

#[tokio::test]
async fn test_get_presentation_definition_dcql_w3c_mixed_selective_disclosure() {
    // GIVEN
    let (context, org, _, identifier, key) = TestContext::new_with_did(None).await;

    let schema_id1 = "https://example.org/foo-no-sd";
    let credential_schema_no_sd = context
        .db
        .credential_schemas
        .create(
            "Schema no SD",
            &org,
            "NONE",
            TestingCreateSchemaParams {
                schema_id: Some(schema_id1.to_string()),
                format: Some("JSON_LD_CLASSIC".to_owned()),
                schema_type: Some(CredentialSchemaType::SdJwtVc),
                ..Default::default()
            },
        )
        .await;

    let schema_id2 = "https://example.org/foo-sd";
    let credential_schema_with_sd = context
        .db
        .credential_schemas
        .create(
            "Schema with SD",
            &org,
            "NONE",
            TestingCreateSchemaParams {
                schema_id: Some(schema_id2.to_string()),
                format: Some("JSON_LD_BBSPLUS".to_owned()),
                schema_type: Some(CredentialSchemaType::SdJwtVc),
                ..Default::default()
            },
        )
        .await;

    let credential1 = context
        .db
        .credentials
        .create(
            &credential_schema_no_sd,
            CredentialStateEnum::Accepted,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                role: Some(CredentialRole::Holder),
                ..Default::default()
            },
        )
        .await;

    let credential2 = context
        .db
        .credentials
        .create(
            &credential_schema_with_sd,
            CredentialStateEnum::Accepted,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                role: Some(CredentialRole::Holder),
                ..Default::default()
            },
        )
        .await;

    // Allow both credential schemas
    let credential_query = CredentialQuery::ldp_vc(vec![
        vec![
            "https://www.w3.org/ns/credentials/v2".to_owned(),
            "https://core.dev.procivis-one.com/ssi/context/v1/lvvc.json".to_owned(),
            format!("{schema_id1}#SchemaNoSd"),
        ],
        vec![
            "https://www.w3.org/ns/credentials/v2".to_owned(),
            format!("{schema_id2}#SchemaWithSd"),
        ],
    ])
    .id("test_id")
    .claims(vec![
        ClaimQuery::builder()
            .path(vec!["firstName".to_string()])
            // this is _not_ mandatory
            .required(false)
            .build(),
    ])
    .build();
    let dcql_query = DcqlQuery::builder()
        .credentials(vec![credential_query])
        .build();
    let proof = proof_for_dcql_query(&context, &org, &identifier, key, &dcql_query).await;

    // WHEN
    let resp = context.api.proofs.presentation_definition(proof.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let body = resp.json_value().await;

    // both credentials are applicable
    body["requestGroups"][0]["requestedCredentials"][0]["applicableCredentials"]
        .assert_eq_unordered(&[credential1.id.to_string(), credential2.id.to_string()]);

    // because credential1 does not support selective disclosure, all it's claims are present in fields
    // (despite only one being requested) and all of them are required true (despite the requested claim
    // being required false).
    body["requestGroups"][0]["requestedCredentials"][0]["fields"][0]["required"].assert_eq(&true);
    body["requestGroups"][0]["requestedCredentials"][0]["fields"][1]["required"].assert_eq(&true);

    let fields = body["requestGroups"][0]["requestedCredentials"][0]["fields"]
        .as_array()
        .unwrap();
    // This claim was asked for by the verifier, both credentials are applicable
    assert!(fields.iter().any(|field| field["id"] == "test_id:firstName"
        && field["keyMap"].as_object().unwrap().len() == 2));

    // This claim was not asked for by the verifier but since it is included in credential1, and it is not selectively disclosable, it is listed.
    // For credential2 this claim is not even selectable, as it was never asked for.
    assert!(fields.iter().any(|field| field["id"] == "test_id:isOver18"
        && field["keyMap"] == json!({credential1.id.to_string(): "isOver18"})));
}

#[tokio::test]
async fn test_get_presentation_definition_dcql_value_match() {
    // GIVEN
    let (context, org, _, identifier, key) = TestContext::new_with_did(None).await;

    let claim_1 = Uuid::new_v4();
    let claim_2 = Uuid::new_v4();

    let vct = "https://example.org/foo";
    let credential_schema = context
        .db
        .credential_schemas
        .create_with_claims(
            &Uuid::new_v4(),
            "Simple test schema",
            &org,
            "NONE",
            &[
                (claim_1, "firstName", true, "STRING", false),
                (claim_2, "isOver18", false, "BOOLEAN", false),
            ],
            "SD_JWT_VC",
            vct,
        )
        .await;

    let credential1 = context
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
                    (claim_1, "firstName", "test-name"),
                    (claim_2, "isOver18", "true"),
                ]),
                ..Default::default()
            },
        )
        .await;

    // this one will be inapplicable because the claim values don't match
    let credential2 = context
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
                    (claim_1, "firstName", "test-name2"),
                    (claim_2, "isOver18", "false"),
                ]),
                ..Default::default()
            },
        )
        .await;

    let credential_query = CredentialQuery::sd_jwt_vc(vec![vct.to_string()])
        .id("test_id")
        .claims(vec![
            ClaimQuery::builder()
                .path(vec!["isOver18".to_string()])
                .values(vec![true.into()])
                .build(),
        ])
        .build();
    let dcql_query = DcqlQuery::builder()
        .credentials(vec![credential_query])
        .build();
    let proof = proof_for_dcql_query(&context, &org, &identifier, key, &dcql_query).await;

    // WHEN
    let resp = context.api.proofs.presentation_definition(proof.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let body = resp.json_value().await;
    assert_eq!(body["credentials"].as_array().unwrap().len(), 2);
    let expected_requested_credentials = json!({
        "applicableCredentials": [credential1.id.to_string()],
        "fields": [{
            "id": "test_id:isOver18",
            "keyMap": {
                credential1.id.to_string(): "isOver18",
            },
            "name": "isOver18",
            "required": true,
        }],
        "id": "test_id",
        "inapplicableCredentials": [credential2.id.to_string()]
    });
    body["requestGroups"][0]["requestedCredentials"][0].assert_eq(&expected_requested_credentials);
}
