use one_core::model::certificate::CertificateState;
use one_core::model::claim_schema::ClaimSchema;
use one_core::model::credential::{CredentialRole, CredentialStateEnum};
use one_core::model::identifier::IdentifierType;
use rcgen::{CertificateParams, KeyUsagePurpose};
use serde_json::json;
use similar_asserts::assert_eq;
use sql_data_provider::test_utilities::get_dummy_date;
use standardized_types::openid4vp::dcql::{
    ClaimQuery, ClaimQueryId, ClaimValue, CredentialQuery, DcqlQuery, PathSegment, TrustedAuthority,
};
use uuid::Uuid;

use crate::fixtures::dcql::proof_for_dcql_query;
use crate::fixtures::{ClaimData, TestingCredentialParams, TestingIdentifierParams};
use crate::utils::context::TestContext;
use crate::utils::db_clients::certificates::TestingCertificateParams;
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
            TestingCreateSchemaParams {
                schema_id: Some(vct.to_string()),
                format: Some("SD_JWT_VC".into()),
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
                        schema_id: credential_schema.claim_schemas.as_ref().await.unwrap()[0].id,
                        path: "firstName".to_string(),
                        value: Some("name".to_string()),
                        selectively_disclosable: true,
                    },
                    ClaimData {
                        schema_id: credential_schema.claim_schemas.as_ref().await.unwrap()[1].id,
                        path: "isOver18".to_string(),
                        value: Some("true".to_string()),
                        selectively_disclosable: true,
                    },
                ]),
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
    let proof = proof_for_dcql_query(
        &context,
        &org,
        &identifier,
        key,
        &dcql_query,
        "OPENID4VP_FINAL1",
        None,
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
        .assert_eq(&credential.common().id);
    let claims = body["credentialQueries"]["test_id"]["applicableCredentials"][0]["claims"]
        .as_array()
        .unwrap();
    assert!(
        claims
            .iter()
            .any(|c| c["path"] == "firstName" && c["required"] == true)
    );
    let credential_sets = json!([{
        "options": [["test_id"]],
        "required": true
    }]);
    body["credentialSets"].assert_eq(&credential_sets);
}

#[tokio::test]
async fn test_get_presentation_definition_dcql_nesting() {
    // GIVEN
    let (context, org, _, identifier, key) = TestContext::new_with_did(None).await;

    let claim_1 = Uuid::new_v4();
    let claim_2 = Uuid::new_v4();
    let claim_3 = Uuid::new_v4();
    let vct = "https://example.org/foo";
    let credential_schema = context
        .db
        .credential_schemas
        .create_with_claims(
            &Uuid::new_v4(),
            "Nested test schema",
            &org,
            &[
                (claim_1, "first", true, "OBJECT", true),
                (claim_2, "first/second", true, "OBJECT", false),
                (claim_3, "first/second/third", true, "STRING", true),
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
                claims_data: Some(vec![
                    ClaimData {
                        schema_id: claim_1.into(),
                        path: "first".to_string(),
                        value: None,
                        selectively_disclosable: true,
                    },
                    ClaimData {
                        schema_id: claim_1.into(),
                        path: "first/0".to_string(),
                        value: None,
                        selectively_disclosable: false,
                    },
                    ClaimData {
                        schema_id: claim_2.into(),
                        path: "first/0/second".to_string(),
                        value: None,
                        selectively_disclosable: false,
                    },
                    ClaimData {
                        schema_id: claim_3.into(),
                        path: "first/0/second/third".to_string(),
                        value: None,
                        selectively_disclosable: false,
                    },
                    ClaimData {
                        schema_id: claim_3.into(),
                        path: "first/0/second/third/0".to_string(),
                        value: Some("test_value".to_string()),
                        selectively_disclosable: false,
                    },
                ]),
                ..Default::default()
            },
        )
        .await;

    let credential_query = CredentialQuery::sd_jwt_vc(vec![vct.to_string()])
        .id("test_id")
        .claims(vec![
            ClaimQuery::builder()
                .path(vec!["first".to_string()])
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
        None,
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
        .assert_eq(&credential.common().id);
    let claims = &body["credentialQueries"]["test_id"]["applicableCredentials"][0]["claims"];
    let flat = flatten_claims(claims);
    assert!(
        flat.iter()
            .any(|(p, c)| p == "first" && c["required"] == true)
    );
    let credential_sets = json!([{
        "options": [["test_id"]],
        "required": true
    }]);
    body["credentialSets"].assert_eq(&credential_sets);
}

#[tokio::test]
async fn test_get_presentation_definition_dcql_nested_with_mandatory_disclosure_sibling() {
    // GIVEN
    let (context, org, _, identifier, key) = TestContext::new_with_did(None).await;

    let claim_1 = Uuid::new_v4();
    let claim_2 = Uuid::new_v4();
    let claim_3 = Uuid::new_v4();
    let claim_4 = Uuid::new_v4();
    let vct = "https://example.org/foo";
    let credential_schema = context
        .db
        .credential_schemas
        .create_with_claims(
            &Uuid::new_v4(),
            "Nested test schema",
            &org,
            &[
                (claim_1, "first", true, "OBJECT", false),
                (claim_2, "first/second", true, "OBJECT", false),
                (claim_3, "first/second/third", true, "STRING", false),
                (claim_4, "first/sibling", true, "STRING", false),
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
                claims_data: Some(vec![
                    ClaimData {
                        schema_id: claim_1.into(),
                        path: "first".to_string(),
                        value: None,
                        selectively_disclosable: true,
                    },
                    ClaimData {
                        schema_id: claim_2.into(),
                        path: "first/second".to_string(),
                        value: None,
                        selectively_disclosable: true,
                    },
                    ClaimData {
                        schema_id: claim_3.into(),
                        path: "first/second/third".to_string(),
                        value: Some("test_value1".to_string()),
                        selectively_disclosable: true,
                    },
                    ClaimData {
                        schema_id: claim_4.into(),
                        path: "first/sibling".to_string(),
                        value: Some("test_value2".to_string()),
                        selectively_disclosable: false,
                    },
                ]),
                ..Default::default()
            },
        )
        .await;

    let credential_query = CredentialQuery::sd_jwt_vc(vec![vct.to_string()])
        .id("test_id")
        .claims(vec![
            ClaimQuery::builder()
                .path(vec!["first".to_string(), "second".to_string()])
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
        None,
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
        .assert_eq(&credential.common().id);

    let claims = &body["credentialQueries"]["test_id"]["applicableCredentials"][0]["claims"];
    let flat = flatten_claims(claims);
    assert_eq!(flat.len(), 4);

    // false because it is optional in the request and selectively disclosable
    assert_v2_required_flag("first", false, &flat);
    assert_v2_required_flag("first/second", false, &flat);

    // true because it is not selectively disclosable
    assert_v2_required_flag("first/sibling", true, &flat);

    let credential_sets = json!([{
        "options": [["test_id"]],
        "required": true
    }]);
    body["credentialSets"].assert_eq(&credential_sets);
}

#[tokio::test]
async fn test_get_presentation_definition_dcql_nested_required_with_mandatory_disclosure_sibling() {
    // GIVEN
    let (context, org, _, identifier, key) = TestContext::new_with_did(None).await;

    let claim_1 = Uuid::new_v4();
    let claim_2 = Uuid::new_v4();
    let claim_3 = Uuid::new_v4();
    let claim_4 = Uuid::new_v4();
    let vct = "https://example.org/foo";
    let credential_schema = context
        .db
        .credential_schemas
        .create_with_claims(
            &Uuid::new_v4(),
            "Nested test schema",
            &org,
            &[
                (claim_1, "first", true, "OBJECT", false),
                (claim_2, "first/second", true, "STRING", false),
                (claim_3, "first/sibling", true, "STRING", false),
                (claim_4, "first/sibling_sd", true, "STRING", false),
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
                claims_data: Some(vec![
                    ClaimData {
                        schema_id: claim_1.into(),
                        path: "first".to_string(),
                        value: None,
                        selectively_disclosable: true,
                    },
                    ClaimData {
                        schema_id: claim_2.into(),
                        path: "first/second".to_string(),
                        value: Some("test_value".to_string()),
                        selectively_disclosable: true,
                    },
                    ClaimData {
                        schema_id: claim_3.into(),
                        path: "first/sibling".to_string(),
                        value: Some("sibling no sd".to_string()),
                        selectively_disclosable: false,
                    },
                    ClaimData {
                        schema_id: claim_4.into(),
                        path: "first/sibling_sd".to_string(),
                        value: Some("sibling with sd".to_string()),
                        selectively_disclosable: true,
                    },
                ]),
                ..Default::default()
            },
        )
        .await;

    let credential_query = CredentialQuery::sd_jwt_vc(vec![vct.to_string()])
        .id("test_id")
        .claims(vec![
            ClaimQuery::builder()
                .path(vec!["first".to_string(), "second".to_string()])
                .build(),
            ClaimQuery::builder()
                .path(vec!["first".to_string(), "sibling".to_string()])
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
        None,
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
        .assert_eq(&credential.common().id);

    let claims = &body["credentialQueries"]["test_id"]["applicableCredentials"][0]["claims"];
    let flat = flatten_claims(claims);
    assert_eq!(flat.len(), 3);

    // true because it is mandatory in the request
    assert_v2_required_flag("first", true, &flat);
    assert_v2_required_flag("first/second", true, &flat);

    // true because it is not selectively disclosable
    assert_v2_required_flag("first/sibling", true, &flat);

    let credential_sets = json!([{
        "options": [["test_id"]],
        "required": true
    }]);
    body["credentialSets"].assert_eq(&credential_sets);
}

#[tokio::test]
async fn test_get_presentation_definition_dcql_nested_with_array_query() {
    // GIVEN
    let (context, org, _, identifier, key) = TestContext::new_with_did(None).await;

    let claim_1 = Uuid::new_v4();
    let claim_2 = Uuid::new_v4();
    let claim_3 = Uuid::new_v4();
    let claim_4 = Uuid::new_v4();
    let vct = "https://example.org/foo";
    let credential_schema = context
        .db
        .credential_schemas
        .create_with_claims(
            &Uuid::new_v4(),
            "Nested test schema",
            &org,
            &[
                (claim_1, "first", true, "OBJECT", false),
                (claim_2, "first/second", true, "OBJECT", false),
                (claim_3, "first/second/third", true, "STRING", true),
                (claim_4, "first/sibling", true, "STRING", false),
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
                claims_data: Some(vec![
                    ClaimData {
                        schema_id: claim_1.into(),
                        path: "first".to_string(),
                        value: None,
                        selectively_disclosable: true,
                    },
                    ClaimData {
                        schema_id: claim_2.into(),
                        path: "first/second".to_string(),
                        value: None,
                        selectively_disclosable: true,
                    },
                    ClaimData {
                        schema_id: claim_3.into(),
                        path: "first/second/third".to_string(),
                        value: None,
                        selectively_disclosable: true,
                    },
                    ClaimData {
                        schema_id: claim_3.into(),
                        path: "first/second/third/0".to_string(),
                        value: Some("test_value1".to_string()),
                        selectively_disclosable: true,
                    },
                    ClaimData {
                        schema_id: claim_3.into(),
                        path: "first/second/third/1".to_string(),
                        value: Some("test_value2".to_string()),
                        selectively_disclosable: false,
                    },
                    ClaimData {
                        schema_id: claim_4.into(),
                        path: "first/sibling".to_string(),
                        value: Some("test_value2".to_string()),
                        selectively_disclosable: false,
                    },
                ]),
                ..Default::default()
            },
        )
        .await;

    let credential_query = CredentialQuery::sd_jwt_vc(vec![vct.to_string()])
        .id("test_id")
        .claims(vec![
            ClaimQuery::builder()
                .path(vec![
                    PathSegment::from("first".to_string()),
                    PathSegment::from("second".to_string()),
                    PathSegment::from("third".to_string()),
                    PathSegment::from(0),
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
        None,
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
        .assert_eq(&credential.common().id);

    let claims = &body["credentialQueries"]["test_id"]["applicableCredentials"][0]["claims"];
    let flat = flatten_claims(claims);
    assert_eq!(flat.len(), 6);

    // false because it is optional in the request and selectively disclosable
    assert_v2_required_flag("first", false, &flat);
    assert_v2_required_flag("first/second", false, &flat);
    assert_v2_required_flag("first/second/third", false, &flat);
    assert_v2_required_flag("first/second/third/0", false, &flat);

    // true because it is not selectively disclosable
    assert_v2_required_flag("first/second/third/1", true, &flat);
    assert_v2_required_flag("first/sibling", true, &flat);

    let credential_sets = json!([{
        "options": [["test_id"]],
        "required": true
    }]);
    body["credentialSets"].assert_eq(&credential_sets);
}

#[tokio::test]
async fn test_get_presentation_definition_dcql_array_all_query() {
    // GIVEN
    let (context, org, _, identifier, key) = TestContext::new_with_did(None).await;

    let claim_1 = Uuid::new_v4();
    let claim_2 = Uuid::new_v4();
    let claim_3 = Uuid::new_v4();
    let vct = "https://example.org/foo";
    let credential_schema = context
        .db
        .credential_schemas
        .create_with_claims(
            &Uuid::new_v4(),
            "Nested test schema",
            &org,
            &[
                (claim_1, "first", true, "OBJECT", true),
                (claim_2, "first/second", true, "STRING", false),
                (claim_3, "first/sibling", false, "STRING", false),
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
                claims_data: Some(vec![
                    ClaimData {
                        schema_id: claim_1.into(),
                        path: "first".to_string(),
                        value: None,
                        selectively_disclosable: true,
                    },
                    ClaimData {
                        schema_id: claim_1.into(),
                        path: "first/0".to_string(),
                        value: None,
                        selectively_disclosable: true,
                    },
                    ClaimData {
                        schema_id: claim_1.into(),
                        path: "first/1".to_string(),
                        value: None,
                        selectively_disclosable: true,
                    },
                    ClaimData {
                        schema_id: claim_2.into(),
                        path: "first/0/second".to_string(),
                        value: None,
                        selectively_disclosable: true,
                    },
                    ClaimData {
                        schema_id: claim_3.into(),
                        path: "first/0/sibling".to_string(),
                        value: Some("test_value2".to_string()),
                        selectively_disclosable: false,
                    },
                    ClaimData {
                        schema_id: claim_2.into(),
                        path: "first/1/second".to_string(),
                        value: None,
                        selectively_disclosable: true,
                    },
                ]),
                ..Default::default()
            },
        )
        .await;

    let credential_query = CredentialQuery::sd_jwt_vc(vec![vct.to_string()])
        .id("test_id")
        .claims(vec![
            ClaimQuery::builder()
                .path(vec![
                    PathSegment::from("first".to_string()),
                    PathSegment::ArrayAll,
                    PathSegment::from("second".to_string()),
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
        None,
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
        .assert_eq(&credential.common().id);

    let claims = &body["credentialQueries"]["test_id"]["applicableCredentials"][0]["claims"];
    let flat = flatten_claims(claims);

    // V2 only emits the chain needed for the mandatory non-SD `first/0/sibling` leaf;
    // optional SD elements (`first/1`, `first/N/second`) are not materialised
    assert_eq!(flat.len(), 3);
    assert_v2_required_flag("first", false, &flat);
    assert_v2_required_flag("first/0", false, &flat);
    assert_v2_required_flag("first/0/sibling", true, &flat);

    let credential_sets = json!([{
        "options": [["test_id"]],
        "required": true
    }]);
    body["credentialSets"].assert_eq(&credential_sets);
}

#[tokio::test]
async fn test_get_presentation_definition_dcql_array_all_mandatory_query() {
    // GIVEN
    let (context, org, _, identifier, key) = TestContext::new_with_did(None).await;

    let claim_1 = Uuid::new_v4();
    let claim_2 = Uuid::new_v4();
    let claim_3 = Uuid::new_v4();
    let vct = "https://example.org/foo";
    let credential_schema = context
        .db
        .credential_schemas
        .create_with_claims(
            &Uuid::new_v4(),
            "Nested test schema",
            &org,
            &[
                (claim_1, "first", true, "OBJECT", true),
                (claim_2, "first/second", true, "STRING", false),
                (claim_3, "first/sibling", false, "STRING", false),
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
                claims_data: Some(vec![
                    ClaimData {
                        schema_id: claim_1.into(),
                        path: "first".to_string(),
                        value: None,
                        selectively_disclosable: true,
                    },
                    ClaimData {
                        schema_id: claim_1.into(),
                        path: "first/0".to_string(),
                        value: None,
                        selectively_disclosable: true,
                    },
                    ClaimData {
                        schema_id: claim_1.into(),
                        path: "first/1".to_string(),
                        value: None,
                        selectively_disclosable: true,
                    },
                    ClaimData {
                        schema_id: claim_2.into(),
                        path: "first/0/second".to_string(),
                        value: None,
                        selectively_disclosable: true,
                    },
                    ClaimData {
                        schema_id: claim_3.into(),
                        path: "first/0/sibling".to_string(),
                        value: Some("test_value2".to_string()),
                        selectively_disclosable: false,
                    },
                    ClaimData {
                        schema_id: claim_2.into(),
                        path: "first/1/second".to_string(),
                        value: None,
                        selectively_disclosable: true,
                    },
                ]),
                ..Default::default()
            },
        )
        .await;

    let credential_query = CredentialQuery::sd_jwt_vc(vec![vct.to_string()])
        .id("test_id")
        .claims(vec![
            ClaimQuery::builder()
                .path(vec![
                    PathSegment::from("first".to_string()),
                    PathSegment::ArrayAll,
                    PathSegment::from("second".to_string()),
                ])
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
        None,
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
        .assert_eq(&credential.common().id);

    let claims = &body["credentialQueries"]["test_id"]["applicableCredentials"][0]["claims"];
    let flat = flatten_claims(claims);

    assert_eq!(flat.len(), 3);
    // true because it is a transitive parent of a claim required by verifier (sibling)
    assert_v2_required_flag("first", true, &flat);
    assert_v2_required_flag("first/0", true, &flat);

    // true because it is not selectively disclosable
    assert_v2_required_flag("first/0/sibling", true, &flat);

    let credential_sets = json!([{
        "options": [["test_id"]],
        "required": true
    }]);
    body["credentialSets"].assert_eq(&credential_sets);
}

/// Flatten the nested V2 `claims` tree into a flat list of (path, claim_json) pairs.
fn flatten_claims(claims: &serde_json::Value) -> Vec<(String, serde_json::Value)> {
    let mut out = Vec::new();
    fn recurse(node: &serde_json::Value, out: &mut Vec<(String, serde_json::Value)>) {
        if let Some(arr) = node.as_array() {
            for c in arr {
                if let Some(path) = c.get("path").and_then(|p| p.as_str()) {
                    out.push((path.to_string(), c.clone()));
                    if let Some(value) = c.get("value")
                        && value.is_array()
                    {
                        recurse(value, out);
                    }
                }
            }
        }
    }
    recurse(claims, &mut out);
    out
}

fn assert_v2_required_flag(path: &str, required: bool, flat: &[(String, serde_json::Value)]) {
    let claim = &flat
        .iter()
        .find(|(p, _)| p == path)
        .expect("claim path not found")
        .1;
    assert_eq!(
        claim["required"].as_bool().unwrap(),
        required,
        "expected required={required} for path '{path}', got claim: {claim}"
    );
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
            TestingCreateSchemaParams {
                schema_id: Some(schema_id.to_string()),
                format: Some("JWT".into()),
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
    let proof = proof_for_dcql_query(
        &context,
        &org,
        &identifier,
        key,
        &dcql_query,
        "OPENID4VP_FINAL1",
        None,
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
        .assert_eq(&credential.common().id);

    let claims = &body["credentialQueries"]["test_id"]["applicableCredentials"][0]["claims"];
    let flat = flatten_claims(claims);
    // both claims are required because JWT does not support selective disclosure
    assert!(
        flat.iter()
            .any(|(p, c)| p == "firstName" && c["required"] == true)
    );
    assert!(
        flat.iter()
            .any(|(p, c)| p == "isOver18" && c["required"] == true)
    );

    let credential_sets = json!([{
        "options": [["test_id"]],
        "required": true
    }]);
    body["credentialSets"].assert_eq(&credential_sets);
}

#[tokio::test]
async fn test_get_presentation_definition_dcql_no_selective_disclosure_inapplicable_credential() {
    // GIVEN
    let (context, org, _, identifier, key) = TestContext::new_with_did(None).await;

    let schema_id = "https://example.org/foo";
    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "Simple test schema",
            &org,
            TestingCreateSchemaParams {
                schema_id: Some(schema_id.to_string()),
                format: Some("JWT".into()),
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
        format!("{schema_id}#SimpleTestSchema"),
    ]])
    .id("test_id")
    .claims(vec![
        ClaimQuery::builder()
            .path(vec!["non-existing-claim".to_string()])
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
        None,
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
    let _ = &credential;
    body["credentialQueries"]["test_id"]["failureHint"]["reason"]
        .assert_eq(&"CONSTRAINT".to_string());
    body["credentialQueries"]["test_id"]["failureHint"]["credentialSchema"]["id"]
        .assert_eq(&credential_schema.id);

    let credential_sets = json!([{
        "options": [["test_id"]],
        "required": true
    }]);
    body["credentialSets"].assert_eq(&credential_sets);
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
                claims_data: Some(vec![ClaimData {
                    schema_id: claim_1.into(),
                    path: "firstName".to_string(),
                    value: Some("test-name".to_string()),
                    selectively_disclosable: false,
                }]),
                ..Default::default()
            },
        )
        .await;

    let credential_query = CredentialQuery::sd_jwt_vc(vec![vct.to_string()])
        .id("test_id")
        .claims(vec![
            ClaimQuery::builder()
                .id("test-claim-firstName")
                .path(vec!["firstName".to_string()])
                .build(),
            ClaimQuery::builder()
                .id("test-claim-isOver18")
                .path(vec!["isOver18".to_string()])
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
        None,
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
    let _ = &credential;
    body["credentialQueries"]["test_id"]["failureHint"]["reason"]
        .assert_eq(&"CONSTRAINT".to_string());
    body["credentialQueries"]["test_id"]["failureHint"]["credentialSchema"]["id"]
        .assert_eq(&credential_schema.id);

    let credential_sets = json!([{
        "options": [["test_id"]],
        "required": true
    }]);
    body["credentialSets"].assert_eq(&credential_sets);
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
                claims_data: Some(vec![ClaimData {
                    schema_id: claim_1.into(),
                    path: "firstName".to_string(),
                    value: Some("test-name".to_string()),
                    selectively_disclosable: false,
                }]),
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
    let proof = proof_for_dcql_query(
        &context,
        &org,
        &identifier,
        key,
        &dcql_query,
        "OPENID4VP_FINAL1",
        None,
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
        .assert_eq(&credential.common().id);
    let claims = &body["credentialQueries"]["test_id"]["applicableCredentials"][0]["claims"];
    let flat = flatten_claims(claims);
    assert!(
        flat.iter()
            .any(|(p, c)| p == "firstName" && c["required"] == true)
    );

    let credential_sets = json!([{
        "options": [["test_id"]],
        "required": true
    }]);
    body["credentialSets"].assert_eq(&credential_sets);
}

#[tokio::test]
async fn test_get_presentation_definition_dcql_claim_sets_disjoint_credentials() {
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
            &[
                (claim_1, "first", false, "STRING", false),
                (claim_2, "second", false, "STRING", false),
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
                claims_data: Some(vec![ClaimData {
                    schema_id: claim_1.into(),
                    path: "first".to_string(),
                    value: Some("test-value-first".to_string()),
                    selectively_disclosable: false,
                }]),
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
                claims_data: Some(vec![ClaimData {
                    schema_id: claim_2.into(),
                    path: "second".to_string(),
                    value: Some("test-value-second".to_string()),
                    selectively_disclosable: false,
                }]),
                ..Default::default()
            },
        )
        .await;

    let credential_query = CredentialQuery::sd_jwt_vc(vec![vct.to_string()])
        .id("test_id")
        .claims(vec![
            ClaimQuery::builder()
                .id("claim1")
                .path(vec!["first".to_string()])
                .required(true)
                .build(),
            ClaimQuery::builder()
                .id("claim2")
                .path(vec!["second".to_string()])
                .required(true)
                .build(),
        ])
        .claim_sets(vec![
            vec![ClaimQueryId::from("claim1")],
            vec![ClaimQueryId::from("claim2")],
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
        None,
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
    let applicable = body["credentialQueries"]["test_id"]["applicableCredentials"]
        .as_array()
        .unwrap();
    let ids: Vec<String> = applicable
        .iter()
        .map(|c| c["id"].as_str().unwrap().to_string())
        .collect();
    assert!(ids.contains(&credential1.common().id.to_string()));
    assert!(ids.contains(&credential2.common().id.to_string()));
    assert_eq!(ids.len(), 2);

    let cred1 = applicable
        .iter()
        .find(|c| c["id"].as_str() == Some(&credential1.common().id.to_string()))
        .unwrap();
    let flat1 = flatten_claims(&cred1["claims"]);
    assert!(flat1.iter().any(|(p, _)| p == "first"));

    let cred2 = applicable
        .iter()
        .find(|c| c["id"].as_str() == Some(&credential2.common().id.to_string()))
        .unwrap();
    let flat2 = flatten_claims(&cred2["claims"]);
    assert!(flat2.iter().any(|(p, _)| p == "second"));

    let credential_sets = json!([{
        "options": [["test_id"]],
        "required": true
    }]);
    body["credentialSets"].assert_eq(&credential_sets);
}

#[tokio::test]
async fn test_get_presentation_definition_dcql_metadata_value_matching() {
    // GIVEN
    let (context, org, _, identifier, key) = TestContext::new_with_did(None).await;

    let claim_schema_id = Uuid::new_v4();
    let metadata_claim_schema_id = Uuid::new_v4();

    let vct = "https://example.org/foo";
    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "Simple test schema",
            &org,
            TestingCreateSchemaParams {
                schema_id: Some(vct.to_owned()),
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
                    ClaimData {
                        schema_id: claim_schema_id.into(),
                        path: "string_claim".to_string(),
                        value: Some("test-value-first".to_string()),
                        selectively_disclosable: false,
                    },
                    ClaimData {
                        schema_id: metadata_claim_schema_id.into(),
                        path: "iss".to_string(),
                        value: Some("other-issuer".to_string()),
                        selectively_disclosable: false,
                    },
                ]),
                ..Default::default()
            },
        )
        .await;

    let credential_query = CredentialQuery::sd_jwt_vc(vec![vct.to_string()])
        .id("test_id")
        .claims(vec![
            ClaimQuery::builder()
                .id("claim1")
                .path(vec!["string_claim".to_string()])
                .required(true)
                .build(),
            ClaimQuery::builder()
                .id("claim2")
                .path(vec!["iss".to_string()])
                .values(vec![ClaimValue::String("some-issuer".to_owned())])
                .required(true)
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
        None,
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
    let _ = &credential2;
    // credential1 matches the iss metadata claim value, credential2 does not.
    let applicable = body["credentialQueries"]["test_id"]["applicableCredentials"]
        .as_array()
        .unwrap();
    let ids: Vec<String> = applicable
        .iter()
        .map(|c| c["id"].as_str().unwrap().to_string())
        .collect();
    assert!(ids.contains(&credential1.common().id.to_string()));
    assert!(!ids.contains(&credential2.common().id.to_string()));

    let cred1 = applicable
        .iter()
        .find(|c| c["id"].as_str() == Some(&credential1.common().id.to_string()))
        .unwrap();
    let flat = flatten_claims(&cred1["claims"]);
    // metadata claims used for matching are not surfaced in `claims`
    assert!(flat.iter().any(|(p, _)| p == "string_claim"));
    assert!(!flat.iter().any(|(p, _)| p == "iss"));

    let credential_sets = json!([{
        "options": [["test_id"]],
        "required": true
    }]);
    body["credentialSets"].assert_eq(&credential_sets);
}

#[tokio::test]
async fn test_get_presentation_definition_dcql_no_credentials() {
    // GIVEN
    let (context, org, _, identifier, key) = TestContext::new_with_did(None).await;

    let vct = "https://example.org/foo";
    let credential_query = CredentialQuery::w3c_sd_jwt(vec![vec![vct.to_string()]])
        .id("test_id")
        .claims(vec![
            ClaimQuery::builder()
                .id("claim1")
                .path(vec![
                    "vc".to_string(),
                    "credentialSubject".to_string(),
                    "string_claim".to_string(),
                ])
                .required(true)
                .build(),
            ClaimQuery::builder()
                .id("claim2")
                .path(vec!["iss".to_string()])
                .values(vec![ClaimValue::String("some-issuer".to_owned())])
                .required(true)
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
        None,
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
    body["credentialQueries"]["test_id"]["failureHint"]["reason"]
        .assert_eq(&"NO_CREDENTIAL".to_string());

    let credential_sets = json!([{
        "options": [["test_id"]],
        "required": true
    }]);
    body["credentialSets"].assert_eq(&credential_sets);
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
            TestingCreateSchemaParams {
                schema_id: Some(vct.to_string()),
                format: Some("SD_JWT_VC".into()),
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
                claims_data: Some(vec![
                    ClaimData {
                        schema_id: credential_schema.claim_schemas.as_ref().await.unwrap()[0].id,
                        path: "firstName".to_string(),
                        value: Some("name1".to_string()),
                        selectively_disclosable: true,
                    },
                    ClaimData {
                        schema_id: credential_schema.claim_schemas.as_ref().await.unwrap()[1].id,
                        path: "isOver18".to_string(),
                        value: Some("true".to_string()),
                        selectively_disclosable: true,
                    },
                ]),
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
                claims_data: Some(vec![
                    ClaimData {
                        schema_id: credential_schema.claim_schemas.as_ref().await.unwrap()[0].id,
                        path: "firstName".to_string(),
                        value: Some("name2".to_string()),
                        selectively_disclosable: true,
                    },
                    ClaimData {
                        schema_id: credential_schema.claim_schemas.as_ref().await.unwrap()[1].id,
                        path: "isOver18".to_string(),
                        value: Some("false".to_string()),
                        selectively_disclosable: true,
                    },
                ]),
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
    let proof = proof_for_dcql_query(
        &context,
        &org,
        &identifier,
        key,
        &dcql_query,
        "OPENID4VP_FINAL1",
        None,
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
    let applicable = body["credentialQueries"]["test_id"]["applicableCredentials"]
        .as_array()
        .unwrap();
    let ids: Vec<String> = applicable
        .iter()
        .map(|c| c["id"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(ids.len(), 2);
    assert!(ids.contains(&credential1.common().id.to_string()));
    assert!(ids.contains(&credential2.common().id.to_string()));

    for cred in applicable {
        let flat = flatten_claims(&cred["claims"]);
        assert!(flat.iter().any(|(p, _)| p == "isOver18"));
    }

    let credential_sets = json!([{
        "options": [["test_id"]],
        "required": true
    }]);
    body["credentialSets"].assert_eq(&credential_sets);
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
            TestingCreateSchemaParams {
                schema_id: Some(vct.to_string()),
                format: Some("SD_JWT_VC".into()),
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
            &[
                (claim_1, "org.iso.18013.5.1", true, "OBJECT", false),
                (claim_2, "org.iso.18013.5.1/test_1", true, "STRING", false),
                (claim_3, "org.iso.18013.5.1/test_2", false, "BOOLEAN", false),
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
                claims_data: Some(vec![
                    ClaimData {
                        schema_id: claim_1.into(),
                        path: "org.iso.18013.5.1".to_string(),
                        value: None,
                        selectively_disclosable: false,
                    },
                    ClaimData {
                        schema_id: claim_2.into(),
                        path: "org.iso.18013.5.1/test_1".to_string(),
                        value: Some("test-data".to_string()),
                        selectively_disclosable: false,
                    },
                ]),
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
    let proof = proof_for_dcql_query(
        &context,
        &org,
        &identifier,
        key,
        &dcql_query,
        "OPENID4VP_FINAL1",
        None,
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
    assert_eq!(
        body["credentialQueries"]["test_id"]["applicableCredentials"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        body["credentialQueries"]["test_id2"]["applicableCredentials"]
            .as_array()
            .unwrap()
            .len(),
        1
    );

    // The two queries are independent (no explicit DCQL credentialSets), so each maps to its
    // own implicit credential set entry.
    let credential_sets = json!([
        {"options": [["test_id"]], "required": true},
        {"options": [["test_id2"]], "required": true}
    ]);
    body["credentialSets"].assert_eq(&credential_sets);
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
            TestingCreateSchemaParams {
                schema_id: Some(vct.to_string()),
                format: Some("SD_JWT_VC".into()),
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
                claims_data: Some(vec![ClaimData {
                    schema_id: credential_schema.claim_schemas.as_ref().await.unwrap()[0].id,
                    path: "firstName".to_string(),
                    value: Some("name".to_string()),
                    selectively_disclosable: true,
                }]),
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
    let proof = proof_for_dcql_query(
        &context,
        &org,
        &identifier,
        key,
        &dcql_query,
        "OPENID4VP_FINAL1",
        None,
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
        .assert_eq(&credential.common().id);

    let credential_sets = json!([{
        "options": [["test_id"]],
        "required": true
    }]);
    body["credentialSets"].assert_eq(&credential_sets);
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
            TestingCreateSchemaParams {
                schema_id: Some(schema_id1.to_string()),
                format: Some("JSON_LD_CLASSIC".into()),
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
            TestingCreateSchemaParams {
                schema_id: Some(schema_id2.to_string()),
                format: Some("JSON_LD_BBSPLUS".into()),
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
                claims_data: Some(vec![
                    ClaimData {
                        schema_id: credential_schema_with_sd
                            .claim_schemas
                            .as_ref()
                            .await
                            .unwrap()[0]
                            .id,
                        path: "firstName".to_string(),
                        value: Some("name".to_string()),
                        selectively_disclosable: true,
                    },
                    ClaimData {
                        schema_id: credential_schema_with_sd
                            .claim_schemas
                            .as_ref()
                            .await
                            .unwrap()[1]
                            .id,
                        path: "isOver18".to_string(),
                        value: Some("false".to_string()),
                        selectively_disclosable: true,
                    },
                ]),
                ..Default::default()
            },
        )
        .await;

    // Allow both credential schemas
    let credential_query = CredentialQuery::ldp_vc(vec![
        vec![
            "https://www.w3.org/ns/credentials/v2".to_owned(),
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
    let proof = proof_for_dcql_query(
        &context,
        &org,
        &identifier,
        key,
        &dcql_query,
        "OPENID4VP_FINAL1",
        None,
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

    // both credentials are applicable
    let applicable = body["credentialQueries"]["test_id"]["applicableCredentials"]
        .as_array()
        .unwrap();
    let ids: Vec<String> = applicable
        .iter()
        .map(|c| c["id"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(ids.len(), 2);
    assert!(ids.contains(&credential1.common().id.to_string()));
    assert!(ids.contains(&credential2.common().id.to_string()));

    // credential1 (no SD): all schema claims are present and all are required, even though only
    // "firstName" was requested.
    let cred1 = applicable
        .iter()
        .find(|c| c["id"].as_str() == Some(&credential1.common().id.to_string()))
        .unwrap();
    let flat1 = flatten_claims(&cred1["claims"]);
    assert!(
        flat1
            .iter()
            .any(|(p, c)| p == "firstName" && c["required"] == true)
    );
    assert!(
        flat1
            .iter()
            .any(|(p, c)| p == "isOver18" && c["required"] == true)
    );

    // credential2 (BBS+ SD): only the requested "firstName" claim is selected.
    let cred2 = applicable
        .iter()
        .find(|c| c["id"].as_str() == Some(&credential2.common().id.to_string()))
        .unwrap();
    let flat2 = flatten_claims(&cred2["claims"]);
    assert!(flat2.iter().any(|(p, _)| p == "firstName"));
    assert!(!flat2.iter().any(|(p, _)| p == "isOver18"));

    let credential_sets = json!([{
        "options": [["test_id"]],
        "required": true
    }]);
    body["credentialSets"].assert_eq(&credential_sets);
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
                    ClaimData {
                        schema_id: claim_1.into(),
                        path: "firstName".to_string(),
                        value: Some("test-name".to_string()),
                        selectively_disclosable: true,
                    },
                    ClaimData {
                        schema_id: claim_2.into(),
                        path: "isOver18".to_string(),
                        value: Some("true".to_string()),
                        selectively_disclosable: true,
                    },
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
                    ClaimData {
                        schema_id: claim_1.into(),
                        path: "firstName".to_string(),
                        value: Some("test-name2".to_string()),
                        selectively_disclosable: true,
                    },
                    ClaimData {
                        schema_id: claim_2.into(),
                        path: "isOver18".to_string(),
                        value: Some("false".to_string()),
                        selectively_disclosable: true,
                    },
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
    let proof = proof_for_dcql_query(
        &context,
        &org,
        &identifier,
        key,
        &dcql_query,
        "OPENID4VP_FINAL1",
        None,
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
    let _ = &credential2;
    let applicable = body["credentialQueries"]["test_id"]["applicableCredentials"]
        .as_array()
        .unwrap();
    assert_eq!(applicable.len(), 1);
    applicable[0]["id"].assert_eq(&credential1.common().id);

    let flat = flatten_claims(&applicable[0]["claims"]);
    assert!(
        flat.iter()
            .any(|(p, c)| p == "isOver18" && c["required"] == true)
    );

    let credential_sets = json!([{
        "options": [["test_id"]],
        "required": true
    }]);
    body["credentialSets"].assert_eq(&credential_sets);
}

#[tokio::test]
async fn test_get_presentation_definition_dcql_using_multiple_flag() {
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
                    ClaimData {
                        schema_id: claim_1.into(),
                        path: "firstName".to_string(),
                        value: Some("test-name".to_string()),
                        selectively_disclosable: true,
                    },
                    ClaimData {
                        schema_id: claim_2.into(),
                        path: "isOver18".to_string(),
                        value: Some("true".to_string()),
                        selectively_disclosable: true,
                    },
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
        .multiple()
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
        None,
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
    body["credentialQueries"]["test_id"]["multiple"].assert_eq(&true);
    body["credentialQueries"]["test_id"]["applicableCredentials"][0]["id"]
        .assert_eq(&credential1.common().id);

    let flat =
        flatten_claims(&body["credentialQueries"]["test_id"]["applicableCredentials"][0]["claims"]);
    assert!(
        flat.iter()
            .any(|(p, c)| p == "isOver18" && c["required"] == true)
    );

    let credential_sets = json!([{
        "options": [["test_id"]],
        "required": true
    }]);
    body["credentialSets"].assert_eq(&credential_sets);
}

mod trusted_authorities {
    use one_core::mapper::x509::pem_chain_to_authority_key_identifiers;
    use one_core::model::certificate::Certificate;
    use one_core::model::organisation::Organisation;
    use similar_asserts::assert_eq;
    use standardized_types::x509::KeyIdentifier;

    use super::*;
    use crate::fixtures::certificate::{
        create_ca_cert, create_intermediate_ca_cert, ecdsa, eddsa, fingerprint,
    };

    struct CertificateInfo {
        pub cert: Certificate,
        pub aki: KeyIdentifier,
    }

    async fn create_cert_chain(
        context: &TestContext,
        organisation: &Organisation,
    ) -> (CertificateInfo, CertificateInfo) {
        let mut ca_cert_params = cert_params();
        let (ca_raw, ca_issuer) = create_ca_cert(&mut ca_cert_params, eddsa::Key);
        let ca_cert = create_db_cert(context, organisation, &ca_raw).await;
        let (intermediary_raw, _) = create_intermediate_ca_cert(
            &mut cert_params(),
            &ecdsa::Key,
            &ca_issuer,
            &ca_cert_params,
        );
        let intermediary_cert = create_db_cert(context, organisation, &intermediary_raw).await;
        (
            CertificateInfo {
                aki: aki_for_cert(&ca_cert),
                cert: ca_cert,
            },
            CertificateInfo {
                aki: aki_for_cert(&intermediary_cert),
                cert: intermediary_cert,
            },
        )
    }

    fn aki_for_cert(cert: &Certificate) -> KeyIdentifier {
        let vec = pem_chain_to_authority_key_identifiers(&cert.chain).unwrap();
        vec.into_iter().next().unwrap()
    }

    async fn create_db_cert(
        context: &TestContext,
        organisation: &Organisation,
        raw_cert: &rcgen::Certificate,
    ) -> Certificate {
        let identifier = context
            .db
            .identifiers
            .create(
                organisation,
                TestingIdentifierParams {
                    r#type: Some(IdentifierType::Certificate),
                    is_remote: Some(true),
                    ..Default::default()
                },
            )
            .await;

        context
            .db
            .certificates
            .create(
                identifier.id,
                organisation.clone(),
                TestingCertificateParams {
                    name: Some("issuer certificate".to_string()),
                    chain: Some(raw_cert.pem()),
                    fingerprint: Some(fingerprint(raw_cert)),
                    state: Some(CertificateState::Active),
                    ..Default::default()
                },
            )
            .await
    }

    fn cert_params() -> CertificateParams {
        let mut params = CertificateParams::default();
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
        ];
        params.use_authority_key_identifier_extension = true;
        params
    }

    #[tokio::test]
    async fn credential_found_when_aki_matches_root_ca() {
        // GIVEN
        let (context, org, _, identifier, key) = TestContext::new_with_did(None).await;

        let (root_ca_aki, intermediate_ca_cert) = {
            let certs = create_cert_chain(&context, &org).await;
            (certs.0.aki, certs.1.cert)
        };

        let vct = "https://example.org/foo";
        let credential_schema = context
            .db
            .credential_schemas
            .create(
                "Simple test schema",
                &org,
                TestingCreateSchemaParams {
                    schema_id: Some(vct.to_string()),
                    format: Some("SD_JWT_VC".into()),
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
                    issuer_certificate: Some(intermediate_ca_cert),
                    role: Some(CredentialRole::Holder),
                    claims_data: Some(vec![
                        ClaimData {
                            schema_id: credential_schema.claim_schemas.as_ref().await.unwrap()[0]
                                .id,
                            path: "firstName".to_string(),
                            value: Some("name".to_string()),
                            selectively_disclosable: true,
                        },
                        ClaimData {
                            schema_id: credential_schema.claim_schemas.as_ref().await.unwrap()[1]
                                .id,
                            path: "isOver18".to_string(),
                            value: Some("true".to_string()),
                            selectively_disclosable: true,
                        },
                    ]),
                    ..Default::default()
                },
            )
            .await;

        let credential_query = CredentialQuery::sd_jwt_vc(vec![vct.to_string()])
            .id("test_id")
            .trusted_authorities(vec![TrustedAuthority::AuthorityKeyId {
                values: vec![
                    // Add a bogus value to test whether a single match is sufficient
                    b"does-not-match".to_vec().into(),
                    root_ca_aki,
                ],
            }])
            .claims(vec![
                ClaimQuery::builder()
                    .path(vec!["firstName".to_string()])
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
            None,
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
            .assert_eq(&credential.common().id);

        let flat = flatten_claims(
            &body["credentialQueries"]["test_id"]["applicableCredentials"][0]["claims"],
        );
        assert!(
            flat.iter()
                .any(|(p, c)| p == "firstName" && c["required"] == true)
        );

        let credential_sets = json!([{
            "options": [["test_id"]],
            "required": true
        }]);
        body["credentialSets"].assert_eq(&credential_sets);
    }

    #[tokio::test]
    async fn credential_found_when_aki_matches_issuer() {
        // GIVEN
        let (context, org, _, identifier, key) = TestContext::new_with_did(None).await;

        let (intermediate_ca_cert, intermediate_ca_aki) = {
            let certs = create_cert_chain(&context, &org).await;
            (certs.1.cert, certs.1.aki)
        };

        let vct = "https://example.org/foo";
        let credential_schema = context
            .db
            .credential_schemas
            .create(
                "Simple test schema",
                &org,
                TestingCreateSchemaParams {
                    schema_id: Some(vct.to_string()),
                    format: Some("SD_JWT_VC".into()),
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
                    issuer_certificate: Some(intermediate_ca_cert),
                    role: Some(CredentialRole::Holder),
                    claims_data: Some(vec![
                        ClaimData {
                            schema_id: credential_schema.claim_schemas.as_ref().await.unwrap()[0]
                                .id,
                            path: "firstName".to_string(),
                            value: Some("name".to_string()),
                            selectively_disclosable: true,
                        },
                        ClaimData {
                            schema_id: credential_schema.claim_schemas.as_ref().await.unwrap()[1]
                                .id,
                            path: "isOver18".to_string(),
                            value: Some("true".to_string()),
                            selectively_disclosable: true,
                        },
                    ]),
                    ..Default::default()
                },
            )
            .await;

        let credential_query = CredentialQuery::sd_jwt_vc(vec![vct.to_string()])
            .id("test_id")
            .trusted_authorities(vec![TrustedAuthority::AuthorityKeyId {
                values: vec![
                    // Add a bogus value to test whether a single match is sufficient
                    b"does-not-match".to_vec().into(),
                    intermediate_ca_aki,
                ],
            }])
            .claims(vec![
                ClaimQuery::builder()
                    .path(vec!["firstName".to_string()])
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
            None,
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
            .assert_eq(&credential.common().id);

        let flat = flatten_claims(
            &body["credentialQueries"]["test_id"]["applicableCredentials"][0]["claims"],
        );
        assert!(
            flat.iter()
                .any(|(p, c)| p == "firstName" && c["required"] == true)
        );

        let credential_sets = json!([{
            "options": [["test_id"]],
            "required": true
        }]);
        body["credentialSets"].assert_eq(&credential_sets);
    }

    #[tokio::test]
    async fn empty_result_on_aki_mismatch() {
        // GIVEN
        let (context, org, _, identifier, key) = TestContext::new_with_did(None).await;

        let ca_cert = create_cert_chain(&context, &org).await.0.cert;

        let vct = "https://example.org/foo";
        let credential_schema = context
            .db
            .credential_schemas
            .create(
                "Simple test schema",
                &org,
                TestingCreateSchemaParams {
                    schema_id: Some(vct.to_string()),
                    format: Some("SD_JWT_VC".into()),
                    ..Default::default()
                },
            )
            .await;

        let _credential = context
            .db
            .credentials
            .create(
                &credential_schema,
                CredentialStateEnum::Accepted,
                &identifier,
                "OPENID4VCI_DRAFT13",
                TestingCredentialParams {
                    issuer_certificate: Some(ca_cert),
                    role: Some(CredentialRole::Holder),
                    claims_data: Some(vec![
                        ClaimData {
                            schema_id: credential_schema.claim_schemas.as_ref().await.unwrap()[0]
                                .id,
                            path: "firstName".to_string(),
                            value: Some("name".to_string()),
                            selectively_disclosable: true,
                        },
                        ClaimData {
                            schema_id: credential_schema.claim_schemas.as_ref().await.unwrap()[1]
                                .id,
                            path: "isOver18".to_string(),
                            value: Some("true".to_string()),
                            selectively_disclosable: true,
                        },
                    ]),
                    ..Default::default()
                },
            )
            .await;

        let credential_query = CredentialQuery::sd_jwt_vc(vec![vct.to_string()])
            .id("test_id")
            .trusted_authorities(vec![TrustedAuthority::AuthorityKeyId {
                values: vec![b"whatever".to_vec().into()],
            }])
            .claims(vec![
                ClaimQuery::builder()
                    .path(vec!["firstName".to_string()])
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
            None,
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
        body["credentialQueries"]["test_id"]["failureHint"]["reason"]
            .assert_eq(&"NO_CREDENTIAL".to_string());
    }

    #[tokio::test]
    async fn empty_result_on_empty_authority_list() {
        // GIVEN
        let (context, org, _, identifier, key) = TestContext::new_with_did(None).await;

        let ca_cert = create_cert_chain(&context, &org).await.0.cert;

        let vct = "https://example.org/foo";
        let credential_schema = context
            .db
            .credential_schemas
            .create(
                "Simple test schema",
                &org,
                TestingCreateSchemaParams {
                    schema_id: Some(vct.to_string()),
                    format: Some("SD_JWT_VC".into()),
                    ..Default::default()
                },
            )
            .await;

        let _credential = context
            .db
            .credentials
            .create(
                &credential_schema,
                CredentialStateEnum::Accepted,
                &identifier,
                "OPENID4VCI_DRAFT13",
                TestingCredentialParams {
                    issuer_certificate: Some(ca_cert),
                    role: Some(CredentialRole::Holder),
                    claims_data: Some(vec![
                        ClaimData {
                            schema_id: credential_schema.claim_schemas.as_ref().await.unwrap()[0]
                                .id,
                            path: "firstName".to_string(),
                            value: Some("name".to_string()),
                            selectively_disclosable: true,
                        },
                        ClaimData {
                            schema_id: credential_schema.claim_schemas.as_ref().await.unwrap()[1]
                                .id,
                            path: "isOver18".to_string(),
                            value: Some("true".to_string()),
                            selectively_disclosable: true,
                        },
                    ]),
                    ..Default::default()
                },
            )
            .await;

        let credential_query = CredentialQuery::sd_jwt_vc(vec![vct.to_string()])
            .id("test_id")
            .trusted_authorities(vec![])
            .claims(vec![
                ClaimQuery::builder()
                    .path(vec!["firstName".to_string()])
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
            None,
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
        body["credentialQueries"]["test_id"]["failureHint"]["reason"]
            .assert_eq(&"NO_CREDENTIAL".to_string());

        let credential_sets = json!([{
            "options": [["test_id"]],
            "required": true
        }]);
        body["credentialSets"].assert_eq(&credential_sets);
    }
}
