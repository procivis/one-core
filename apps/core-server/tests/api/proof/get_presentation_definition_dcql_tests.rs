use std::collections::HashMap;

use core_server::endpoint::proof::dto::PresentationDefinitionFieldRestDTO;
use dcql::{
    ClaimQuery, ClaimQueryId, ClaimValue, CredentialQuery, DcqlQuery, PathSegment, TrustedAuthority,
};
use one_core::model::certificate::CertificateState;
use one_core::model::claim_schema::ClaimSchema;
use one_core::model::credential::{CredentialRole, CredentialStateEnum};
use one_core::model::credential_schema::CredentialSchemaClaim;
use one_core::model::identifier::IdentifierType;
use rcgen::{CertificateParams, KeyUsagePurpose};
use serde_json::json;
use similar_asserts::assert_eq;
use sql_data_provider::test_utilities::get_dummy_date;
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
            "NONE",
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
                        schema_id: credential_schema.claim_schemas.as_ref().unwrap()[0]
                            .schema
                            .id,
                        path: "firstName".to_string(),
                        value: Some("name".to_string()),
                        selectively_disclosable: true,
                    },
                    ClaimData {
                        schema_id: credential_schema.claim_schemas.as_ref().unwrap()[1]
                            .schema
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
        "OPENID4VP_DRAFT25",
    )
    .await;

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
            "NONE",
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
        "OPENID4VP_DRAFT25",
    )
    .await;

    // WHEN
    let resp = context.api.proofs.presentation_definition(proof.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let body = resp.json_value().await;
    assert_eq!(body["credentials"][0]["id"], credential.id.to_string());
    body["requestGroups"][0]["requestedCredentials"][0]["applicableCredentials"]
        .assert_eq(&vec![credential.id.to_string()]);
    let field1 = json!({
        "id": "test_id:first",
        "keyMap": {
            credential.id.to_string(): "first"
        },
        "name": "first",
        "required": true
    });
    body["requestGroups"][0]["requestedCredentials"][0]["fields"].assert_eq(&[field1]);
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
            "NONE",
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
        "OPENID4VP_DRAFT25",
    )
    .await;

    // WHEN
    let resp = context.api.proofs.presentation_definition(proof.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let body = resp.json_value().await;
    assert_eq!(body["credentials"][0]["id"], credential.id.to_string());

    let group = body["requestGroups"][0]["requestedCredentials"][0]
        .as_object()
        .unwrap();
    group["applicableCredentials"].assert_eq(&vec![credential.id.to_string()]);

    let fields: Vec<PresentationDefinitionFieldRestDTO> =
        serde_json::from_value(group["fields"].to_owned()).unwrap();
    assert_eq!(fields.len(), 3);

    // false because it is optional in the request and selectively disclosable
    assert_field_required_flag("first", false, &fields);
    assert_field_required_flag("first/second", false, &fields);

    // true because it is not selectively disclosable
    assert_field_required_flag("first/sibling", true, &fields);
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
            "NONE",
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
                        schema_id: claim_3.into(),
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
        "OPENID4VP_DRAFT25",
    )
    .await;

    // WHEN
    let resp = context.api.proofs.presentation_definition(proof.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let body = resp.json_value().await;
    assert_eq!(body["credentials"][0]["id"], credential.id.to_string());

    let group = body["requestGroups"][0]["requestedCredentials"][0]
        .as_object()
        .unwrap();
    group["applicableCredentials"].assert_eq(&vec![credential.id.to_string()]);

    let fields: Vec<PresentationDefinitionFieldRestDTO> =
        serde_json::from_value(group["fields"].to_owned()).unwrap();
    assert_eq!(fields.len(), 3);

    // true because it is mandatory in the request
    assert_field_required_flag("first", true, &fields);
    assert_field_required_flag("first/second", true, &fields);

    // true because it is not selectively disclosable
    assert_field_required_flag("first/sibling", true, &fields);
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
            "NONE",
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
        "OPENID4VP_DRAFT25",
    )
    .await;

    // WHEN
    let resp = context.api.proofs.presentation_definition(proof.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let body = resp.json_value().await;
    assert_eq!(body["credentials"][0]["id"], credential.id.to_string());

    let group = body["requestGroups"][0]["requestedCredentials"][0]
        .as_object()
        .unwrap();
    group["applicableCredentials"].assert_eq(&vec![credential.id.to_string()]);

    let fields: Vec<PresentationDefinitionFieldRestDTO> =
        serde_json::from_value(group["fields"].to_owned()).unwrap();
    assert_eq!(fields.len(), 6);

    // false because it is optional in the request and selectively disclosable
    assert_field_required_flag("first", false, &fields);
    assert_field_required_flag("first/second", false, &fields);
    assert_field_required_flag("first/second/third", false, &fields);
    assert_field_required_flag("first/second/third/0", false, &fields);

    // true because it is not selectively disclosable
    assert_field_required_flag("first/second/third/1", true, &fields);
    assert_field_required_flag("first/sibling", true, &fields);
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
            "NONE",
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
        "OPENID4VP_DRAFT25",
    )
    .await;

    // WHEN
    let resp = context.api.proofs.presentation_definition(proof.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let body = resp.json_value().await;
    assert_eq!(body["credentials"][0]["id"], credential.id.to_string());

    let group = body["requestGroups"][0]["requestedCredentials"][0]
        .as_object()
        .unwrap();
    group["applicableCredentials"].assert_eq(&vec![credential.id.to_string()]);

    let fields: Vec<PresentationDefinitionFieldRestDTO> =
        serde_json::from_value(group["fields"].to_owned()).unwrap();
    assert_eq!(fields.len(), 6);

    // false because it is optional in the request and selectively disclosable
    assert_field_required_flag("first", false, &fields);
    assert_field_required_flag("first/0", false, &fields);
    assert_field_required_flag("first/1", false, &fields);
    assert_field_required_flag("first/0/second", false, &fields);
    assert_field_required_flag("first/1/second", false, &fields);

    // true because it is not selectively disclosable
    assert_field_required_flag("first/0/sibling", true, &fields);
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
            "NONE",
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
        "OPENID4VP_DRAFT25",
    )
    .await;

    // WHEN
    let resp = context.api.proofs.presentation_definition(proof.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let body = resp.json_value().await;
    assert_eq!(body["credentials"][0]["id"], credential.id.to_string());

    let group = body["requestGroups"][0]["requestedCredentials"][0]
        .as_object()
        .unwrap();
    group["applicableCredentials"].assert_eq(&vec![credential.id.to_string()]);

    let fields: Vec<PresentationDefinitionFieldRestDTO> =
        serde_json::from_value(group["fields"].to_owned()).unwrap();
    assert_eq!(fields.len(), 6);

    // true because it is required by verifier
    assert_field_required_flag("first/0/second", true, &fields);
    assert_field_required_flag("first/1/second", true, &fields);

    // true because it is a transitive parent of a claim required by verifier
    assert_field_required_flag("first", true, &fields);
    assert_field_required_flag("first/0", true, &fields);
    assert_field_required_flag("first/1", true, &fields);

    // true because it is not selectively disclosable
    assert_field_required_flag("first/0/sibling", true, &fields);
}

fn assert_field_required_flag(
    field_name: &str,
    required: bool,
    fields: &[PresentationDefinitionFieldRestDTO],
) {
    let requested_field = fields
        .iter()
        .find(|field| field.name.as_ref().unwrap() == field_name)
        .unwrap();
    assert_eq!(requested_field.required.unwrap(), required);
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
    let proof = proof_for_dcql_query(
        &context,
        &org,
        &identifier,
        key,
        &dcql_query,
        "OPENID4VP_DRAFT25",
    )
    .await;

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
            "NONE",
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
        "https://core.dev.procivis-one.com/ssi/context/v1/lvvc.json".to_owned(),
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
        "OPENID4VP_DRAFT25",
    )
    .await;

    // WHEN
    let resp = context.api.proofs.presentation_definition(proof.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let body = resp.json_value().await;
    assert_eq!(body["credentials"][0]["id"], credential.id.to_string());
    let credential_request = &body["requestGroups"][0]["requestedCredentials"][0];
    credential_request["inapplicableCredentials"].assert_eq(&vec![credential.id.to_string()]);
    assert_eq!(
        credential_request["applicableCredentials"]
            .as_array()
            .unwrap()
            .len(),
        0
    );

    let field_non_existing = json!({
        "id": "test_id:non-existing-claim",
        "keyMap": {},
        "name": "non-existing-claim",
        "required": true,
    });
    let field_1 = json!({
        "id": "test_id:firstName",
        "keyMap": {
            credential.id.to_string(): "firstName"
        },
        "name": "firstName",
        "required": true
    });
    let field_2 = json!({
        "id": "test_id:isOver18",
        "keyMap": {
            credential.id.to_string(): "isOver18"
        },
        "name": "isOver18",
        "required": true
    });
    credential_request["fields"].assert_eq_unordered(&[field_1, field_2, field_non_existing]);
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
        "OPENID4VP_DRAFT25",
    )
    .await;

    // WHEN
    let resp = context.api.proofs.presentation_definition(proof.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let body = resp.json_value().await;
    assert_eq!(body["credentials"][0]["id"], credential.id.to_string());
    body["requestGroups"][0]["requestedCredentials"][0]["inapplicableCredentials"]
        .assert_eq(&vec![credential.id.to_string()]);

    let field_found = json!({
        "id": "test_id:firstName",
        "keyMap": {
            credential.id.to_string(): "firstName"
        },
        "name": "firstName",
        "required": true
    });
    let field_not_found = json!({
        "id": "test_id:isOver18",
        "keyMap": {},
        "name": "isOver18",
        "required": true
    });
    body["requestGroups"][0]["requestedCredentials"][0]["fields"]
        .assert_eq_unordered(&[field_found, field_not_found]);
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
        "OPENID4VP_DRAFT25",
    )
    .await;

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
            "NONE",
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
        "OPENID4VP_DRAFT25",
    )
    .await;

    // WHEN
    let resp = context.api.proofs.presentation_definition(proof.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let body = resp.json_value().await;
    body["requestGroups"][0]["requestedCredentials"][0]["applicableCredentials"]
        .assert_eq_unordered(&[credential1.id.to_string(), credential2.id.to_string()]);
    let field1 = json!({
        "id": "test_id:first",
        "keyMap": {
            credential1.id.to_string(): "first"
        },
        "name": "first",
        "required": true
    });
    let field2 = json!({
        "id": "test_id:second",
        "keyMap": {
            credential2.id.to_string(): "second"
        },
        "name": "second",
        "required": true
    });
    body["requestGroups"][0]["requestedCredentials"][0]["fields"]
        .assert_eq_unordered(&[field1, field2]);
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
            "NONE",
            TestingCreateSchemaParams {
                schema_id: Some(vct.to_owned()),
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
        "OPENID4VP_DRAFT25",
    )
    .await;

    // WHEN
    let resp = context.api.proofs.presentation_definition(proof.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let body = resp.json_value().await;
    body["requestGroups"][0]["requestedCredentials"][0]["applicableCredentials"]
        .assert_eq(&[credential1.id.to_string()]);
    // credential 2 is inapplicable because the iss claim has the wrong value
    body["requestGroups"][0]["requestedCredentials"][0]["inapplicableCredentials"]
        .assert_eq(&[credential2.id.to_string()]);
    let field1 = json!({
        "id": "test_id:string_claim",
        "keyMap": {
            credential1.id.to_string(): "string_claim",
            credential2.id.to_string(): "string_claim"
        },
        "name": "string_claim",
        "required": true
    });
    // Metadata claims (such as iss) are used for matching, but are _not_ added to the fields array.
    body["requestGroups"][0]["requestedCredentials"][0]["fields"].assert_eq(&[field1]);
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
        "OPENID4VP_DRAFT25",
    )
    .await;

    // WHEN
    let resp = context.api.proofs.presentation_definition(proof.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let body = resp.json_value().await;
    let field1 = json!({
        "id": "test_id:string_claim",
        "keyMap": {},
        "name": "string_claim",
        "required": true
    });
    // Metadata claims (such as iss) are used for matching, but are _not_ added to the fields array.
    body["requestGroups"][0]["requestedCredentials"][0]["fields"].assert_eq(&[field1]);
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
                        schema_id: credential_schema.claim_schemas.as_ref().unwrap()[0]
                            .schema
                            .id,
                        path: "firstName".to_string(),
                        value: Some("name1".to_string()),
                        selectively_disclosable: true,
                    },
                    ClaimData {
                        schema_id: credential_schema.claim_schemas.as_ref().unwrap()[1]
                            .schema
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
                        schema_id: credential_schema.claim_schemas.as_ref().unwrap()[0]
                            .schema
                            .id,
                        path: "firstName".to_string(),
                        value: Some("name2".to_string()),
                        selectively_disclosable: true,
                    },
                    ClaimData {
                        schema_id: credential_schema.claim_schemas.as_ref().unwrap()[1]
                            .schema
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
        "OPENID4VP_DRAFT25",
    )
    .await;

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
        "OPENID4VP_DRAFT25",
    )
    .await;

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
                    schema_id: credential_schema.claim_schemas.as_ref().unwrap()[0]
                        .schema
                        .id,
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
        "OPENID4VP_DRAFT25",
    )
    .await;

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
            "NONE",
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
                        schema_id: credential_schema_with_sd.claim_schemas.as_ref().unwrap()[0]
                            .schema
                            .id,
                        path: "firstName".to_string(),
                        value: Some("name".to_string()),
                        selectively_disclosable: true,
                    },
                    ClaimData {
                        schema_id: credential_schema_with_sd.claim_schemas.as_ref().unwrap()[1]
                            .schema
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
    let proof = proof_for_dcql_query(
        &context,
        &org,
        &identifier,
        key,
        &dcql_query,
        "OPENID4VP_DRAFT25",
    )
    .await;

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
        "OPENID4VP_DRAFT25",
    )
    .await;

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
        "OPENID4VP_DRAFT25",
    )
    .await;

    // WHEN
    let resp = context.api.proofs.presentation_definition(proof.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let body = resp.json_value().await;
    assert_eq!(body["credentials"].as_array().unwrap().len(), 1);
    let expected_requested_credentials = json!({
        "applicableCredentials": [credential1.id.to_string()],
        "multiple": true,
        "fields": [{
            "id": "test_id:isOver18",
            "keyMap": {
                credential1.id.to_string(): "isOver18",
            },
            "name": "isOver18",
            "required": true,
        }],
        "id": "test_id"
    });
    body["requestGroups"][0]["requestedCredentials"][0].assert_eq(&expected_requested_credentials);
}

mod trusted_authorities {
    use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
    use one_core::model::certificate::Certificate;
    use one_core::model::organisation::Organisation;
    use one_core::util::authority_key_identifier::get_akis_for_pem_chain;
    use similar_asserts::assert_eq;

    use super::*;
    use crate::fixtures::certificate::{
        create_ca_cert, create_intermediate_ca_cert, ecdsa, eddsa, fingerprint,
    };

    struct CertificateInfo {
        pub cert: Certificate,
        pub aki_b64: String,
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
                aki_b64: aki_for_cert(&ca_cert),
                cert: ca_cert,
            },
            CertificateInfo {
                aki_b64: aki_for_cert(&intermediary_cert),
                cert: intermediary_cert,
            },
        )
    }

    fn aki_for_cert(cert: &Certificate) -> String {
        let vec = get_akis_for_pem_chain(cert.chain.as_bytes()).unwrap();
        let first = vec.into_iter().next().unwrap();
        Base64UrlSafeNoPadding::encode_to_string(first.0.as_slice()).unwrap()
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
                TestingCertificateParams {
                    name: Some("issuer certificate".to_string()),
                    chain: Some(raw_cert.pem()),
                    fingerprint: Some(fingerprint(raw_cert)),
                    state: Some(CertificateState::Active),
                    organisation_id: Some(organisation.id),
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
            (certs.0.aki_b64, certs.1.cert)
        };

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
                            schema_id: credential_schema.claim_schemas.as_ref().unwrap()[0]
                                .schema
                                .id,
                            path: "firstName".to_string(),
                            value: Some("name".to_string()),
                            selectively_disclosable: true,
                        },
                        ClaimData {
                            schema_id: credential_schema.claim_schemas.as_ref().unwrap()[1]
                                .schema
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
                    Base64UrlSafeNoPadding::encode_to_string("does-not-match").unwrap(),
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
            "OPENID4VP_DRAFT25",
        )
        .await;

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
    async fn credential_found_when_aki_matches_issuer() {
        // GIVEN
        let (context, org, _, identifier, key) = TestContext::new_with_did(None).await;

        let (intermediate_ca_cert, intermediate_ca_aki) = {
            let certs = create_cert_chain(&context, &org).await;
            (certs.1.cert, certs.1.aki_b64)
        };

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
                            schema_id: credential_schema.claim_schemas.as_ref().unwrap()[0]
                                .schema
                                .id,
                            path: "firstName".to_string(),
                            value: Some("name".to_string()),
                            selectively_disclosable: true,
                        },
                        ClaimData {
                            schema_id: credential_schema.claim_schemas.as_ref().unwrap()[1]
                                .schema
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
                    Base64UrlSafeNoPadding::encode_to_string("does-not-match").unwrap(),
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
            "OPENID4VP_DRAFT25",
        )
        .await;

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
                "NONE",
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
                            schema_id: credential_schema.claim_schemas.as_ref().unwrap()[0]
                                .schema
                                .id,
                            path: "firstName".to_string(),
                            value: Some("name".to_string()),
                            selectively_disclosable: true,
                        },
                        ClaimData {
                            schema_id: credential_schema.claim_schemas.as_ref().unwrap()[1]
                                .schema
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
                values: vec![Base64UrlSafeNoPadding::encode_to_string("whatever").unwrap()],
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
            "OPENID4VP_DRAFT25",
        )
        .await;

        // WHEN
        let resp = context.api.proofs.presentation_definition(proof.id).await;

        // THEN
        assert_eq!(resp.status(), 200);
        let resp_body = resp.json_value().await;
        let resp_credentials = resp_body["credentials"].as_array().unwrap();
        assert!(resp_credentials.is_empty());
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
                "NONE",
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
                            schema_id: credential_schema.claim_schemas.as_ref().unwrap()[0]
                                .schema
                                .id,
                            path: "firstName".to_string(),
                            value: Some("name".to_string()),
                            selectively_disclosable: true,
                        },
                        ClaimData {
                            schema_id: credential_schema.claim_schemas.as_ref().unwrap()[1]
                                .schema
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
            "OPENID4VP_DRAFT25",
        )
        .await;

        // WHEN
        let resp = context.api.proofs.presentation_definition(proof.id).await;

        // THEN
        assert_eq!(resp.status(), 200);
        let resp_body = resp.json_value().await;
        let resp_credentials = resp_body["credentials"].as_array().unwrap();
        assert!(resp_credentials.is_empty());
    }
}
