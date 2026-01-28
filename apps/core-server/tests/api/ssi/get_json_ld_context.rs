use similar_asserts::assert_eq;
use uuid::Uuid;

use crate::utils::context::TestContext;
use crate::utils::db_clients::credential_schemas::TestingCreateSchemaParams;

#[tokio::test]
async fn test_get_json_ld_context_success() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let core_base_url = &context.config.app.core_base_url;

    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test schema",
            &organisation,
            None,
            TestingCreateSchemaParams {
                format: Some("JSON_LD_CLASSIC".into()),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context
        .api
        .ssi
        .get_json_ld_context(credential_schema.id)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    assert_eq!(
        resp["@context"]["ProcivisOneSchema2024"]["@id"],
        format!(
            "{core_base_url}/ssi/context/v1/{}#ProcivisOneSchema2024",
            credential_schema.id
        )
    );
    assert_eq!(
        resp["@context"]["TestSchema"]["@id"],
        format!(
            "{core_base_url}/ssi/context/v1/{}#TestSchema",
            credential_schema.id
        )
    );
    assert_eq!(
        resp["@context"]["firstName"]["@id"],
        format!(
            "{core_base_url}/ssi/context/v1/{}#firstName",
            credential_schema.id
        )
    );
    assert_eq!(
        resp["@context"]["isOver18"]["@id"],
        format!(
            "{core_base_url}/ssi/context/v1/{}#isOver18",
            credential_schema.id
        )
    );
}

#[tokio::test]
async fn test_get_json_ld_context_not_found() {
    // GIVEN
    let context = TestContext::new(None).await;

    // WHEN
    let resp = context.api.ssi.get_json_ld_context(Uuid::new_v4()).await;

    // THEN
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_get_json_ld_context_with_nested_claims_success() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let core_base_url = &context.config.app.core_base_url;

    let credential_schema = context
        .db
        .credential_schemas
        .create_with_nested_claims(
            "test schema",
            &organisation,
            None,
            TestingCreateSchemaParams {
                format: Some("JSON_LD_CLASSIC".into()),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context
        .api
        .ssi
        .get_json_ld_context(credential_schema.id)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    let credential_schema_id = credential_schema.id;
    assert_eq!(
        resp["@context"]["ProcivisOneSchema2024"]["@id"],
        format!("{core_base_url}/ssi/context/v1/{credential_schema_id}#ProcivisOneSchema2024",)
    );
    assert_eq!(
        resp["@context"]["ProcivisOneSchema2024"]["@context"]["metadata"]["@id"],
        format!("{core_base_url}/ssi/context/v1/{credential_schema_id}#metadata",)
    );
    assert_eq!(
        resp["@context"]["TestSchema"]["@id"],
        format!("{core_base_url}/ssi/context/v1/{credential_schema_id}#TestSchema",)
    );
    assert_eq!(
        resp["@context"]["address"]["@id"],
        format!("{core_base_url}/ssi/context/v1/{credential_schema_id}#address",)
    );
    assert_eq!(
        resp["@context"]["address"]["@context"]["street"]["@id"],
        format!("{core_base_url}/ssi/context/v1/{credential_schema_id}#street",)
    );
    assert_eq!(
        resp["@context"]["address"]["@context"]["coordinates"]["@id"],
        format!("{core_base_url}/ssi/context/v1/{credential_schema_id}#coordinates",)
    );
    assert_eq!(
        resp["@context"]["address"]["@context"]["coordinates"]["@context"]["x"]["@id"],
        format!("{core_base_url}/ssi/context/v1/{credential_schema_id}#x",)
    );
    assert_eq!(
        resp["@context"]["address"]["@context"]["coordinates"]["@context"]["y"]["@id"],
        format!("{core_base_url}/ssi/context/v1/{credential_schema_id}#y",)
    );
}

#[tokio::test]
async fn test_get_json_ld_context_special_chars_success() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let core_base_url = &context.config.app.core_base_url;

    let credential_schema = context
        .db
        .credential_schemas
        .create_special_chars(
            "test schema",
            &organisation,
            None,
            TestingCreateSchemaParams {
                format: Some("JSON_LD_CLASSIC".into()),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context
        .api
        .ssi
        .get_json_ld_context(credential_schema.id)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    let credential_schema_id = credential_schema.id;
    assert_eq!(
        resp["@context"]["ProcivisOneSchema2024"]["@id"],
        format!("{core_base_url}/ssi/context/v1/{credential_schema_id}#ProcivisOneSchema2024",)
    );
    assert_eq!(
        resp["@context"]["first name#"]["@id"],
        format!("{core_base_url}/ssi/context/v1/{credential_schema_id}#first%20name%23",)
    );
}

#[tokio::test]
async fn test_get_json_ld_context_credential_invalid_format() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test schema",
            &organisation,
            None,
            TestingCreateSchemaParams {
                format: Some("MDOC".into()),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context
        .api
        .ssi
        .get_json_ld_context(credential_schema.id)
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
}
