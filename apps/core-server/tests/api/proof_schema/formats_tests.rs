use one_core::model::credential_schema::CredentialSchema;
use one_core::model::credential_schema_format::CredentialSchemaFormat;
use one_core::model::organisation::Organisation;
use one_core::repository::DataRepository;
use serde_json::{Value, json};
use shared_types::ProofSchemaId;
use similar_asserts::assert_eq;
use uuid::Uuid;

use crate::utils::context::TestContext;
use crate::utils::db_clients::credential_schemas::TestingCreateSchemaParams;

async fn multiformat_schema(
    context: &TestContext,
    organisation: &Organisation,
) -> CredentialSchema {
    context
        .db
        .credential_schemas
        .create(
            "multiformat",
            organisation,
            TestingCreateSchemaParams {
                formats: Some(vec![
                    ("JWT".into(), "jwt-schema".into()),
                    ("SD_JWT_VC".into(), "sd-jwt-schema".into()),
                ]),
                allow_revocation: Some(false),
                allow_suspension: Some(false),
                ..Default::default()
            },
        )
        .await
}

async fn input(schema: &CredentialSchema, formats: Option<Value>) -> Value {
    let mut input = json!({
        "credentialSchemaId": schema.id,
        "claimSchemas": [{"id": schema.claim_schemas.as_ref().await.unwrap()[0].id, "required": true}]
    });
    if let Some(formats) = formats {
        input["formats"] = formats;
    }
    input
}

async fn create(
    context: &TestContext,
    organisation: &Organisation,
    schema: &CredentialSchema,
    name: &str,
    formats: Option<Value>,
) -> ProofSchemaId {
    let response = context
        .api
        .proof_schemas
        .create_with_multiple_schemas(name, organisation.id, json!([input(schema, formats).await]))
        .await;
    assert_eq!(response.status(), 201);
    serde_json::from_value(response.json_value().await["id"].clone()).unwrap()
}

async fn export(
    context: &TestContext,
    organisation: &Organisation,
    schema: &CredentialSchema,
    formats: Value,
) -> Value {
    let id = create(context, organisation, schema, "source", Some(formats)).await;
    let response = context.api.ssi.get_proof_schema(id).await;
    assert_eq!(response.status(), 200);
    response.json_value().await
}

#[tokio::test]
async fn create_details_and_export_preserve_format_snapshots() {
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let schema = multiformat_schema(&context, &organisation).await;
    let mut snapshots = Vec::new();
    for (name, selection, expected) in [
        ("default", None, json!(["JWT", "SD_JWT_VC"])),
        ("subset", Some(json!(["SD_JWT_VC"])), json!(["SD_JWT_VC"])),
        (
            "ordered",
            Some(json!(["SD_JWT_VC", "JWT"])),
            json!(["SD_JWT_VC", "JWT"]),
        ),
    ] {
        snapshots.push((
            create(&context, &organisation, &schema, name, selection).await,
            expected,
        ));
    }

    // Adding a format to the credential schema must not widen any saved selection.
    sql_data_provider::DataLayer::build(context.db.db_conn.clone(), vec![])
        .get_credential_schema_format_repository()
        .create_credential_schema_format(CredentialSchemaFormat {
            id: Uuid::new_v4().into(),
            credential_schema_id: schema.id,
            created_date: one_core::clock::now_utc(),
            last_modified: one_core::clock::now_utc(),
            format: "SD_JWT".into(),
            ecosystem_schema_id: "later-format".into(),
            claim_mappings: Default::default(),
        })
        .await
        .unwrap();

    for (id, expected) in snapshots {
        let stored = context.db.proof_schemas.get(&id).await;
        assert_eq!(
            serde_json::to_value(&stored.input_schemas.as_ref().await.unwrap()[0].formats).unwrap(),
            expected
        );
        let details = context.api.proof_schemas.get(id).await;
        assert_eq!(details.status(), 200);
        assert_eq!(
            details.json_value().await["proofInputSchemas"][0]["formats"],
            expected
        );
        let export = context.api.ssi.get_proof_schema(id).await;
        assert_eq!(export.status(), 200);
        assert_eq!(
            export.json_value().await["proofInputSchemas"][0]["formats"],
            expected
        );
    }
}

#[tokio::test]
async fn create_rejects_invalid_format_selections() {
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let schema = multiformat_schema(&context, &organisation).await;
    for (selection, code) in [
        (json!([]), "BR_0508"),
        (json!(["JWT", "JWT"]), "BR_0509"),
        (json!(["MDOC"]), "BR_0510"),
        (json!(["unknown"]), "BR_0510"),
        (json!([" JWT"]), "BR_0510"),
    ] {
        let response = context
            .api
            .proof_schemas
            .create_with_multiple_schemas(
                "invalid",
                organisation.id,
                json!([input(&schema, Some(selection)).await]),
            )
            .await;
        assert_eq!(response.status(), 400);
        assert_eq!(response.error_code().await, code);
    }
}

#[tokio::test]
async fn create_resolves_each_input_independently() {
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let first = multiformat_schema(&context, &organisation).await;
    let second = context
        .db
        .credential_schemas
        .create("second", &organisation, Default::default())
        .await;
    let response = context
        .api
        .proof_schemas
        .create_with_multiple_schemas(
            "multiple",
            organisation.id,
            json!([
                input(&first, Some(json!(["SD_JWT_VC"]))).await,
                input(&second, None).await,
            ]),
        )
        .await;
    assert_eq!(response.status(), 201);
    let id: ProofSchemaId =
        serde_json::from_value(response.json_value().await["id"].clone()).unwrap();
    let details = context.api.proof_schemas.get(id).await.json_value().await;
    assert_eq!(
        details["proofInputSchemas"][0]["formats"],
        json!(["SD_JWT_VC"])
    );
    assert_eq!(details["proofInputSchemas"][1]["formats"], json!(["JWT"]));
}

#[tokio::test]
async fn import_preserves_explicit_formats_with_existing_credential_schema() {
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let schema = multiformat_schema(&context, &organisation).await;
    let mut exported = export(&context, &organisation, &schema, json!(["SD_JWT_VC"])).await;
    exported["name"] = json!("explicit import");
    let response = context
        .api
        .proof_schemas
        .import(exported, organisation.id)
        .await;
    assert_eq!(response.status(), 201);
    let id: ProofSchemaId =
        serde_json::from_value(response.json_value().await["id"].clone()).unwrap();
    let details = context.api.proof_schemas.get(id).await.json_value().await;
    assert_eq!(
        details["proofInputSchemas"][0]["formats"],
        json!(["SD_JWT_VC"])
    );
    assert_eq!(
        details["proofInputSchemas"][0]["credentialSchema"]["id"],
        json!(schema.id)
    );
}

#[tokio::test]
async fn import_without_formats_uses_all_formats_from_existing_credential_schema() {
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let schema = multiformat_schema(&context, &organisation).await;
    let mut exported = export(&context, &organisation, &schema, json!(["SD_JWT_VC"])).await;
    exported["name"] = json!("import without formats");
    exported["proofInputSchemas"][0]
        .as_object_mut()
        .unwrap()
        .remove("formats");
    let response = context
        .api
        .proof_schemas
        .import(exported, organisation.id)
        .await;
    assert_eq!(response.status(), 201);
    let id: ProofSchemaId =
        serde_json::from_value(response.json_value().await["id"].clone()).unwrap();
    let details = context.api.proof_schemas.get(id).await.json_value().await;
    assert_eq!(
        details["proofInputSchemas"][0]["formats"],
        json!(["JWT", "SD_JWT_VC"])
    );
    assert_eq!(
        details["proofInputSchemas"][0]["credentialSchema"]["id"],
        json!(schema.id)
    );
}

#[tokio::test]
async fn import_rejects_invalid_formats_with_existing_credential_schema() {
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let schema = multiformat_schema(&context, &organisation).await;
    let export = export(&context, &organisation, &schema, json!(["SD_JWT_VC"])).await;
    for (selection, code) in [
        (json!([]), "BR_0508"),
        (json!(["JWT", "JWT"]), "BR_0509"),
        (json!(["JWT", "MDOC"]), "BR_0510"),
    ] {
        let mut exported = export.clone();
        exported["name"] = json!("invalid import");
        exported["proofInputSchemas"][0]["formats"] = selection;
        let response = context
            .api
            .proof_schemas
            .import(exported, organisation.id)
            .await;
        assert_eq!(response.status(), 400);
        assert_eq!(response.error_code().await, code);
    }
}

#[tokio::test]
async fn import_resolves_formats_from_downloaded_multiformat_schema() {
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let schema = multiformat_schema(&context, &organisation).await;
    let export = export(
        &context,
        &organisation,
        &schema,
        json!(["SD_JWT_VC", "JWT"]),
    )
    .await;
    let mut credential_export = context
        .api
        .ssi
        .get_credential_schema_v2(schema.id)
        .await
        .json_value()
        .await;
    let mock = wiremock::MockServer::start().await;
    let path = format!("/ssi/schema/v2/{}", schema.id);
    let source_url = format!("{}{path}", mock.uri());
    credential_export["importedSourceUrl"] = json!(source_url);
    wiremock::Mock::given(wiremock::matchers::path(path))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(credential_export))
        .expect(2)
        .mount(&mock)
        .await;

    for legacy in [false, true] {
        let destination = context.db.organisations.create().await;
        let mut exported = export.clone();
        exported["proofInputSchemas"][0]["credentialSchema"]["importedSourceUrl"] =
            json!(source_url);
        if legacy {
            exported["proofInputSchemas"][0]
                .as_object_mut()
                .unwrap()
                .remove("formats");
        }
        let response = context
            .api
            .proof_schemas
            .import(exported, destination.id)
            .await;
        assert_eq!(response.status(), 201);
        let id: ProofSchemaId =
            serde_json::from_value(response.json_value().await["id"].clone()).unwrap();
        let details = context.api.proof_schemas.get(id).await.json_value().await;
        let expected = if legacy {
            json!(["JWT", "SD_JWT_VC"])
        } else {
            json!(["SD_JWT_VC", "JWT"])
        };
        assert_eq!(details["proofInputSchemas"][0]["formats"], expected);
    }
}
