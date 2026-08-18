use one_core::model::claim_schema::ClaimSchema;
use one_core::model::organisation::{OrganisationConfiguration, UpdateOrganisationRequest};
use serde_json::json;
use similar_asserts::assert_eq;
use sql_data_provider::test_utilities::get_dummy_date;
use uuid::Uuid;

use crate::utils::context::TestContext;
use crate::utils::db_clients::credential_schemas::TestingCreateSchemaParams;
use crate::utils::db_clients::proof_schemas::CreateProofInputSchema;
use crate::utils::db_clients::trust_collections::TestTrustCollectionParams;

#[tokio::test]
async fn test_get_verifier_provider_success() {
    // GIVEN
    let context = TestContext::new(None).await;

    // WHEN
    let resp = context.api.ssi.get_verifier_provider("PROCIVIS_ONE").await;

    // THEN
    assert_eq!(resp.status(), 200);
    let body = resp.json_value().await;
    assert_eq!(body["name"], "PROCIVIS_ONE");
    assert_eq!(body["appVersion"]["minimum"], "v1.50.0");
    assert_eq!(body["appVersion"]["minimumRecommended"], "v1.55.0");

    let reject = body["appVersion"]["reject"].as_array().unwrap();
    assert_eq!(reject.len(), 1);
    assert_eq!(reject[0], "v1.51.0");

    assert_eq!(
        body["appVersion"]["updateScreen"]["link"],
        "https//example.com"
    );
    assert_eq!(body["featureFlags"]["ecosystemsEnabled"], true);
    assert_eq!(body["featureFlags"]["ecosystemsEnforcementEnabled"], false);
    assert_eq!(body["trustCollections"].as_array().unwrap().len(), 0);

    // no organisation is assigned to the provider, so no ecosystems are advertised
    assert_eq!(body["ecosystems"], json!([]));
}

#[tokio::test]
async fn test_get_verifier_provider_failure() {
    // GIVEN
    let context = TestContext::new(None).await;

    // WHEN
    let resp = context
        .api
        .ssi
        .get_verifier_provider("DOES_NOT_EXIST")
        .await;

    // THEN
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_get_verifier_provider_with_ecosystems() {
    // GIVEN
    let config = indoc::indoc! {"
      verifierProvider:
        PROCIVIS_ONE:
          params:
            public:
              featureFlags:
                ecosystemsEnforcementEnabled: true
      ecosystem:
        EUDI:
          params:
            public:
              instanceProviderDefaultSelected: true
    "}
    .to_string();
    let (context, organisation) = TestContext::new_with_organisation(Some(config)).await;

    context
        .db
        .organisations
        .update(
            &organisation.id,
            UpdateOrganisationRequest {
                verifier_provider: Some(Some("PROCIVIS_ONE".to_string())),
                configuration: Some(OrganisationConfiguration {
                    selected_ecosystems: vec!["EUDI".into()],
                    ..Default::default()
                }),
                ..Default::default()
            },
        )
        .await;

    let collection = context
        .db
        .trust_collections
        .create(
            organisation.clone(),
            TestTrustCollectionParams {
                name: Some("EUDI collection".to_string()),
                ecosystem: Some("EUDI".into()),
                ..Default::default()
            },
        )
        .await;

    let claim_schema = ClaimSchema {
        id: Uuid::new_v4().into(),
        key: "firstName".to_string(),
        data_type: "STRING".to_string(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        array: false,
        metadata: false,
        required: true,
        translations: Default::default(),
    };

    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "ecosystem schema",
            &organisation,
            TestingCreateSchemaParams {
                ecosystem: Some("EUDI".into()),
                imported_source_url: Some("https://schemas.example.com/pid".to_string()),
                claim_schemas: Some(vec![claim_schema.clone()]),
                ..Default::default()
            },
        )
        .await;

    context
        .db
        .proof_schemas
        .create_with_ecosystem(
            "ecosystem proof schema",
            &organisation,
            vec![CreateProofInputSchema::from((
                &[(claim_schema.id.into(), "firstName", true, "STRING", false)][..],
                &credential_schema,
            ))],
            Some("EUDI".into()),
        )
        .await;

    // WHEN
    let resp = context.api.ssi.get_verifier_provider("PROCIVIS_ONE").await;

    // THEN
    assert_eq!(resp.status(), 200);
    let body = resp.json_value().await;

    assert_eq!(body["featureFlags"]["ecosystemsEnforcementEnabled"], true);

    let ecosystems = body["ecosystems"].as_array().unwrap();
    assert_eq!(ecosystems.len(), 1);

    let ecosystem = &ecosystems[0];
    assert_eq!(ecosystem["name"], "EUDI");
    assert_eq!(
        ecosystem["trustCollections"],
        json!([{"id": collection.id, "name": "EUDI collection"}])
    );
    assert_eq!(
        ecosystem["credentialSchemas"],
        json!(["https://schemas.example.com/pid"])
    );
    assert_eq!(ecosystem["proofSchemas"], json!(["CORE_URL"]));
    assert_eq!(ecosystem["defaultSelected"], true);

    // the deprecated flat lists mirror the entities of the advertised ecosystems
    let trust_collections = body["trustCollections"].as_array().unwrap();
    assert_eq!(trust_collections.len(), 1);
    assert_eq!(trust_collections[0]["id"], json!(collection.id));
    assert_eq!(trust_collections[0]["name"], "EUDI collection");
    assert_eq!(trust_collections[0]["defaultSelected"], true);
    assert_eq!(
        body["credentialSchemas"],
        json!(["https://schemas.example.com/pid"])
    );
    assert_eq!(body["proofSchemas"], json!(["CORE_URL"]));
}
