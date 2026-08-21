use one_core::model::claim_schema::ClaimSchema;
use similar_asserts::assert_eq;
use sql_data_provider::test_utilities::get_dummy_date;
use uuid::Uuid;

use crate::utils::context::TestContext;
use crate::utils::db_clients::credential_schemas::TestingCreateSchemaParams;
use crate::utils::field_match::FieldHelpers;

#[tokio::test]
async fn test_get_credential_schema_success() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create("test schema", &organisation, Default::default())
        .await;

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .get(&credential_schema.id)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    resp["id"].assert_eq(&credential_schema.id);
    resp["schemaId"].assert_eq(&credential_schema.id);
    assert_eq!(resp["format"], "JWT");
    resp["requiresWalletInstanceAttestation"]
        .assert_eq(&credential_schema.requires_wallet_instance_attestation);
    assert_eq!(resp["claims"].as_array().unwrap().len(), 2);
    assert_eq!(resp["revocationMethod"], "BITSTRINGSTATUSLIST");
    assert_eq!(resp["layoutProperties"]["background"]["color"], "#DA2727");
    assert_eq!(resp["layoutProperties"]["primaryAttribute"], "firstName");
    assert_eq!(resp["layoutProperties"]["secondaryAttribute"], "firstName");
    assert_eq!(resp["layoutProperties"]["logo"]["fontColor"], "#DA2727");
    assert_eq!(
        resp["layoutProperties"]["logo"]["backgroundColor"],
        "#DA2727"
    );
    assert_eq!(resp["layoutProperties"]["pictureAttribute"], "firstName");
    assert_eq!(resp["layoutProperties"]["code"]["attribute"], "firstName");
    assert_eq!(resp["layoutProperties"]["code"]["type"], "BARCODE");
    assert_eq!(resp["claims"][0]["translations"]["name"]["en"], "firstName");
    assert_eq!(resp["translations"]["name"]["en"], "test schema");
    assert!(resp["expiration"].is_null());
}

#[tokio::test]
async fn test_get_credential_schema_with_expiration() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test schema",
            &organisation,
            TestingCreateSchemaParams {
                expiration: Some(time::Duration::seconds(63072000)),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .get(&credential_schema.id)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    assert_eq!(resp["expiration"], 63072000);
}

#[tokio::test]
async fn test_get_credential_schema_with_category_claim() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let claim_id = Uuid::new_v4().into();
    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test schema",
            &organisation,
            TestingCreateSchemaParams {
                claim_schemas: Some(vec![ClaimSchema {
                    id: claim_id,
                    key: "category".to_string(),
                    data_type: "EAA_CATEGORY".to_string(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    array: false,
                    metadata: false,
                    required: true,
                    translations: Default::default(),
                }]),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .get(&credential_schema.id)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    resp["id"].assert_eq(&credential_schema.id);
    let claims = resp["claims"].as_array().unwrap();
    assert_eq!(claims.len(), 1);
    assert_eq!(claims[0]["datatype"], "EAA_CATEGORY");
    assert_eq!(claims[0]["translations"]["name"]["en"], "category");
}
