use one_core::model::credential_schema::CredentialSchemaType;

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
        .create(
            "test schema",
            &organisation,
            "STATUSLIST2021",
            Default::default(),
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
    resp["schemaId"].assert_eq(&credential_schema.id);
    assert_eq!(resp["claims"].as_array().unwrap().len(), 2);
    assert_eq!(resp["revocationMethod"], "STATUSLIST2021");
    assert_eq!(resp["layoutType"], "CARD");
    assert_eq!(resp["schemaType"], "ProcivisOneSchema2024");
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
}

#[tokio::test]
async fn test_get_credential_scheme_with_3rd_party_type() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test",
            &organisation,
            "NONE",
            TestingCreateSchemaParams {
                schema_type: Some(CredentialSchemaType::Other("foo".into())),
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
    assert_eq!(resp["schemaType"], "foo");
}
