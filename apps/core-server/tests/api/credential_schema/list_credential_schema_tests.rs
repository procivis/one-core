use one_core::service::credential_schema::dto::CredentialSchemaListIncludeEntityTypeEnum;
use similar_asserts::assert_eq;

use crate::utils::context::TestContext;

#[tokio::test]
async fn test_get_list_credential_schema_success() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    for i in 1..15 {
        context
            .db
            .credential_schemas
            .create(
                &format!("test-{i}"),
                &organisation,
                None,
                Default::default(),
            )
            .await;
    }

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .list(1, 8, &organisation.id, None)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    assert_eq!(resp["totalItems"], 14);
    assert_eq!(resp["totalPages"], 2);
    assert_eq!(resp["values"].as_array().unwrap().len(), 6);
}

#[tokio::test]
async fn test_get_list_credential_schema_include_layout_properties_success() {
    // GIVEN
    let (context, organisation, ..) = TestContext::new_with_did(None).await;
    context
        .db
        .credential_schemas
        .create("test", &organisation, None, Default::default())
        .await;

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .list(
            0,
            10,
            &organisation.id,
            Some(vec![
                CredentialSchemaListIncludeEntityTypeEnum::LayoutProperties,
            ]),
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    assert_eq!(resp["totalItems"], 1);
    assert_eq!(resp["totalPages"], 1);
    assert_eq!(resp["values"].as_array().unwrap().len(), 1);
    assert_eq!(
        resp["values"][0]["layoutProperties"]["background"]["color"],
        "#DA2727"
    );
    assert_eq!(
        resp["values"][0]["requiresWalletInstanceAttestation"],
        false
    );
    assert_eq!(
        resp["values"][0]["layoutProperties"]["primaryAttribute"],
        "firstName"
    );
    assert_eq!(
        resp["values"][0]["layoutProperties"]["logo"]["fontColor"],
        "#DA2727"
    );
}
