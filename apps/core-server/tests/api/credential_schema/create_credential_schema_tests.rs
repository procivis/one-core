use crate::utils::context::TestContext;
use crate::utils::field_match::FieldHelpers;

#[tokio::test]
async fn test_create_credential_schema_success() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;

    // WHEN
    let resp = context.api.credential_schemas.create(organisation.id).await;

    // THEN
    assert_eq!(resp.status(), 201);
    let resp = resp.json_value().await;

    let credential_schema = context.db.credential_schemas.get(&resp["id"].parse()).await;
    assert_eq!(credential_schema.name, "some credential schema");
    assert_eq!(credential_schema.revocation_method, "STATUSLIST2021");
    assert_eq!(credential_schema.organisation.unwrap().id, organisation.id);
    assert_eq!(credential_schema.format, "JWT");
    assert_eq!(credential_schema.claim_schemas.unwrap().len(), 1);
}
