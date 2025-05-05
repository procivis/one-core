use crate::fixtures::TestingKeyParams;
use crate::utils::context::TestContext;

#[tokio::test]
async fn test_identifier_success() {
    let (context, organisation, _, _, _) = TestContext::new_with_did(None).await;

    let key = context
        .db
        .keys
        .create(&organisation, TestingKeyParams::default())
        .await;

    let result = context
        .api
        .identifiers
        .create_key_identifier("test-identifier", key.id, organisation.id)
        .await;

    assert_eq!(result.status(), 201);
    let resp = result.json_value().await;
    let identifier_id = resp["id"].as_str().unwrap().parse().unwrap();

    let result = context.api.identifiers.get(&identifier_id).await;
    assert_eq!(result.status(), 200);
    let resp = result.json_value().await;

    assert_eq!(resp["name"].as_str().unwrap(), "test-identifier");
    assert_eq!(resp["type"].as_str().unwrap(), "KEY");
    assert_eq!(resp["status"].as_str().unwrap(), "ACTIVE");
    assert!(!resp["isRemote"].as_bool().unwrap());
    assert_eq!(
        resp["organisationId"].as_str().unwrap(),
        organisation.id.to_string()
    );
    assert_eq!(resp["key"]["id"].as_str().unwrap(), key.id.to_string());

    let delete_resp = context.api.identifiers.delete(&identifier_id).await;
    assert_eq!(delete_resp.status(), 204);

    let already_deleted = context.api.identifiers.delete(&identifier_id).await;
    assert_eq!(already_deleted.status(), 404);
}
