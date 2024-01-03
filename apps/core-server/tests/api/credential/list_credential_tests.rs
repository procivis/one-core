use one_core::model::credential::CredentialStateEnum;
use time::OffsetDateTime;

use crate::fixtures::TestingCredentialParams;
use crate::utils::context::TestContext;

#[tokio::test]
async fn test_get_list_credential_success() {
    // GIVEN
    let (context, organisation, did) = TestContext::new_with_did().await;
    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, "NONE")
        .await;

    for _ in 1..15 {
        context
            .db
            .credentials
            .create(
                &credential_schema,
                CredentialStateEnum::Accepted,
                &did,
                "PROCIVIS_TEMPORARY",
                TestingCredentialParams::default(),
            )
            .await;
    }

    // WHEN
    let resp = context.api.credentials.list(0, 8, &organisation.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    assert_eq!(resp["totalItems"], 14);
    assert_eq!(resp["totalPages"], 2);
    assert_eq!(resp["values"].as_array().unwrap().len(), 8);
}

#[tokio::test]
async fn test_get_list_credential_deleted_credentials_are_not_returned() {
    // GIVEN
    let (context, organisation, did) = TestContext::new_with_did().await;
    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, "NONE")
        .await;

    for _ in 1..15 {
        context
            .db
            .credentials
            .create(
                &credential_schema,
                CredentialStateEnum::Created,
                &did,
                "PROCIVIS_TEMPORARY",
                TestingCredentialParams::default(),
            )
            .await;
    }

    context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Created,
            &did,
            "PROCIVIS_TEMPORARY",
            TestingCredentialParams {
                deleted_at: Some(OffsetDateTime::now_utc()),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context.api.credentials.list(0, 8, &organisation.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    assert_eq!(resp["totalItems"], 14);
    assert_eq!(resp["totalPages"], 2);
    assert_eq!(resp["values"].as_array().unwrap().len(), 8);
}
