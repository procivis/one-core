use std::ops::Sub;

use one_core::model::credential::CredentialStateEnum;
use time::{Duration, OffsetDateTime};

use crate::fixtures::TestingCredentialParams;
use crate::utils::context::TestContext;

#[tokio::test]
async fn test_run_task_suspend_check_no_update() {
    // GIVEN
    let context = TestContext::new().await;

    // WHEN
    let resp = context.api.tasks.run("SUSPEND_CHECK").await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    assert_eq!(resp["totalChecks"], 0);
    assert_eq!(resp["updatedCredentialIds"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn test_run_task_suspend_check_with_update() {
    // GIVEN
    let (context, organisation, did, _) = TestContext::new_with_did().await;
    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test",
            &organisation,
            "BITSTRINGSTATUSLIST",
            Default::default(),
        )
        .await;

    let a_while_ago = OffsetDateTime::now_utc().sub(Duration::seconds(1));

    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Suspended,
            &did,
            "PROCIVIS_TEMPORARY",
            TestingCredentialParams {
                suspend_end_date: Some(a_while_ago),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context.api.tasks.run("SUSPEND_CHECK").await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    assert_eq!(resp["totalChecks"], 1);
    let credentials = resp["updatedCredentialIds"].as_array().unwrap().to_owned();
    assert_eq!(credentials.len(), 1);
    assert_eq!(
        credentials.first().unwrap().as_str().unwrap(),
        credential.id.to_string()
    );

    let credential = context.db.credentials.get(&credential.id).await;
    let credential_state = &credential.state.unwrap()[0];
    assert_eq!(credential_state.state, CredentialStateEnum::Accepted);
    assert_eq!(credential_state.suspend_end_date, None);
}
