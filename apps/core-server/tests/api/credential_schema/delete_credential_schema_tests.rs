use core_server::router::start_server;

use crate::{fixtures, utils};

#[tokio::test]
async fn test_delete_credential_schema_success() {
    // GIVEN
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let config = fixtures::create_config(&base_url);
    let db_conn = fixtures::create_db(&config).await;
    let organisation = fixtures::create_organisation(&db_conn).await;

    let credential_schema = fixtures::create_credential_schema(
        &db_conn,
        "test schema",
        &organisation,
        "STATUSLIST2021",
    )
    .await;

    // WHEN
    let url = format!(
        "{base_url}/api/credential-schema/v1/{}",
        credential_schema.id
    );
    let db_conn_clone = db_conn.clone();
    let _handle = tokio::spawn(async move { start_server(listener, config, db_conn_clone).await });

    let resp = utils::client()
        .delete(url)
        .bearer_auth("test")
        .send()
        .await
        .unwrap();

    // THEN
    assert_eq!(resp.status(), 204);
    let credential_schema = fixtures::get_credential_schema(&db_conn, &credential_schema.id).await;
    assert!(credential_schema.deleted_at.is_some());
}
