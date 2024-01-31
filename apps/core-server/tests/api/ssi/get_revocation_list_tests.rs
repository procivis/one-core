use core_server::router::start_server;

use crate::{fixtures, utils};

#[tokio::test]
async fn test_get_revocation_list_success() {
    // GIVEN
    let status_list_credential_jwt = "test-jwt";
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());

    let config = fixtures::create_config(&base_url, None);
    let db_conn = fixtures::create_db(&config).await;
    let organisation = fixtures::create_organisation(&db_conn).await;
    let did = fixtures::create_did(&db_conn, &organisation, None).await;
    let revocation_list = fixtures::create_revocation_list(
        &db_conn,
        &did,
        Some(status_list_credential_jwt.as_bytes()),
    )
    .await;

    // WHEN
    let url = format!("{base_url}/ssi/revocation/v1/list/{}", revocation_list.id);

    let _handle = tokio::spawn(async move { start_server(listener, config, db_conn).await });

    let resp = utils::client().get(url).send().await.unwrap();

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.text().await.unwrap();
    assert_eq!(resp, status_list_credential_jwt);
}
