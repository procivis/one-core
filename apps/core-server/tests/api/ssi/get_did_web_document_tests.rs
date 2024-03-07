use one_core::model::did::{KeyRole, RelatedKey};
use serde_json::Value;

use crate::{
    fixtures::{self, TestingDidParams},
    utils::{self, server::run_server},
};

#[tokio::test]
async fn test_get_did_web_document_es256_success() {
    // GIVEN
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());

    let config = fixtures::create_config(&base_url, None);
    let db_conn = fixtures::create_db(&config).await;
    let organisation = fixtures::create_organisation(&db_conn).await;
    let key = fixtures::create_es256_key(&db_conn, &organisation).await;
    let did = fixtures::create_did(
        &db_conn,
        &organisation,
        Some(TestingDidParams {
            did_method: Some("WEB".to_string()),
            keys: Some(vec![
                RelatedKey {
                    role: KeyRole::Authentication,
                    key: key.clone(),
                },
                RelatedKey {
                    role: KeyRole::KeyAgreement,
                    key: key.clone(),
                },
                RelatedKey {
                    role: KeyRole::AssertionMethod,
                    key: key.clone(),
                },
            ]),
            ..Default::default()
        }),
    )
    .await;

    // WHEN
    let url = format!("{base_url}/ssi/did-web/v1/{}/did.json", did.id);

    let _handle = run_server(listener, config, &db_conn);

    let resp = utils::client().get(url).send().await.unwrap();

    // THEN
    assert_eq!(resp.status(), 200);
    let resp: Value = resp.json().await.unwrap();

    let assertion_method = resp["assertionMethod"][0].as_str().unwrap();
    assert_eq!(
        assertion_method,
        resp["verificationMethod"][0]["id"].as_str().unwrap()
    );
    assert_eq!(
        resp["verificationMethod"][0]["publicKeyJwk"]["crv"]
            .as_str()
            .unwrap(),
        "P-256"
    );
    assert_eq!(
        resp["verificationMethod"][0]["publicKeyJwk"]["kty"]
            .as_str()
            .unwrap(),
        "EC"
    );
    assert_eq!(
        resp["verificationMethod"][0]["publicKeyJwk"]["x"]
            .as_str()
            .unwrap(),
        "cd_LTtCQnat2XnDElumvgQAM5ZcnUMVTkPig458C1yc"
    );
    assert_eq!(
        resp["verificationMethod"][0]["publicKeyJwk"]["y"]
            .as_str()
            .unwrap(),
        "iaQmPUgir80I2XCFqn2_KPqdWH0PxMzCCP8W3uPxlUA"
    );

    let parts: Vec<&str> = assertion_method.split(':').collect();
    assert_eq!(3, parts.len());
    assert_eq!("did", parts[0]);
    assert_eq!("test", parts[1]);

    let parts: Vec<&str> = parts[2].split('#').collect();
    assert_eq!(2, parts.len());

    let did_id = parts[0];
    assert_eq!(did_id, did.id.to_string());

    let key_id = parts[1];
    let expected_key_id = format!("key-{}", key.id);
    assert_eq!(expected_key_id, key_id);
}

#[tokio::test]
async fn test_get_did_web_document_eddsa_success() {
    // GIVEN
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());

    let config = fixtures::create_config(&base_url, None);
    let db_conn = fixtures::create_db(&config).await;
    let organisation = fixtures::create_organisation(&db_conn).await;
    let key = fixtures::create_eddsa_key(&db_conn, &organisation).await;
    let did = fixtures::create_did(
        &db_conn,
        &organisation,
        Some(TestingDidParams {
            did_method: Some("WEB".to_string()),
            keys: Some(vec![
                RelatedKey {
                    role: KeyRole::Authentication,
                    key: key.clone(),
                },
                RelatedKey {
                    role: KeyRole::KeyAgreement,
                    key: key.clone(),
                },
                RelatedKey {
                    role: KeyRole::AssertionMethod,
                    key,
                },
            ]),
            ..Default::default()
        }),
    )
    .await;

    // WHEN
    let url = format!("{base_url}/ssi/did-web/v1/{}/did.json", did.id);

    let _handle = run_server(listener, config, &db_conn);

    let resp = utils::client().get(url).send().await.unwrap();

    // THEN
    assert_eq!(resp.status(), 200);
    let resp: Value = resp.json().await.unwrap();
    assert_eq!(
        resp["assertionMethod"][0].as_str().unwrap(),
        resp["verificationMethod"][0]["id"].as_str().unwrap()
    );
    assert_eq!(
        resp["verificationMethod"][0]["publicKeyJwk"]["crv"]
            .as_str()
            .unwrap(),
        "Ed25519"
    );
    assert_eq!(
        resp["verificationMethod"][0]["publicKeyJwk"]["kty"]
            .as_str()
            .unwrap(),
        "OKP"
    );
    assert_eq!(
        resp["verificationMethod"][0]["publicKeyJwk"]["x"]
            .as_str()
            .unwrap(),
        "3LOKxB5ik9WikgQmqNFtmuvNC0FMFFVXr6ATVoL-kT4"
    );
    assert!(resp["verificationMethod"][0]["publicKeyJwk"]["y"]
        .as_str()
        .is_none());
}

#[tokio::test]
async fn test_get_did_web_document_wrong_did_method() {
    // GIVEN
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());

    let config = fixtures::create_config(&base_url, None);
    let db_conn = fixtures::create_db(&config).await;
    let organisation = fixtures::create_organisation(&db_conn).await;
    let did = fixtures::create_did(&db_conn, &organisation, None).await;

    // WHEN
    let url = format!("{base_url}/ssi/did-web/v1/{}/did.json", did.id);

    let _handle = run_server(listener, config, &db_conn);

    let resp = utils::client().get(url).send().await.unwrap();

    // THEN
    assert_eq!(resp.status(), 400)
}

#[tokio::test]
async fn test_get_did_web_document_deactivated() {
    // GIVEN
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());

    let config = fixtures::create_config(&base_url, None);
    let db_conn = fixtures::create_db(&config).await;
    let organisation = fixtures::create_organisation(&db_conn).await;
    let did = fixtures::create_did(
        &db_conn,
        &organisation,
        Some(TestingDidParams {
            did_method: Some("WEB".to_string()),
            deactivated: Some(true),
            ..Default::default()
        }),
    )
    .await;
    // WHEN
    let url = format!("{base_url}/ssi/did-web/v1/{}/did.json", did.id);

    let _handle = run_server(listener, config, &db_conn);

    let resp = utils::client().get(url).send().await.unwrap();

    // THEN
    assert_eq!(resp.status(), 400)
}
