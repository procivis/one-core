use std::time::Duration;

use serde_json::json;
use similar_asserts::assert_eq;
use wiremock::http::Method;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::ReqwestClient;
use crate::error::{ErrorCode, ErrorCodeMixin};
use crate::proto::http_client::{HttpClient, HttpClientSecurityConfig, StatusCode};

#[tokio::test]
async fn test_client_param_max_redirects() {
    let mock_server = MockServer::start().await;
    Mock::given(method(Method::GET))
        .and(path("/no-redirect"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&mock_server)
        .await;
    Mock::given(method(Method::GET))
        .and(path("/with-redirect"))
        .respond_with(ResponseTemplate::new(302).insert_header("Location", "/no-redirect"))
        .mount(&mock_server)
        .await;

    // disallow redirections
    let client_not_redirecting = ReqwestClient::new(HttpClientSecurityConfig {
        max_redirects: 0,
        ..Default::default()
    })
    .unwrap();

    let response = client_not_redirecting
        .get(&format!("{}/no-redirect", mock_server.uri()))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status, StatusCode(200));

    let error = client_not_redirecting
        .get(&format!("{}/with-redirect", mock_server.uri()))
        .send()
        .await
        .unwrap_err();
    assert_eq!(error.error_code(), ErrorCode::BR_0347);

    // allow redirection (max one jump)
    let client_redirecting_once = ReqwestClient::new(HttpClientSecurityConfig {
        max_redirects: 1,
        ..Default::default()
    })
    .unwrap();

    let response = client_redirecting_once
        .get(&format!("{}/no-redirect", mock_server.uri()))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status, StatusCode(200));

    let response = client_redirecting_once
        .get(&format!("{}/with-redirect", mock_server.uri()))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status, StatusCode(200));
}

#[tokio::test]
async fn test_client_param_denied_hosts() {
    let mock_server = MockServer::start().await;
    Mock::given(method(Method::GET))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&mock_server)
        .await;

    // disallow mock server
    let restricting_client = ReqwestClient::new(HttpClientSecurityConfig {
        denied_hosts: Some(vec![mock_server.address().ip().to_string()]),
        ..Default::default()
    })
    .unwrap();

    let error = restricting_client
        .get(&mock_server.uri())
        .send()
        .await
        .unwrap_err();
    assert_eq!(error.error_code(), ErrorCode::BR_0347);

    // allowed mock server host
    let client_with_restriction = ReqwestClient::new(HttpClientSecurityConfig {
        denied_hosts: Some(vec!["procivis.ch".to_string()]),
        ..Default::default()
    })
    .unwrap();

    let response = client_with_restriction
        .get(&mock_server.uri())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status, StatusCode(200));
}

#[tokio::test]
async fn test_client_param_insecure_http_transport_allowed() {
    let mock_server = MockServer::start().await;
    Mock::given(method(Method::GET))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&mock_server)
        .await;

    let restricting_client = ReqwestClient::new(HttpClientSecurityConfig {
        insecure_http_transport_allowed: false,
        ..Default::default()
    })
    .unwrap();

    let error = restricting_client
        .get(&mock_server.uri())
        .send()
        .await
        .unwrap_err();
    assert_eq!(error.error_code(), ErrorCode::BR_0347);

    let benevolent_client = ReqwestClient::new(HttpClientSecurityConfig {
        insecure_http_transport_allowed: true,
        ..Default::default()
    })
    .unwrap();

    let response = benevolent_client
        .get(&mock_server.uri())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status, StatusCode(200));
}

#[tokio::test]
async fn test_client_param_max_response_size() {
    let mock_server = MockServer::start().await;
    Mock::given(method(Method::GET))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&mock_server)
        .await;

    let restricting_client = ReqwestClient::new(HttpClientSecurityConfig {
        max_response_size: Some(1),
        ..Default::default()
    })
    .unwrap();

    let error = restricting_client
        .get(&mock_server.uri())
        .send()
        .await
        .unwrap_err();
    assert_eq!(error.error_code(), ErrorCode::BR_0347);

    let benevolent_client = ReqwestClient::new(HttpClientSecurityConfig {
        max_response_size: Some(10),
        ..Default::default()
    })
    .unwrap();

    let response = benevolent_client
        .get(&mock_server.uri())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status, StatusCode(200));
}

#[tokio::test]
async fn test_client_param_timeout() {
    let mock_server = MockServer::start().await;
    Mock::given(method(Method::GET))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(100))
                .set_body_json(json!({})),
        )
        .mount(&mock_server)
        .await;

    let restricting_client = ReqwestClient::new(HttpClientSecurityConfig {
        timeout_seconds: Some(time::Duration::milliseconds(1)),
        ..Default::default()
    })
    .unwrap();

    let error = restricting_client
        .get(&mock_server.uri())
        .send()
        .await
        .unwrap_err();
    assert_eq!(error.error_code(), ErrorCode::BR_0347);

    let benevolent_client = ReqwestClient::new(HttpClientSecurityConfig {
        timeout_seconds: Some(time::Duration::seconds(10)),
        ..Default::default()
    })
    .unwrap();

    let response = benevolent_client
        .get(&mock_server.uri())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status, StatusCode(200));
}

#[tokio::test]
async fn test_client_param_timeout_and_max_response_size() {
    let mock_server = MockServer::start().await;
    Mock::given(method(Method::GET))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(100))
                .set_body_json(json!({})),
        )
        .mount(&mock_server)
        .await;

    let restricting_client = ReqwestClient::new(HttpClientSecurityConfig {
        timeout_seconds: Some(time::Duration::milliseconds(1)),
        max_response_size: Some(1),
        ..Default::default()
    })
    .unwrap();

    let error = restricting_client
        .get(&mock_server.uri())
        .send()
        .await
        .unwrap_err();
    assert_eq!(error.error_code(), ErrorCode::BR_0347);

    let benevolent_client = ReqwestClient::new(HttpClientSecurityConfig {
        timeout_seconds: Some(time::Duration::seconds(10)),
        max_response_size: Some(10),
        ..Default::default()
    })
    .unwrap();

    let response = benevolent_client
        .get(&mock_server.uri())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status, StatusCode(200));
}

#[tokio::test]
async fn test_client_sends_zero_content_length_for_post_without_body() {
    let mock_server = MockServer::start().await;
    Mock::given(method(Method::POST))
        .and(path("/nonce"))
        .and(header("content-length", "0"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = ReqwestClient::new(HttpClientSecurityConfig {
        insecure_http_transport_allowed: true,
        ..Default::default()
    })
    .unwrap();

    let response = client
        .post(&format!("{}/nonce", mock_server.uri()))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status, StatusCode(200));
}
