use reqwest::{Method, StatusCode};
use serde::Serialize;

use crate::fixtures::sts::{StsSetup, setup_sts};
use crate::utils::api_clients::http_client;
use crate::utils::context::TestContext;

// This replicates the struct found in core_server::middleware,
// to avoid making it public.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StsToken {
    pub organisation_id: Option<()>,
    pub permissions: Vec<&'static str>,
}

#[tokio::test]
async fn test_authorization_success_no_permission_required() {
    test_authorization(Method::GET, "/api/config/v1", vec![], StatusCode::OK).await;
}

#[tokio::test]
async fn test_authorization_success_has_required_permission() {
    test_authorization(
        Method::DELETE,
        "/api/cache/v1?types[]=OPENID_METADATA",
        vec!["CACHE_DELETE"],
        StatusCode::NO_CONTENT,
    )
    .await;
}

#[tokio::test]
async fn test_authorization_failed_missing_required_permission() {
    test_authorization(
        Method::DELETE,
        "/api/cache/v1?types[]=OPENID_METADATA",
        vec![],
        StatusCode::FORBIDDEN,
    )
    .await;
}

async fn test_authorization(
    request_method: Method,
    request_url: &'static str,
    permissions: Vec<&'static str>,
    expected_status: StatusCode,
) {
    // given
    let StsSetup {
        config,
        token,
        mock_server: _mock_server,
    } = setup_sts(permissions).await;
    let context = TestContext::new(Some(config)).await;

    // when
    let resp = http_client()
        .request(
            request_method,
            format!("{}{}", context.config.app.core_base_url, request_url),
        )
        .bearer_auth(token)
        .send()
        .await
        .unwrap();

    // then
    similar_asserts::assert_eq!(resp.status(), expected_status);
}
