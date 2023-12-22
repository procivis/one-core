use wiremock::http::Method::Post;
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

pub struct MockServer {
    mock: wiremock::MockServer,
}

impl MockServer {
    pub async fn new() -> Self {
        let mock = wiremock::MockServer::start().await;
        Self { mock }
    }

    pub fn uri(&self) -> String {
        self.mock.uri()
    }

    pub async fn mock_temporary_issuer_reject(&self) {
        Mock::given(method(Post))
            .and(path("/ssi/temporary-issuer/v1/reject"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&self.mock)
            .await;
    }
}
