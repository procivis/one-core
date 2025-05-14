use shared_types::CertificateId;

use super::{HttpClient, Response};

pub struct CertificatesApi {
    client: HttpClient,
}

impl CertificatesApi {
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }

    pub async fn get(&self, id: &CertificateId) -> Response {
        self.client.get(&format!("/api/certificate/v1/{id}")).await
    }
}
