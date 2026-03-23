use std::sync::Arc;

use crate::proto::http_client::HttpClient;

mod dto;
pub mod provider;

pub struct HTTPVerifierProviderClient {
    http_client: Arc<dyn HttpClient>,
}

impl HTTPVerifierProviderClient {
    pub fn new(http_client: Arc<dyn HttpClient>) -> Self {
        Self { http_client }
    }
}
