use std::sync::Arc;

use crate::proto::http_client::HttpClient;

mod dto;
pub mod provider;

pub struct HTTPWalletProviderClient {
    http_client: Arc<dyn HttpClient>,
}

impl HTTPWalletProviderClient {
    pub fn new(http_client: Arc<dyn HttpClient>) -> Self {
        Self { http_client }
    }
}
