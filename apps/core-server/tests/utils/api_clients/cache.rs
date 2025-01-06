use std::fmt::Display;

use crate::utils::api_clients::{HttpClient, Response};

pub struct CacheApi {
    client: HttpClient,
}

impl CacheApi {
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }

    pub async fn delete(&self, types: Option<Vec<impl Display>>) -> Response {
        let mut url = "/api/cache/v1".to_string();
        if let Some(r#type) = types {
            url = format!(
                "{}?{}",
                url,
                r#type
                    .iter()
                    .map(|val| format!("types[]={val}"))
                    .collect::<Vec<_>>()
                    .join("&")
            );
        }
        self.client.delete(&url).await
    }
}
