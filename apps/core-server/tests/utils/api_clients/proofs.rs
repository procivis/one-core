use std::fmt::Display;

use uuid::Uuid;

use super::{HttpClient, Response};

pub struct ProofsApi {
    client: HttpClient,
}

impl ProofsApi {
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }

    pub async fn get(&self, id: impl Display) -> Response {
        let url = format!("/api/proof-request/v1/{id}");
        self.client.get(&url).await
    }

    pub async fn list(
        &self,
        page: u32,
        page_size: u32,
        organisation_id: &impl Display,
        ids: impl IntoIterator<Item = &Uuid>,
    ) -> Response {
        let mut url = format!(
            "/api/proof-request/v1?page={page}&pageSize={page_size}&organisationId={organisation_id}"
        );

        for id in ids {
            url += &format!("&ids[]={id}")
        }

        self.client.get(&url).await
    }
}
