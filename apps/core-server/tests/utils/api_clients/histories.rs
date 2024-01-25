use std::fmt::Display;

use one_core::model::credential_schema::CredentialSchemaId;

use super::{HttpClient, Response};

pub struct HistoriesApi {
    client: HttpClient,
}

impl HistoriesApi {
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }

    pub async fn list(
        &self,
        page: u64,
        page_size: u64,
        organisation_id: &impl Display,
        credential_schema_id: Option<CredentialSchemaId>,
    ) -> Response {
        let schema_param = match credential_schema_id {
            None => "".to_string(),
            Some(value) => format!("&credentialSchemaId={value}"),
        };

        let url = format!(
            "/api/history/v1?page={page}&pageSize={page_size}&organisationId={organisation_id}{schema_param}"
        );
        self.client.get(&url).await
    }
}
