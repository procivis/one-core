use std::fmt::Display;

use shared_types::{CredentialSchemaId, HistoryId};

use super::{HttpClient, Response};

pub struct HistoriesApi {
    client: HttpClient,
}

impl HistoriesApi {
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn list(
        &self,
        page: u64,
        page_size: u64,
        organisation_id: &impl Display,
        credential_schema_id: Option<CredentialSchemaId>,
        entity_types: Option<Vec<String>>,
        actions: Option<Vec<String>>,
        user: Option<&str>,
    ) -> Response {
        let schema_param = match credential_schema_id {
            None => "".to_string(),
            Some(value) => format!("&credentialSchemaId={value}"),
        };

        let mut url = format!(
            "/api/history/v1?page={page}&pageSize={page_size}&organisationId={organisation_id}{schema_param}"
        );
        if entity_types.is_some() {
            let entity_types_as_string = entity_types
                .unwrap()
                .into_iter()
                .map(|e| format!("entityTypes[]={e}"))
                .collect::<Vec<String>>()
                .join("&");
            url.push_str(&format!("&{entity_types_as_string}"));
        }
        if actions.is_some() {
            let actions_as_string = actions
                .unwrap()
                .into_iter()
                .map(|e| format!("actions[]={e}"))
                .collect::<Vec<String>>()
                .join("&");
            url.push_str(&format!("&{actions_as_string}"));
        }
        if let Some(user) = user {
            url.push_str(&format!("&user={user}"));
        }

        self.client.get(&url).await
    }

    pub async fn get(&self, history_id: HistoryId) -> Response {
        let url = format!("/api/history/v1/{history_id}");
        self.client.get(&url).await
    }
}
