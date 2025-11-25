use std::fmt::Display;

use core_server::endpoint::history::dto::{HistoryAction, HistoryEntityType, HistorySource};
use serde_json::json;
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
        if let Some(entity_types) = entity_types {
            let entity_types_as_string = entity_types
                .into_iter()
                .map(|e| format!("entityTypes[]={e}"))
                .collect::<Vec<String>>()
                .join("&");
            url.push_str(&format!("&{entity_types_as_string}"));
        }
        if let Some(actions) = actions {
            let actions_as_string = actions
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

    pub async fn create(
        &self,
        source: impl Into<HistorySource>,
        entity_type: impl Into<HistoryEntityType>,
        action: impl Into<HistoryAction>,
        metadata: Option<serde_json::Value>,
    ) -> Response {
        let body = json!({
          "source": source.into(),
          "entityType": entity_type.into(),
          "action": action.into(),
          "metadata": metadata,
        });

        self.client.post("/api/history/v1", body).await
    }
}
