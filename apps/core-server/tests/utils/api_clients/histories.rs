use core_server::endpoint::history::dto::{HistoryAction, HistoryEntityType, HistorySource};
use serde_json::json;
use shared_types::{CredentialSchemaId, EntityId, HistoryId, OrganisationId};

use super::{HttpClient, Response};

pub struct HistoriesApi {
    client: HttpClient,
}

#[derive(Debug, Default)]
pub struct QueryParams {
    pub credential_schema_id: Option<CredentialSchemaId>,
    pub organisation_ids: Option<Vec<OrganisationId>>,
    pub entity_types: Option<Vec<String>>,
    pub entity_ids: Option<Vec<EntityId>>,
    pub actions: Option<Vec<String>>,
    pub sources: Option<Vec<HistorySource>>,
    pub users: Option<Vec<String>>,
    pub show_system_history: Option<bool>,
}

impl HistoriesApi {
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }

    pub async fn list(&self, page: u64, page_size: u64, filter: QueryParams) -> Response {
        let mut url = format!("/api/history/v1?page={page}&pageSize={page_size}");
        if let Some(credential_schema_id) = filter.credential_schema_id {
            url.push_str(&format!("&credentialSchemaId={credential_schema_id}"));
        }
        if let Some(organisation_ids) = filter.organisation_ids {
            let organisation_ids_as_string = organisation_ids
                .into_iter()
                .map(|o| format!("organisationIds[]={o}"))
                .collect::<Vec<String>>()
                .join("&");
            url.push_str(&format!("&{organisation_ids_as_string}"));
        }
        if let Some(entity_types) = filter.entity_types {
            let entity_types_as_string = entity_types
                .into_iter()
                .map(|e| format!("entityTypes[]={e}"))
                .collect::<Vec<String>>()
                .join("&");
            url.push_str(&format!("&{entity_types_as_string}"));
        }
        if let Some(entity_ids) = filter.entity_ids {
            let entity_ids_as_string = entity_ids
                .into_iter()
                .map(|e| format!("entityIds[]={e}"))
                .collect::<Vec<String>>()
                .join("&");
            url.push_str(&format!("&{entity_ids_as_string}"));
        }
        if let Some(actions) = filter.actions {
            let actions_as_string = actions
                .into_iter()
                .map(|e| format!("actions[]={e}"))
                .collect::<Vec<String>>()
                .join("&");
            url.push_str(&format!("&{actions_as_string}"));
        }
        if let Some(sources) = filter.sources {
            let sources_as_string = sources
                .iter()
                .map(|s| format!("sources[]={}", serde_json::to_string(s).unwrap()))
                .collect::<Vec<String>>()
                .join("&");
            url.push_str(&format!("&{sources_as_string}"));
        }
        if let Some(users) = filter.users {
            let users_as_string = users
                .into_iter()
                .map(|u| format!("users[]={u}"))
                .collect::<Vec<String>>()
                .join("&");
            url.push_str(&format!("&{users_as_string}"));
        }
        if let Some(show_system_history) = filter.show_system_history
            && show_system_history
        {
            url.push_str("&showSystemHistory=true");
        }

        self.client.get(&url).await
    }

    pub async fn get(&self, history_id: HistoryId) -> Response {
        let url = format!("/api/history/v1/{history_id}");
        self.client.get(&url).await
    }

    pub async fn create(
        &self,
        name: &str,
        source: impl Into<HistorySource>,
        entity_type: impl Into<HistoryEntityType>,
        action: impl Into<HistoryAction>,
        metadata: Option<serde_json::Value>,
    ) -> Response {
        let body = json!({
          "name": name,
          "source": source.into(),
          "entityType": entity_type.into(),
          "action": action.into(),
          "metadata": metadata,
        });

        self.client.post("/api/history/v1", body).await
    }
}
