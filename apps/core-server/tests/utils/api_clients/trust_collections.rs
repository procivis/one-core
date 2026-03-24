use serde_json::json;
use shared_types::OrganisationId;
use time::OffsetDateTime;
use uuid::Uuid;

use super::{HttpClient, Response};
use crate::utils::serialization::query_time_urlencoded;

pub struct TrustCollectionsApi {
    client: HttpClient,
}

#[derive(Default)]
pub struct ListFilters {
    pub organisation_id: Option<OrganisationId>,
    pub name: Option<String>,
    pub created_date_after: Option<OffsetDateTime>,
    pub created_date_before: Option<OffsetDateTime>,
    pub last_modified_after: Option<OffsetDateTime>,
    pub last_modified_before: Option<OffsetDateTime>,
}

impl TrustCollectionsApi {
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }

    pub async fn create(&self, name: &str, organisation_id: Option<OrganisationId>) -> Response {
        let body = json!({
          "name": name,
          "organisationId": organisation_id,
        });

        self.client.post("/api/trust-collection/v1", body).await
    }

    pub async fn get(&self, id: impl Into<Uuid>) -> Response {
        let url = format!("/api/trust-collection/v1/{}", id.into());
        self.client.get(&url).await
    }

    pub async fn list(&self, page: usize, filters: ListFilters) -> Response {
        let ListFilters {
            organisation_id,
            name,
            created_date_after,
            created_date_before,
            last_modified_after,
            last_modified_before,
        } = filters;

        let mut url = format!("/api/trust-collection/v1?pageSize=20&page={page}");

        if let Some(organisation_id) = organisation_id {
            url += &format!("&organisationId={organisation_id}");
        }

        if let Some(name) = name {
            url += &format!("&name={name}");
        }

        if let Some(date) = created_date_after {
            url += &format!("&{}", query_time_urlencoded("createdDateAfter", date));
        }
        if let Some(date) = created_date_before {
            url += &format!("&{}", query_time_urlencoded("createdDateBefore", date));
        }
        if let Some(date) = last_modified_after {
            url += &format!("&{}", query_time_urlencoded("lastModifiedAfter", date));
        }
        if let Some(date) = last_modified_before {
            url += &format!("&{}", query_time_urlencoded("lastModifiedBefore", date));
        }

        self.client.get(&url).await
    }

    pub async fn delete(&self, id: impl Into<Uuid>) -> Response {
        let url = format!("/api/trust-collection/v1/{}", id.into());
        self.client.delete(&url).await
    }

    pub async fn create_subscription(
        &self,
        trust_collection_id: impl Into<Uuid>,
        name: &str,
        role: Option<&str>,
        reference: &str,
        r#type: &str,
    ) -> Response {
        let body = json!({
          "name": name,
          "role": role,
          "reference": reference,
          "type": r#type,
        });

        let url = format!(
            "/api/trust-collection/v1/{}/trust-list",
            trust_collection_id.into()
        );
        self.client.post(&url, body).await
    }

    pub async fn delete_subscription(
        &self,
        trust_collection_id: impl Into<Uuid>,
        subscription_id: impl Into<Uuid>,
    ) -> Response {
        let url = format!(
            "/api/trust-collection/v1/{}/trust-list/{}",
            trust_collection_id.into(),
            subscription_id.into()
        );
        self.client.delete(&url).await
    }

    pub async fn list_subscriptions(&self, trust_collection_id: impl Into<Uuid>) -> Response {
        self.client
            .get(&format!(
                "/api/trust-collection/v1/{}/trust-list?pageSize=20&page=0",
                trust_collection_id.into()
            ))
            .await
    }
}
