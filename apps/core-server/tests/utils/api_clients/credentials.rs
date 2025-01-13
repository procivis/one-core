use std::fmt::Display;

use one_core::service::credential::dto::CredentialListIncludeEntityTypeEnum;
use serde_json::json;
use shared_types::{CredentialId, KeyId};
use uuid::Uuid;

use super::{HttpClient, Response};

pub struct CredentialsApi {
    client: HttpClient,
}

#[derive(Debug, Default)]
pub struct Filters {
    pub name: Option<String>,
    pub search_text: Option<String>,
    pub search_type: Option<Vec<String>>,
}

impl CredentialsApi {
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }

    pub async fn create(
        &self,
        credential_schema_id: impl Into<Uuid>,
        exchange: impl Into<String>,
        issuer_did: impl Into<Uuid>,
        claims: serde_json::Value,
        issuer_key: impl Into<Option<KeyId>>,
    ) -> Response {
        let body = json!({
          "credentialSchemaId": credential_schema_id.into(),
          "exchange": exchange.into(),
          "issuerDid": issuer_did.into(),
          "issuerKey": issuer_key.into(),
          "claimValues": claims
        });

        self.client.post("/api/credential/v1", body).await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn list(
        &self,
        page: u64,
        size: u64,
        organisation_id: &impl Display,
        role: Option<&str>,
        filters: Option<Filters>,
        ids: Option<&[CredentialId]>,
        include: Option<Vec<CredentialListIncludeEntityTypeEnum>>,
    ) -> Response {
        let mut url = format!(
            "/api/credential/v1?page={page}&pageSize={size}&organisationId={organisation_id}"
        );
        if let Some(role) = role {
            url += &format!("&role={role}")
        }
        if let Some(filters) = filters {
            if let Some(name) = filters.name {
                url += &format!("&name={name}")
            }
            if let Some(search_text) = filters.search_text {
                url += &format!("&searchText={search_text}")
            }
            url += &filters
                .search_type
                .into_iter()
                .flatten()
                .fold(String::new(), |url, search_type| {
                    url + &format!("&searchType[]={search_type}")
                });
        }
        if let Some(ids) = ids {
            for id in ids {
                url += &format!("&ids[]={id}")
            }
        }
        if let Some(include) = include {
            for item in include {
                url += &format!("&include[]={item}")
            }
        }
        self.client.get(&url).await
    }

    pub async fn get(&self, id: &impl Display) -> Response {
        let url = format!("/api/credential/v1/{id}");
        self.client.get(&url).await
    }

    pub async fn delete(&self, id: &impl Display) -> Response {
        let url = format!("/api/credential/v1/{id}");
        self.client.delete(&url).await
    }

    pub async fn reactivate(&self, id: &impl Display) -> Response {
        let url = format!("/api/credential/v1/{id}/reactivate");
        self.client.post(&url, None).await
    }

    pub async fn revoke(&self, id: &impl Display) -> Response {
        let url = format!("/api/credential/v1/{id}/revoke");
        self.client.post(&url, None).await
    }

    pub async fn suspend(&self, id: &impl Display, suspend_end_date: Option<String>) -> Response {
        let url = format!("/api/credential/v1/{id}/suspend");
        let body = suspend_end_date
            .map(|suspend_end_date| {
                json!({
                  "suspendEndDate": suspend_end_date,
                })
            })
            .unwrap_or(json!({}));

        self.client.post(&url, body).await
    }

    pub async fn revocation_check(
        &self,
        credential_id: impl Into<Uuid>,
        cache_bypass: Vec<&str>,
    ) -> Response {
        let body = json!({
          "credentialIds": vec![credential_id.into()]
        });

        let mut url = "/api/credential/v1/revocation-check".to_string();
        if let Some(query) = cache_bypass
            .iter()
            .map(|val| format!("bypassCache[]={val}"))
            .reduce(|a, b| a + "&" + &b)
        {
            url.push('?');
            url += &query;
        }

        self.client.post(&url, body).await
    }

    pub async fn share(&self, id: &impl Display) -> Response {
        let url = format!("/api/credential/v1/{id}/share");
        self.client.post(&url, None).await
    }
}
