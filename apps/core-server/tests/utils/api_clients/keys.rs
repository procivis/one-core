use serde_json::{Value, json};
use shared_types::{KeyId, OrganisationId};
use time::OffsetDateTime;
use uuid::Uuid;

use super::{HttpClient, Response};
use crate::utils::serialization::query_time_urlencoded;

#[derive(Debug, Clone)]
pub struct KeyFilters {
    pub page: u64,
    pub page_size: u64,
    pub organisation_id: OrganisationId,
    pub name: Option<String>,
    pub key_types: Option<Vec<String>>,
    pub key_storages: Option<Vec<String>>,
    pub ids: Option<Vec<KeyId>>,
    pub is_remote: Option<bool>,

    pub created_date_after: Option<OffsetDateTime>,
    pub created_date_before: Option<OffsetDateTime>,
    pub last_modified_after: Option<OffsetDateTime>,
    pub last_modified_before: Option<OffsetDateTime>,
}

pub struct KeysApi {
    client: HttpClient,
}

impl KeysApi {
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }

    pub async fn create(
        &self,
        organisation_id: impl Into<Uuid>,
        key_type: &str,
        name: &str,
    ) -> Response {
        let body = json!({
          "keyParams": {},
          "keyType": key_type,
          "name": name,
          "organisationId": organisation_id.into(),
          "storageParams": {},
          "storageType": "INTERNAL"
        });

        self.client.post("/api/key/v1", body).await
    }

    pub async fn get(&self, key_id: KeyId) -> Response {
        self.client.get(&format!("/api/key/v1/{key_id}")).await
    }

    pub async fn import(
        &self,
        organisation_id: impl Into<Uuid>,
        key_type: &str,
        name: &str,
        jwk: Value,
    ) -> Response {
        let body = json!({
            "keyParams": {},
            "keyType": key_type,
            "name": name,
            "organisationId": organisation_id.into(),
            "storageParams": {
                "jwk": jwk,
            },
            "storageType": "INTERNAL"
        });
        self.client.post("/api/key/v1", body).await
    }

    pub async fn list(
        &self,
        KeyFilters {
            page,
            page_size,
            organisation_id,
            name,
            key_types,
            key_storages,
            ids,
            is_remote,
            created_date_after,
            created_date_before,
            last_modified_after,
            last_modified_before,
        }: KeyFilters,
    ) -> Response {
        let mut url = format!(
            "/api/key/v1?page={page}&pageSize={page_size}&organisationId={organisation_id}"
        );

        if let Some(name) = name {
            url += &format!("&name={name}");
        }

        url = key_types
            .into_iter()
            .flatten()
            .fold(url, |url, v| url + &format!("&keyTypes[]={v}"));

        url = key_storages
            .into_iter()
            .flatten()
            .fold(url, |url, v| url + &format!("&keyStorages[]={v}"));

        if let Some(is_remote) = is_remote {
            url += &format!("&isRemote={is_remote}");
        }

        url = ids
            .into_iter()
            .flatten()
            .fold(url, |url, v| url + &format!("&ids[]={v}"));

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

    pub async fn generate_mdl_csr(&self, key_id: &str) -> Response {
        let body = json!({
            "profile": "MDL",
            "subject": {
                "commonName": "test",
                "countryName": "CH",
            }
        });

        self.client
            .post(&format!("/api/key/v1/{key_id}/generate-csr"), body)
            .await
    }

    pub async fn generate_generic_csr(&self, key_id: &str) -> Response {
        let body = json!({
            "profile": "GENERIC",
            "subject": {}
        });

        self.client
            .post(&format!("/api/key/v1/{key_id}/generate-csr"), body)
            .await
    }
}
