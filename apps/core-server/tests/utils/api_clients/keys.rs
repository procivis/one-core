use serde_json::json;
use shared_types::{KeyId, OrganisationId};
use uuid::Uuid;

use super::{HttpClient, Response};

pub struct KeyFilters {
    pub page: u64,
    pub page_size: u64,
    pub organisation_id: OrganisationId,
    pub name: Option<String>,
    pub key_type: Option<String>,
    pub key_storage: Option<String>,
    pub ids: Option<Vec<KeyId>>,
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

    pub async fn list(
        &self,
        KeyFilters {
            page,
            page_size,
            organisation_id,
            name,
            key_type,
            key_storage,
            ids,
        }: KeyFilters,
    ) -> Response {
        let mut url = format!(
            "/api/key/v1?page={page}&pageSize={page_size}&organisationId={organisation_id}"
        );

        if let Some(name) = name {
            url += &format!("&name={name}");
        }

        if let Some(key_type) = key_type {
            url += &format!("&keyType={key_type}");
        }

        if let Some(key_storage) = key_storage {
            url += &format!("&keyStorage={key_storage}");
        }

        url = ids
            .into_iter()
            .flatten()
            .fold(url, |url, v| url + &format!("&ids[]={v}"));

        self.client.get(&url).await
    }

    pub async fn check_certificate(&self, key_id: &str, certificate: &str) -> Response {
        let body = json!({
            "certificate": certificate
        });

        self.client
            .post(&format!("/api/key/v1/{key_id}/check-certificate"), body)
            .await
    }

    pub async fn generate_mdl_csr(&self, key_id: &str) -> Response {
        let body = json!({
            "exp": "2023-06-09T14:19:57.000Z",
            "nbf": "2023-06-09T14:19:58.000Z",
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
            "exp": "2023-06-09T14:19:57.000Z",
            "nbf": "2023-06-09T14:19:58.000Z",
            "profile": "GENERIC",
            "subject": {}
        });

        self.client
            .post(&format!("/api/key/v1/{key_id}/generate-csr"), body)
            .await
    }
}
