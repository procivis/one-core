use std::fmt::Display;

use serde_json::json;
use shared_types::{KeyId, OrganisationId};
use uuid::Uuid;

use super::{HttpClient, Response};

pub struct DidFilters {
    pub page: u64,
    pub page_size: u64,
    pub organisation_id: OrganisationId,
    pub deactivated: Option<bool>,
    pub key_algorithms: Option<Vec<String>>,
    pub key_roles: Option<Vec<String>>,
    pub did_methods: Option<Vec<String>>,
    pub key_ids: Option<Vec<KeyId>>,
}

pub struct DidsApi {
    client: HttpClient,
}

impl DidsApi {
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }

    pub async fn create(
        &self,
        organisation_id: impl Into<Uuid>,
        keys: DidKeys,
        method: &str,
        name: &str,
        params: Option<serde_json::Value>,
    ) -> Response {
        let body = json!({
          "keys": {
            "assertionMethod": keys.assertion_method,
            "authentication": keys.authentication,
            "capabilityDelegation": keys.capability_delegation,
            "capabilityInvocation": keys.capability_invocation,
            "keyAgreement": keys.key_agreement,
          },
          "method": method,
          "name": name,
          "organisationId": organisation_id.into(),
          "params": params.unwrap_or(serde_json::json!({})),
        });

        self.client.post("/api/did/v1", body).await
    }

    pub async fn list(
        &self,
        DidFilters {
            page,
            page_size,
            organisation_id,
            deactivated,
            key_algorithms,
            key_roles,
            did_methods,
            key_ids,
        }: DidFilters,
    ) -> Response {
        let mut url = format!(
            "/api/did/v1?page={page}&pageSize={page_size}&organisationId={organisation_id}"
        );
        if let Some(deactivated) = deactivated {
            url += &format!("&deactivated={deactivated}");
        }

        url = key_algorithms
            .into_iter()
            .flatten()
            .fold(url, |url, v| url + &format!("&keyAlgorithms[]={v}"));

        url = key_roles
            .into_iter()
            .flatten()
            .fold(url, |url, v| url + &format!("&keyRoles[]={v}"));

        url = did_methods
            .into_iter()
            .flatten()
            .fold(url, |url, v| url + &format!("&didMethods[]={v}"));

        url = key_ids
            .into_iter()
            .flatten()
            .fold(url, |url, v| url + &format!("&keyIds[]={v}"));

        self.client.get(&url).await
    }

    pub async fn get(&self, did_id: &impl Display) -> Response {
        let url = format!("/api/did/v1/{did_id}");
        self.client.get(&url).await
    }

    pub async fn get_did_webvh(&self, did_id: &impl Display) -> Response {
        let url = format!("/ssi/did-webvh/v1/{did_id}/did.jsonl");
        self.client.get(&url).await
    }

    pub async fn deactivate(&self, did_id: &impl Display) -> Response {
        let url = format!("/api/did/v1/{did_id}");
        let body = json!({
            "deactivated": true,
        });
        self.client.patch(&url, body).await
    }

    pub async fn get_trust_entity(&self, did_id: &impl Display) -> Response {
        let url = format!("/api/did/v1/{did_id}/trust-entity");
        self.client.get(&url).await
    }
}

pub struct DidKeys {
    pub assertion_method: Vec<KeyId>,
    pub authentication: Vec<KeyId>,
    pub capability_delegation: Vec<KeyId>,
    pub capability_invocation: Vec<KeyId>,
    pub key_agreement: Vec<KeyId>,
}

impl DidKeys {
    pub fn single(key: KeyId) -> Self {
        Self {
            assertion_method: vec![key],
            authentication: vec![key],
            capability_delegation: vec![key],
            capability_invocation: vec![key],
            key_agreement: vec![key],
        }
    }

    pub fn all(keys: Vec<KeyId>) -> Self {
        Self {
            assertion_method: keys.clone(),
            authentication: keys.clone(),
            capability_delegation: keys.clone(),
            capability_invocation: keys.clone(),
            key_agreement: keys,
        }
    }
}
